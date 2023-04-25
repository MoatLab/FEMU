# ansible_wrapper.py - module abstracting the official Ansible runner module
#
# Copyright (C) 2021 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import ansible_runner
import logging
import shutil
import yaml

from pathlib import Path
from tempfile import TemporaryDirectory, NamedTemporaryFile

from lcitool import util, LcitoolError

log = logging.getLogger(__name__)


class AnsibleWrapperError(LcitoolError):
    """Global exception type for this module.

    Contains a detailed message coming from one of its subclassed exception
    types.
    """

    def __init__(self, message):
        super().__init__(message, "AnsibleWrapper")


class ExecutionError(AnsibleWrapperError):
    """Thrown whenever the Ansible runner failed the execution."""

    def __init__(self, message):
        message_prefix = "Ansible execution failed: "
        message = message_prefix + message
        super().__init__(message)


class EnvironmentError(AnsibleWrapperError):
    """Thrown when preparation of the execution environment failed."""

    def __init__(self, message):
        message_prefix = "Failed to prepare the execution environment: "
        message = message_prefix + message
        super().__init__(message)


class AnsibleWrapper():
    def __init__(self):
        self._tempdir = TemporaryDirectory(prefix="ansible_runner",
                                           dir=util.get_temp_dir())
        self._private_data_dir = Path(self._tempdir.name)

    def _get_default_params(self):
        ansible_log_path = Path(util.get_cache_dir(), "ansible.log").as_posix()
        default_params = {
            "private_data_dir": self._private_data_dir,
            "envvars": {
                "ANSIBLE_DISPLAY_SKIPPED_HOSTS": "False",
                "ANSIBLE_FORKS": "16",
                "ANSIBLE_NOCOWS": "True",
                "ANSIBLE_LOG_PATH": ansible_log_path,
                "ANSIBLE_SSH_PIPELINING": "True",

                # Group names officially cannot contain dashes, because those
                # characters are invalid in Python identifiers and it caused
                # issues in some Ansible scenarios like using the dot notation,
                # e.g. groups.group-with-dash. In simple group names like
                # ours dashes are still perfectly fine, so ignore the warning
                "ANSIBLE_TRANSFORM_INVALID_GROUP_CHARS": "ignore",
            }
        }

        return default_params

    def prepare_env(self, playbookdir=None, inventories=None,
                    group_vars=None, extravars=None):
        """
        Prepares the Ansible runner execution environment.

        This method creates the necessary directory hierarchy in order for
        lcitool to be able to use the Ansible runner. As part of this process
        some Ansible input data are created/symlinked from the main git repo.

        :param playbookdir: absolute path to the directory containing the
                            playbook and its data (as Path());
                            we don't touch playbooks, so the source path is
                            symlinked
        :param inventories: list of inventory sources; an inventory source can
                            be one of the following:
                              - an absolute path to either a single inventory
                                file or directory containing inventory files
                                or scripts just like Ansible expects (as
                                Path())
                              - a dictionary conforming to the Ansible YAML
                                inventory structure;
                            all the inventory sources will be placed to the
                            runner's runtime directory
        :param group_vars: dictionary of Ansible group_vars that will be dumped
                           in the YAML format to the runner's runtime directory
        :param extravars: dictionary of Ansible extra vars that will be dumped
                          in the YAML format to the runner's runtime directory
        """

        if playbookdir:
            if not playbookdir.is_dir():
                raise EnvironmentError(f"{playbookdir} is not a directory")

            dst = Path(self._private_data_dir, "project")
            dst.symlink_to(playbookdir, target_is_directory=True)

        if inventories:
            dst = Path(self._private_data_dir, "inventory")
            dst.mkdir()

            # NOTE: If we're ever to support multiple inventory sources in the
            # frontend, we'll need to make sure we copy all user data using
            # 'tempfile' primitives in order to avoid file name conflicts among
            # all the sources, otherwise we'd lose data due to rewriting the
            # impacted files.
            for inventory in inventories:
                if type(inventory) is dict:
                    with NamedTemporaryFile("w", dir=dst, delete=False) as fd:
                        yaml.dump(inventory, fd)
                else:
                    if inventory.is_dir():
                        shutil.copytree(inventory, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(inventory, dst)

        if group_vars:
            dst_dir = Path(self._private_data_dir, "inventory/group_vars")
            dst_dir.mkdir(parents=True, exist_ok=True)

            for group in group_vars:
                log.debug(f"Dumping group vars for [{group}]: "
                          f"{group_vars[group]}")

                dst = Path(dst_dir, group + ".yml")
                with open(dst, "w") as fp:
                    yaml.dump(group_vars[group], fp)

        if extravars:
            dst_dir = Path(self._private_data_dir, "env")
            dst_dir.mkdir()

            dst = Path(dst_dir, "extravars")
            with open(dst, "w") as fp:
                yaml.dump(extravars, fp)

    def _run(self, params, **kwargs):
        """
        The actual entry point into the ansible_runner package.

        :param params: any arguments that ansible_runner.RunnerConfig() would
                       accept (as a dict)
        :param kwargs: any arguments that ansible_runner.Runner() would accept
        :returns: ansible_runner.Runner object which holds info about the
                  Ansible execution
        """

        runner_config = ansible_runner.RunnerConfig(**params)
        runner_config.prepare()
        cmd = runner_config.generate_ansible_command()

        try:
            log.debug(f"Running the Ansible runner cmd='{cmd}'")

            runner = ansible_runner.Runner(runner_config, **kwargs)
            runner.run()
        except ansible_runner.exceptions.AnsibleRunnerException as e:
            raise ExecutionError(e)

        if runner.status != "successful":

            message = f"Failed to execute Ansible command '{cmd}'"

            if params.get("quiet", False):
                # Ansible runner 1.4.6-X does not expose the stderr property, so we
                # need to fallback to stdout instead
                # TODO: We'll be able to drop this code once ansible-runner 2.0 is
                # widely available
                if getattr(runner, "stderr", None) is not None:
                    error = runner.stderr.read()
                else:
                    error = runner.stdout.read()

                message = f"{message}: {error}"

            raise ExecutionError(message)

        return runner

    def get_inventory(self):
        """
        Returns a YAML-formatted Ansible inventory populated from all sources.

        :returns: a dictionary corresponding to the Ansible YAML format.
        """

        ansible_event_handler_data = []

        # NOTE: this is nasty hack! We have no way of verifying dynamic
        # Ansible inventories provided by users and thus no way of telling
        # whether their hosts are not named the same way as our target OS
        # groups. Ansible doesn't like that and emits a warning about it which
        # can neither be ignored nor disabled. We also have no way of parsing
        # user's inventory rather than with Ansible's help (as long as we don't
        # intend to run user scripts ourselves), so we have to ask
        # ansible-inventory to take all the sources and dump a YAML-formatted
        # inventory for us from which we can extract the list of hosts.
        # The problem is that since we're consuming directly the stdout of the
        # Ansible inventory process it can be potentially polluted with
        # [WARNING] messages which would make it impossible for the yaml
        # library to parse the data. So, we'll hook up an event handler to
        # Ansible runner which will filter out the warnings for us as the
        # output is produced and we're left out with a list of strings
        # comprising the stdout data - profit!
        def ansible_event_handler(event):
            if "[WARNING]" in event["stdout"]:
                return

            ansible_event_handler_data.append(event["stdout"])

        params = self._get_default_params()
        params["binary"] = "ansible-inventory"
        params["cmdline"] = "--list --yaml"

        # we don't want any Ansible console output for the inventory
        params["quiet"] = True

        self._run(params, event_handler=ansible_event_handler)

        ansible_inventory = '\n'.join(ansible_event_handler_data)

        try:
            return yaml.safe_load(ansible_inventory)
        except Exception as ex:
            raise AnsibleWrapperError(
                f"ansible-inventory didn't return a valid YAML: {ex}"
            )

    def run_playbook(self, limit=None, verbosity=0):
        """
        :param limit: list of hosts to restrict the playbook execution to
        :param verbosity: verbosity of underlying ansible invocation
        :returns: None
        """

        params = self._get_default_params()
        params["playbook"] = "main.yml"

        if verbosity:
            params["verbosity"] = verbosity
        if limit:
            params["limit"] = ','.join(limit)

        self._run(params)
