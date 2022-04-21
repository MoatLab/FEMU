# application.py - module containing the lcitool application code
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import subprocess
import sys

from pathlib import Path
from pkg_resources import resource_filename

from lcitool import util
from lcitool.config import Config, ConfigError
from lcitool.inventory import Inventory, InventoryError
from lcitool.package import package_names_by_type, PackageError
from lcitool.projects import Projects, ProjectError
from lcitool.formatters import DockerfileFormatter, ShellVariablesFormatter, JSONVariablesFormatter, FormatterError
from lcitool.singleton import Singleton
from lcitool.manifest import Manifest

log = logging.getLogger(__name__)


def required_deps(*deps):
    def inner_decorator(func):
        def wrapped(*args, **kwargs):
            cmd = func.__name__[len('_action_'):]
            for dep in deps:
                try:
                    import importlib
                    importlib.import_module(dep)
                except ImportError:
                    raise ApplicationError(
                        f"Command '{cmd}' requires '{dep}' module to be installed"
                    )
            func(*args, **kwargs)
        return wrapped
    return inner_decorator


class ApplicationError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f"Application error: {self.message}"


class Application(metaclass=Singleton):
    def __init__(self):
        # make sure the lcitool cache dir exists
        cache_dir_path = util.get_cache_dir()
        cache_dir_path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _entrypoint_debug(args):
        cli_args = {}
        for arg, val in vars(args).items():
            if arg not in ['func', 'debug']:
                cli_args[arg] = val
        log.debug(f"Cmdline args={cli_args}")

    def _execute_playbook(self, playbook, hosts_pattern, projects_pattern,
                          git_revision):
        from lcitool.ansible_wrapper import AnsibleWrapper

        log.debug(f"Executing playbook '{playbook}': "
                  f"hosts_pattern={hosts_pattern} "
                  f"projects_pattern={projects_pattern} gitrev={git_revision}")

        base = resource_filename(__name__, "ansible")
        config = Config()
        inventory = Inventory()
        projects = Projects()

        hosts_expanded = inventory.expand_hosts(hosts_pattern)
        projects_expanded = Projects().expand_names(projects_pattern)

        if git_revision is not None:
            tokens = git_revision.split("/")
            if len(tokens) < 2:
                print(f"Missing or invalid git revision '{git_revision}'",
                      file=sys.stderr)
                sys.exit(1)

            git_remote = tokens[0]
            git_branch = "/".join(tokens[1:])
        else:
            git_remote = "default"
            git_branch = "master"

        playbook_base = Path(base, "playbooks", playbook)
        inventory_path = Path(util.get_config_dir(), "inventory")
        group_vars = inventory.target_facts

        extra_vars = config.values
        extra_vars.update({
            "base": base,
            "selected_projects": projects_expanded,
            "git_remote": git_remote,
            "git_branch": git_branch,
        })

        log.debug("Preparing Ansible runner environment")
        ansible_runner = AnsibleWrapper()

        for host in hosts_expanded:
            facts = inventory.host_facts[host]
            target = facts["target"]

            # packages are evaluated on a target level and since the
            # host->target mapping is N-1, we can skip hosts belonging to a
            # target group for which we already evaluated the package list
            if group_vars[target].get("packages"):
                continue

            # resolve the package mappings to actual package names
            internal_wanted_projects = ["base", "developer", "vm"]
            if config.values["install"]["cloud_init"]:
                internal_wanted_projects.append("cloud-init")

            selected_projects = internal_wanted_projects + projects_expanded
            pkgs_install = projects.get_packages(selected_projects, facts)
            pkgs_remove = projects.get_packages(["unwanted"], facts)
            package_names = package_names_by_type(pkgs_install)
            package_names_remove = package_names_by_type(pkgs_remove)

            # merge the package lists to the Ansible group vars
            group_vars[target]["packages"] = package_names["native"]
            group_vars[target]["pypi_packages"] = package_names["pypi"]
            group_vars[target]["cpan_packages"] = package_names["cpan"]
            group_vars[target]["unwanted_packages"] = package_names_remove["native"]

        ansible_runner.prepare_env(playbookdir=playbook_base,
                                   inventory=inventory_path,
                                   group_vars=group_vars,
                                   extravars=extra_vars)
        log.debug(f"Running Ansible with playbook '{playbook_base.name}'")
        ansible_runner.run_playbook(limit=hosts_expanded)

    @required_deps('ansible_runner')
    def _action_hosts(self, args):
        self._entrypoint_debug(args)

        inventory = Inventory()
        for host in sorted(inventory.hosts):
            print(host)

    def _action_targets(self, args):
        self._entrypoint_debug(args)

        inventory = Inventory()
        for target in sorted(inventory.targets):
            if args.containerized:
                facts = inventory.target_facts[target]

                if facts["packaging"]["format"] not in ["apk", "deb", "rpm"]:
                    continue

            print(target)

    def _action_projects(self, args):
        self._entrypoint_debug(args)

        projects = Projects()
        for project in sorted(projects.names):
            print(project)

    def _action_install(self, args):
        self._entrypoint_debug(args)

        config = Config()
        host = args.host

        try:
            facts = Inventory().host_facts[host]
        except KeyError:
            raise ApplicationError(f"Invalid host '{host}'")

        if not facts.get("fully_managed"):
            raise ApplicationError(
                f"fully_managed=True not set for {host}, refusing to proceed"
            )

        # Both memory size and disk size are stored as GiB in the
        # inventory, but virt-install expects the disk size in GiB
        # and the memory size in *MiB*, so perform conversion here
        memory_arg = str(config.values["install"]["memory_size"] * 1024)

        vcpus_arg = str(config.values["install"]["vcpus"])

        conf_size = config.values["install"]["disk_size"]
        conf_pool = config.values["install"]["storage_pool"]
        disk_arg = f"size={conf_size},pool={conf_pool},bus=virtio"

        conf_network = config.values["install"]["network"]
        network_arg = f"network={conf_network},model=virtio"

        # Different operating systems require different configuration
        # files for unattended installation to work, but some operating
        # systems simply don't support unattended installation at all
        if facts["os"]["name"] in ["Debian", "Ubuntu"]:
            install_config = "preseed.cfg"
        elif facts["os"]["name"] in ["AlmaLinux", "CentOS", "Fedora"]:
            install_config = "kickstart.cfg"
        elif facts["os"]["name"] == "OpenSUSE":
            install_config = "autoinst.xml"
        else:
            print(f"Host {host} doesn't support installation",
                  file=sys.stderr)
            sys.exit(1)

        try:
            unattended_options = {
                "install.url": facts["install"]["url"],
            }
        except KeyError:
            raise ApplicationError(
                f"Host {host} doesn't support installation"
            )

        # Unattended install scripts are being generated on the fly, based
        # on the templates present in lcitool/configs/
        filename = resource_filename(__name__,
                                     f"configs/install/{install_config}")
        with open(filename, "r") as template:
            content = template.read()
            for option in unattended_options:
                content = content.replace(
                    "{{ " + option + " }}",
                    unattended_options[option],
                )

        initrd_inject = Path(util.get_temp_dir(), install_config).as_posix()

        with open(initrd_inject, "w") as inject:
            inject.write(content)

        # preseed files must use a well-known name to be picked up by
        # d-i; for kickstart files, we can use whatever name we please
        # but we need to point anaconda in the right direction through
        # the 'inst.ks' kernel parameter. We can use 'inst.ks'
        # unconditionally for simplicity's sake, because distributions that
        # don't use kickstart for unattended installation will simply
        # ignore it. We do the same with the 'install' argument in order
        # to workaround a bug which causes old virt-install versions to not
        # pass the URL correctly when installing openSUSE guests
        conf_url = facts["install"]["url"]
        ks = install_config
        extra_arg = f"console=ttyS0 inst.ks=file:/{ks} install={conf_url}"

        cmd = [
            "virt-install",
            "--name", host,
            "--location", facts["install"]["url"],
            "--virt-type", config.values["install"]["virt_type"],
            "--arch", config.values["install"]["arch"],
            "--machine", config.values["install"]["machine"],
            "--cpu", config.values["install"]["cpu_model"],
            "--vcpus", vcpus_arg,
            "--memory", memory_arg,
            "--disk", disk_arg,
            "--network", network_arg,
            "--graphics", "none",
            "--console", "pty",
            "--sound", "none",
            "--rng", "device=/dev/urandom,model=virtio",
            "--initrd-inject", initrd_inject,
            "--extra-args", extra_arg,
        ]

        if not args.wait:
            cmd.append("--noautoconsole")

        log.debug(f"Running {cmd}")
        try:
            subprocess.check_call(cmd)
        except Exception as ex:
            raise ApplicationError(
                f"Failed to install host '{host}': {ex}"
            )

    @required_deps('ansible_runner')
    def _action_update(self, args):
        self._entrypoint_debug(args)

        self._execute_playbook("update", args.hosts, args.projects,
                               args.git_revision)

    def _action_build(self, args):
        self._entrypoint_debug(args)

        # we don't keep a dependencies tree for projects, hence pattern
        # expansion would break the 'build' playbook
        if args.projects == "all" or "*" in args.projects:
            raise ApplicationError(
                "'build' command doesn't support specifying projects by "
                "either wildcards or the 'all' keyword"
            )

        self._execute_playbook("build", args.hosts, args.projects,
                               args.git_revision)

    def _action_variables(self, args):
        self._entrypoint_debug(args)

        projects_expanded = Projects().expand_names(args.projects)

        if args.format == "shell":
            formatter = ShellVariablesFormatter()
        else:
            formatter = JSONVariablesFormatter()

        variables = formatter.format(args.target,
                                     projects_expanded,
                                     args.cross_arch)

        # No comments in json !
        if args.format != "json":
            cliargv = [args.action]
            if args.cross_arch:
                cliargv.extend(["--cross", args.cross_arch])
            cliargv.extend([args.target, args.projects])
            header = util.generate_file_header(cliargv)
        else:
            header = ""

        print(header + variables)

    def _action_dockerfile(self, args):
        self._entrypoint_debug(args)

        projects_expanded = Projects().expand_names(args.projects)

        dockerfile = DockerfileFormatter(args.base,
                                         args.layers).format(args.target,
                                                             projects_expanded,
                                                             args.cross_arch)

        cliargv = [args.action]
        if args.base is not None:
            cliargv.extend(["--base", args.base])
        cliargv.extend(["--layers", args.layers])
        if args.cross_arch:
            cliargv.extend(["--cross", args.cross_arch])
        cliargv.extend([args.target, args.projects])
        header = util.generate_file_header(cliargv)

        print(header + dockerfile)

    def _action_manifest(self, args):
        base_path = None
        if args.base_dir is not None:
            base_path = Path(args.base_dir)
        ci_path = Path(args.ci_dir)
        manifest = Manifest(args.manifest, args.quiet, ci_path, base_path)
        manifest.generate(args.dry_run)

    def run(self, args):
        try:
            util.set_extra_data_dir(args.data_dir)
            args.func(self, args)
        except (ApplicationError,
                ConfigError,
                InventoryError,
                ProjectError,
                PackageError,
                FormatterError) as ex:
            print(ex, file=sys.stderr)
            sys.exit(1)
