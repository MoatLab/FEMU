# application.py - module containing the lcitool application code
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import sys
import textwrap

from pathlib import Path
from tempfile import TemporaryDirectory, NamedTemporaryFile

from lcitool import util, LcitoolError
from lcitool.config import Config
from lcitool.inventory import Inventory
from lcitool.packages import Packages
from lcitool.projects import Projects
from lcitool.targets import Targets, BuildTarget
from lcitool.formatters import DockerfileFormatter
from lcitool.formatters import ShellVariablesFormatter, JSONVariablesFormatter, YamlVariablesFormatter
from lcitool.formatters import ShellBuildEnvFormatter
from lcitool.manifest import Manifest
from lcitool.containers import Docker, Podman, ContainerExecError


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


class ApplicationError(LcitoolError):
    def __init__(self, message):
        super().__init__(message, "Application")


class Application:
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
                          config, data_dir, verbosity=0):
        from lcitool.ansible_wrapper import AnsibleWrapper

        log.debug(f"Executing playbook '{playbook}': "
                  f"hosts_pattern={hosts_pattern} "
                  f"projects_pattern={projects_pattern}")

        base = util.package_resource(__package__, "ansible").as_posix()
        config = Config(config)
        targets = Targets(data_dir)
        packages = Packages(data_dir)
        projects = Projects(data_dir)
        inventory = Inventory(targets, config,
                              inventory_path=util.get_datadir_inventory(data_dir))

        hosts_expanded = inventory.expand_hosts(hosts_pattern)
        projects_expanded = projects.expand_names(projects_pattern)

        playbook_base = Path(base, "playbooks", playbook)
        group_vars = dict()

        user_pre = False
        if data_dir:
            ansible_path = Path(data_dir.path, "ansible")
            if ansible_path.exists():
                if Path(ansible_path, "pre/tasks/main.yml").exists():
                    user_pre = True

        extra_vars = config.values
        extra_vars.update({
            "base": base,
            "selected_projects": projects_expanded,
            "user_datadir": str(data_dir.path) if data_dir else None,
            "user_pre": user_pre,
        })

        log.debug("Preparing Ansible runner environment")
        ansible_runner = AnsibleWrapper()

        for host in hosts_expanded:
            # packages are evaluated on a target level and since the
            # host->target mapping is N-1, we can skip hosts belonging to a
            # target group for which we already evaluated the package list
            target_name = inventory.get_host_target_name(host)
            if target_name in group_vars:
                continue

            target = BuildTarget(targets, packages, target_name)
            group_vars[target_name] = inventory.get_group_vars(target, projects,
                                                               projects_expanded)

        ansible_runner.prepare_env(playbookdir=playbook_base,
                                   inventories=[inventory.ansible_inventory],
                                   group_vars=group_vars,
                                   extravars=extra_vars)
        log.debug(f"Running Ansible with playbook '{playbook_base.name}'")
        ansible_runner.run_playbook(limit=hosts_expanded, verbosity=verbosity)

    @required_deps('ansible_runner', 'libvirt')
    def _action_hosts(self, args):
        self._entrypoint_debug(args)

        config_path = None
        if args.config:
            config_path = args.config.name

        config = Config(config_path)
        targets = Targets(args.data_dir)
        inventory = Inventory(targets, config,
                              inventory_path=util.get_datadir_inventory(args.data_dir))
        for host in sorted(inventory.hosts):
            print(host)

    def _action_targets(self, args):
        self._entrypoint_debug(args)

        targets = Targets(args.data_dir)
        for target in sorted(targets.targets):
            if args.containerized:
                facts = targets.target_facts[target]

                if facts["packaging"]["format"] not in ["apk", "deb", "rpm"]:
                    continue

            print(target)

    def _action_projects(self, args):
        self._entrypoint_debug(args)

        projects = Projects(args.data_dir)
        for project in sorted(projects.names):
            print(project)

    @required_deps('libvirt')
    def _action_install(self, args):
        from lcitool.install import VirtInstall

        self._entrypoint_debug(args)

        facts = {}
        config_path = None
        if args.config:
            config_path = args.config.name

        config = Config(config_path)
        targets = Targets(args.data_dir)
        inventory = Inventory(targets, config,
                              inventory_path=util.get_datadir_inventory(args.data_dir))
        host = args.host
        target = args.target

        try:
            facts = inventory.host_facts[host]
        except KeyError:
            if target is None:
                raise ApplicationError(
                    f"Host {host} not found in the inventory, either add {host} "
                    "to your inventory or use '--target <target>'"
                )

            if target not in targets.targets:
                raise ApplicationError(f"Unsupported target OS '{target}'")

            facts = targets.target_facts[target]
        else:
            if target is not None:
                raise ApplicationError(
                    f"Can't use --target with '{host}': "
                    "host already exists in the inventory"
                )
            elif not facts.get("fully_managed"):
                raise ApplicationError(
                    f"fully_managed=True not set for {host}, refusing to proceed"
                )

        if args.strategy == "cloud":
            virt_install = VirtInstall.from_vendor_image(name=host,
                                                         config=config,
                                                         facts=facts,
                                                         force_download=args.force)
        elif args.strategy == "template":
            virt_install = VirtInstall.from_template_image(name=host,
                                                           config=config,
                                                           facts=facts,
                                                           template_path=args.template)
        else:
            virt_install = VirtInstall.from_url(name=host,
                                                config=config,
                                                facts=facts)
        virt_install(wait=args.wait)

    @required_deps('ansible_runner', 'libvirt')
    def _action_update(self, args):
        self._entrypoint_debug(args)

        config_path = None
        if args.config:
            config_path = args.config.name

        self._execute_playbook("update", args.hosts, args.projects,
                               config_path, args.data_dir, args.verbose)

    def _action_variables(self, args):
        self._entrypoint_debug(args)

        targets = Targets(args.data_dir)
        packages = Packages(args.data_dir)
        projects = Projects(args.data_dir)
        projects_expanded = projects.expand_names(args.projects)

        if args.format == "shell":
            formatter = ShellVariablesFormatter(projects)
        elif args.format == "yaml":
            formatter = YamlVariablesFormatter(projects)
        else:
            formatter = JSONVariablesFormatter(projects)

        target = BuildTarget(targets, packages, args.target,
                             args.host_arch, args.cross_arch)
        variables = formatter.format(target,
                                     projects_expanded)

        # No comments in json !
        if args.format != "json":
            cliargv = [args.action]
            if args.host_arch:
                cliargv.extend(["--host-arch", args.host_arch])
            if args.cross_arch:
                cliargv.extend(["--cross-arch", args.cross_arch])
            cliargv.extend([args.target, args.projects])
            header = util.generate_file_header(cliargv)
        else:
            header = ""

        print(header + variables)

    def _action_dockerfile(self, args):
        self._entrypoint_debug(args)

        targets = Targets(args.data_dir)
        packages = Packages(args.data_dir)
        projects = Projects(args.data_dir)
        projects_expanded = projects.expand_names(args.projects)
        target = BuildTarget(targets, packages, args.target,
                             args.host_arch, args.cross_arch)

        dockerfile = DockerfileFormatter(projects,
                                         args.base,
                                         args.layers).format(target,
                                                             projects_expanded)

        cliargv = [args.action]
        if args.base is not None:
            cliargv.extend(["--base", args.base])
        cliargv.extend(["--layers", args.layers])
        if args.host_arch:
            cliargv.extend(["--host-arch", args.host_arch])
        if args.cross_arch:
            cliargv.extend(["--cross-arch", args.cross_arch])
        cliargv.extend([args.target, args.projects])
        header = util.generate_file_header(cliargv)

        print(header + dockerfile)

    def _action_buildenvscript(self, args):
        self._entrypoint_debug(args)

        targets = Targets(args.data_dir)
        packages = Packages(args.data_dir)
        projects = Projects(args.data_dir)
        projects_expanded = projects.expand_names(args.projects)
        target = BuildTarget(targets, packages, args.target,
                             args.host_arch, args.cross_arch)

        buildenvscript = ShellBuildEnvFormatter(projects).format(target,
                                                                 projects_expanded)

        cliargv = [args.action]
        if args.host_arch:
            cliargv.extend(["--host-arch", args.host_arch])
        if args.cross_arch:
            cliargv.extend(["--cross-arch", args.cross_arch])
        cliargv.extend([args.target, args.projects])
        header = util.generate_file_header(cliargv)

        print(header + buildenvscript)

    def _action_manifest(self, args):
        base_path = None
        if args.base_dir is not None:
            base_path = Path(args.base_dir)
        ci_path = Path(args.ci_dir)
        targets = Targets(args.data_dir)
        packages = Packages(args.data_dir)
        projects = Projects(args.data_dir)
        manifest = Manifest(targets, packages, projects, args.manifest, args.quiet, ci_path, base_path)
        manifest.generate(args.dry_run)

    @staticmethod
    def _container_handle(engine):
        handle = Podman()
        if engine == "docker":
            handle = Docker()

        if handle.available is None:
            raise ApplicationError(f"{handle.engine} engine not available")

        return handle

    def _action_list_engines(self, args):
        engines = []
        for engine in [Podman(), Docker()]:
            if engine.available:
                engines.append(engine.engine)

        if engines:
            print("\n".join(engines))
        else:
            print("No engine available")

    def _action_container_build(self, args):
        self._entrypoint_debug(args)

        targets = Targets()
        packages = Packages()
        projects = Projects(args.data_dir)
        projects_expanded = projects.expand_names(args.projects)
        target = BuildTarget(targets, packages, args.target, cross_arch=args.cross_arch)
        params = {}
        _file = None
        tag = f"lcitool.{args.target}"

        engine = self._container_handle(args.engine)

        # remove image and prepare to build a new one.
        engine.rmi(tag)

        container_tempdir = TemporaryDirectory(prefix="container",
                                               dir=util.get_temp_dir())
        params["tempdir"] = container_tempdir.name

        file_content = DockerfileFormatter(projects).format(
            target,
            projects_expanded
        )
        with NamedTemporaryFile("w",
                                delete=False,
                                dir=params["tempdir"]) as fd:
            fd.write(textwrap.dedent(file_content))
            _file = fd.name

        log.debug(f"Generated Dockerfile copied to {_file}")

        engine.build(tag=tag, filepath=_file, **params)

        log.debug(f"Generated image tag --> {tag}")
        print(f"Image '{tag}' successfully built.")

    def _get_container_run_common_params(self):
        params = {}
        params["image"] = self.args.image
        params["user"] = self.args.user
        if self.args.user.isdecimal():
            params["user"] = int(self.args.user)

        if self.args.env:
            params["env"] = self.args.env

        if self.args.workload_dir:
            workload_dir = Path(self.args.workload_dir)
            if not workload_dir.is_dir():
                raise ApplicationError(f"'{workload_dir}' is not a directory")
            params["datadir"] = workload_dir.resolve()

        if self.args.script:
            script = Path(self.args.script)
            if not script.is_file():
                raise ApplicationError(f"'{script}' is not a file")
            params["script"] = script.resolve()

        return params

    def _container_run(self, container_params, shell=False):
        """
        Call into the container handle object.

        :param shell: whether to spawn an interactive shell session
        :param **kwargs: arguments passed to Container.run()
        """

        container_tempdir = TemporaryDirectory(prefix="container",
                                               dir=util.get_temp_dir())

        container_params["tempdir"] = container_tempdir.name
        engine = self._container_handle(self.args.engine)
        if shell:
            return engine.shell(**container_params)
        return engine.run(**container_params)

    def _action_container_run(self, args):
        self._entrypoint_debug(self.args)

        params = self._get_container_run_common_params()
        params["container_cmd"] = "./script"
        return self._container_run(params)

    def _action_container_shell(self, args):
        self._entrypoint_debug(self.args)

        return self._container_run(self._get_container_run_common_params(),
                                   shell=True)

    def run(self, args):
        try:
            self.args = args
            args.func(self, args)
        except ContainerExecError as ex:
            sys.exit(ex.returncode)
        except LcitoolError as ex:
            print(f"{ex.module_prefix} error:", ex, file=sys.stderr)
            sys.exit(1)
