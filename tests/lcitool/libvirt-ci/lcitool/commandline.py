# commandline.py - module containing the lcitool command line parser
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import logging
import argparse

from pathlib import Path

from lcitool.application import Application
from lcitool.util import DataDir


log = logging.getLogger(__name__)


class DataDirAction(argparse.Action):
    def __init__(self, option_strings, dest, default=DataDir(), nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, default=default, nargs=1, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, DataDir(values[0]))


class CommandLine:

    def __init__(self):
        # Common option parsers to inherit from

        hostsopt = argparse.ArgumentParser(add_help=False)
        hostsopt.add_argument(
            "hosts",
            help="list of hosts to act on (accepts globs)",
        )

        targetopt = argparse.ArgumentParser(add_help=False)
        targetopt.add_argument(
            "target",
            help="target to operate on",
        )

        engineopt = argparse.ArgumentParser(add_help=False)
        engineopt.add_argument(
            "--engine",
            choices=["podman", "docker"],
            default="podman",
            help="container engine to use (default=podman)",
        )

        workload_diropt = argparse.ArgumentParser(add_help=False)
        workload_diropt.add_argument(
            "--workload-dir",
            help="absolute path of data/scratch directory to be \
                  mounted in the container",
        )

        scriptopt = argparse.ArgumentParser(add_help=False)
        scriptopt.add_argument(
            "--script",
            help="absolute path to the script which will run the workload",
        )

        containeropt = argparse.ArgumentParser(add_help=False)
        containeropt.add_argument(
            "--env",
            action="append",
            help="environment variables to set in the container \
                  (option can be passed multiple times e.g --env FOO=bar \
                  --env BAR=baz)",
        )
        containeropt.add_argument(
            "--user",
            default="root",
            help="user to run in the container—accepts \
                  id or username (default=root)",
        )

        imageopt = argparse.ArgumentParser(add_help=False)
        imageopt.add_argument(
            "image",
            help="Image to use (accepts plain names, image IDs, \
                  full registry paths and tags)",
        )

        container_projectopt = argparse.ArgumentParser(add_help=False)
        container_projectopt.add_argument(
            "-p", "--projects",
            help="list of projects (accepts globs)",
        )

        installtargetopt = argparse.ArgumentParser(add_help=False)
        installtargetopt.add_argument(
            "-t", "--target",
            help="what target OS to install",
        )

        installhostopt = argparse.ArgumentParser(add_help=False)
        installhostopt.add_argument(
            "host",
            help="name of the host (taken from inventory OR a new name)",
        )

        update_projectopt = argparse.ArgumentParser(add_help=False)
        update_projectopt.add_argument(
            "projects",
            help="list of projects to consider (accepts globs)",
        )

        gitrevopt = argparse.ArgumentParser(add_help=False)
        gitrevopt.add_argument(
            "-g", "--git-revision",
            help="git revision to build (remote/branch)",
        )

        containerizedopt = argparse.ArgumentParser(add_help=False)
        containerizedopt.add_argument(
            "-c", "--containerized",
            default=False,
            action="store_true",
            help="only report hosts supporting containers")

        crossarchopt = argparse.ArgumentParser(add_help=False)
        crossarchopt.add_argument(
            "-x", "--cross-arch",
            help="target architecture for cross compiler",
        )

        baseopt = argparse.ArgumentParser(add_help=False)
        baseopt.add_argument(
            "-b", "--base",
            help="base image to inherit from",
        )

        layersopt = argparse.ArgumentParser(add_help=False)
        layersopt.add_argument(
            "-l", "--layers",
            default="all",
            choices=['all', 'native', 'foreign'],
            help="output layers (default: 'all')",
        )

        waitopt = argparse.ArgumentParser(add_help=False)
        waitopt.add_argument(
            "-w", "--wait",
            help="wait for installation to complete",
            default=False,
            action="store_true",
        )

        manifestopt = argparse.ArgumentParser(add_help=False)
        manifestopt.add_argument(
            "manifest",
            metavar="PATH",
            default=Path("ci", "manifest.yml").as_posix(),
            nargs="?",
            type=argparse.FileType('r'),
            help="path to CI manifest file (default: 'ci/manifest.yml')",
        )

        dryrunopt = argparse.ArgumentParser(add_help=False)
        dryrunopt.add_argument(
            "-n", "--dry-run",
            action="store_true",
            help="print what files would be generated",
        )

        verbosityopt = argparse.ArgumentParser(add_help=False)
        verbosityopt.add_argument(
            "-v", "--verbose",
            action="count",
            help="make Ansible more verbose (repeat for even more output)",
        )

        quietopt = argparse.ArgumentParser(add_help=False)
        quietopt.add_argument(
            "-q", "--quiet",
            action="store_true",
            help="don't display progress information",
        )

        formatopt = argparse.ArgumentParser(add_help=False)
        formatopt.add_argument(
            "-f", "--format",
            default="shell",
            choices=["shell", "json"],
            help="output format (default: shell)",
        )

        basediropt = argparse.ArgumentParser(add_help=False)
        basediropt.add_argument(
            "--base-dir",
            default=None,
            help="Project base directory (default: current working directory)")

        cidiropt = argparse.ArgumentParser(add_help=False)
        cidiropt.add_argument(
            "--ci-dir",
            default="ci",
            help="CI config directory relative to base dir (default: 'ci')")

        # Main parser
        self._parser = argparse.ArgumentParser(
            conflict_handler="resolve",
            description="libvirt CI guest management tool",
        )

        self._parser.add_argument(
            "--debug",
            help="display debugging information",
            action="store_true",
        )
        self._parser.add_argument(
            "-d", "--data-dir",
            action=DataDirAction,
            help="extra directory for loading data files from")

        subparsers = self._parser.add_subparsers(metavar="ACTION",
                                                 dest="action")
        subparsers.required = True

        # lcitool subcommand parsers
        installparser = subparsers.add_parser(
            "install",
            help="perform unattended host installation",
            parents=[waitopt, installtargetopt, installhostopt],
        )
        installparser.set_defaults(func=Application._action_install)

        updateparser = subparsers.add_parser(
            "update",
            help="prepare hosts and keep them updated",
            parents=[verbosityopt, hostsopt, update_projectopt, gitrevopt],
        )
        updateparser.set_defaults(func=Application._action_update)

        buildparser = subparsers.add_parser(
            "build",
            help="build projects on hosts",
            parents=[verbosityopt, hostsopt, gitrevopt],
        )
        buildparser.add_argument(
            "projects",
            help="list of projects to consider (does NOT accept globs)",
        )
        buildparser.set_defaults(func=Application._action_build)

        hostsparser = subparsers.add_parser(
            "hosts",
            help="list all known hosts",
        )
        hostsparser.set_defaults(func=Application._action_hosts)

        targetsparser = subparsers.add_parser(
            "targets",
            help="list all supported target OS platforms",
            parents=[containerizedopt],
        )
        targetsparser.set_defaults(func=Application._action_targets)

        projectsparser = subparsers.add_parser(
            "projects",
            help="list all known projects",
        )
        projectsparser.set_defaults(func=Application._action_projects)

        variablesparser = subparsers.add_parser(
            "variables",
            help="generate variables",
            parents=[formatopt, targetopt, update_projectopt, crossarchopt],
        )
        variablesparser.set_defaults(func=Application._action_variables)

        dockerfileparser = subparsers.add_parser(
            "dockerfile",
            help="generate Dockerfile",
            parents=[targetopt, update_projectopt, crossarchopt,
                     baseopt, layersopt],
        )
        dockerfileparser.set_defaults(func=Application._action_dockerfile)

        buildenvscriptparser = subparsers.add_parser(
            "buildenvscript",
            help="generate shell script for build environment setup",
            parents=[targetopt, update_projectopt, crossarchopt],
        )
        buildenvscriptparser.set_defaults(func=Application._action_buildenvscript)

        manifestparser = subparsers.add_parser(
            "manifest",
            help="apply the CI manifest (doesn't access the host)",
            parents=[manifestopt, dryrunopt, quietopt, basediropt, cidiropt])
        manifestparser.set_defaults(func=Application._action_manifest)

        container_parser = subparsers.add_parser(
            "container",
            help="Container related functionality"
        )

        containersubparser = container_parser.add_subparsers(metavar="COMMAND",
                                                             dest='container')
        containersubparser.required = True

        container_engineparser = containersubparser.add_parser(
            "engines",
            help="List available container engines",
        )
        container_engineparser.set_defaults(func=Application._action_list_engines)

        build_containerparser = containersubparser.add_parser(
            "build",
            help="Build container image",
            parents=[installtargetopt, container_projectopt, engineopt,
                     crossarchopt],
        )
        build_containerparser.set_defaults(func=Application._action_container_build)

        run_containerparser = containersubparser.add_parser(
            "run",
            help="run container action",
            parents=[imageopt, containeropt, engineopt, workload_diropt, scriptopt]
        )
        run_containerparser.set_defaults(func=Application._action_container_run)

        shell_containerparser = containersubparser.add_parser(
            "shell",
            help="Access to an interactive shell",
            parents=[imageopt, containeropt, engineopt, workload_diropt, scriptopt]
        )
        shell_containerparser.set_defaults(func=Application._action_container_run)

    # Validate "container" args
    def _validate(self, args):
        """
        Validate command line arguments.
        :param args: argparse.Namespace object which contains
                     all the CLI arguments.

        :return: args.
        """

        if vars(args).get("container") \
                and args.container in ["build", "run", "shell"]:

            # Ensure that (--target & --projects) argument are passed with
            # "build" subcommand.
            if args.container == "build":
                if args.projects and args.target:
                    return args
                else:
                    log.error("--target and --projects are required")
                    sys.exit(1)

            if args.container == "run":
                # "run" subcommand only requires "--script" argument;
                # it works with or without "--workload-dir" argument
                if not args.script:
                    log.error("--script is required")
                    sys.exit(1)

        return args

    def parse(self):
        return self._validate(self._parser.parse_args())
