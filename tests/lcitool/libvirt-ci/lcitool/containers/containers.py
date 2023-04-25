# containers.py - module implementing generic container runtime wrapper logic
#
# Copyright (c) 2023 Abdulwasiu Apalowo.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pwd
import shutil
import logging
import subprocess

from abc import ABC
from pathlib import Path

from lcitool import LcitoolError

log = logging.getLogger()


class ContainerError(LcitoolError):
    """Global exception type for this module."""

    def __init__(self, message):
        super().__init__(self)
        self.message = self.__class__.__name__ + ": " + message


class Container(ABC):
    """Abstract class for containers"""

    def __init__(self):
        if self.__class__ is Container:
            self.engine = None
        else:
            self.engine = self.__class__.__name__.lower()

        self._run_exception = None
        self._build_exception = None

    @staticmethod
    def _exec(command, _exception=ContainerError, **kwargs):
        """
        Execute command in a subprocess.run call.

        :param command: a list of command to run in the process
        :param _exception: an instance of ContainerError
        :param **kwargs: arguments passed to subprocess.run()

        :returns: an instance of subprocess.CompletedProcess
        """

        try:
            proc = subprocess.run(args=command, encoding="utf-8",
                                  **kwargs)
        except subprocess.CalledProcessError as ex:
            raise _exception(str(ex.returncode))

        return proc

    def _check(self):
        """
        Checks that engine is available and running. It
        does this by running "{/path/to/engine} version"
        to check if the engine is available

        Returns
             True: if the path can be found and the
                   engine is available.
             False: if the path can not be found OR
                    if the path can be found AND
                      the engine is not running OR
                      the engine's background process is not
                      well set up.
        """

        message = f"Checking if '{self.engine}' is available...%s"

        command = shutil.which(self.engine)
        if command is None:
            log.debug(message, f"no\n'{self.engine}' path cannot be found")
            return False

        exists = self._exec([command, "version"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
        if exists.returncode:
            log.debug(message, "no")
        else:
            log.debug(message, "yes")

        log.debug("\n" + exists.stdout)
        return not exists.returncode

    @property
    def available(self):
        """
        Checks whether the container engine is available and ready to use.

        :returns: boolean
        """

        return self._check()

    @staticmethod
    def _passwd(user):
        """
        Get entry from Unix password database

        :param user: numerical ID (int) or username (str) of the user

        Returns the "/etc/passwd" 7-element tuple:
            name:password:UID:GID:GECOS:directory:shell
        """

        try:
            if type(user) is str:
                return pwd.getpwnam(user)
            elif type(user) is int and user >= 0:
                return pwd.getpwuid(user)
            else:
                raise TypeError(f"{user} must be a string or an integer")
        except KeyError:
            raise ContainerError(f"user, {user} not found")

    def _build_args(self, user, tempdir, env=None, datadir=None, script=None):
        """
        Generate container options.

        These options are then passed to the command to run
        an engine.

        :param user: numerical ID or username of the user
        :param tempdir: path to a temporary directory
        :param env: a list of string containing environmental
                    variables and values. e.g ["FOO=bar"]
        :param datadir: path to a directory containing all the
                        files and folders needed to run workload in
                        a container.
        :param script: path to an executable script to kickstart
                       operations in the container.

        :returns: a list.
        The list contains some options passed to the engine. e.g
        [
            '--env=F00=bar', '--env=BAR=baz', '--user', '0:0',
            '--volume', '/user/path:/container/path',
            '--workdir', /path/to/home',
            '--ulimit', 'nofile=1024:1024',
            '--cap-add', 'SYS_PTRACE'
        ]
        """

        passwd_entry = self._passwd(user)
        user_home = passwd_entry[5]

        # We need the container process to run with current host IDs
        # so that it can access the passed in data directory
        uid, gid = passwd_entry[2], passwd_entry[3]

        #   --user    we execute as the same user & group account
        #             as dev so that file ownership matches host
        #             instead of root:root
        user = f"{uid}:{gid}"

        # We do not directly mount /etc/{passwd,group} as Docker
        # is liable to mess with SELinux labelling which will
        # then prevent the host accessing them. And podman cannot
        # relabel the files due to it running rootless. So
        # copying them first is safer and less error-prone.
        passwd = shutil.copy2(
            "/etc/passwd", Path(tempdir, 'passwd.copy')
        )
        group = shutil.copy2(
            "/etc/group", Path(tempdir, 'group.copy')
        )

        passwd_mount = f"{passwd}:/etc/passwd:ro,z"
        group_mount = f"{group}:/etc/group:ro,z"

        # Docker containers can have very large ulimits
        # for nofiles - as much as 1048576. This makes
        # some applications very slow at executing programs.
        ulimit_files = 1024
        ulimit = f"nofile={ulimit_files}:{ulimit_files}"

        cap_add = "SYS_PTRACE"

        engine_args_ = [
            "--user", user,
            "--volume", passwd_mount,
            "--volume", group_mount,
            "--ulimit", ulimit,
            "--cap-add", cap_add
        ]

        if script:
            script_file = shutil.copy2(
                script, Path(tempdir, "script")
            )
            script_mount = f"{script_file}:{user_home}/script:z"
            engine_args_.extend([
                "--volume", script_mount
            ])

        if datadir:
            datadir_mount = f"{datadir}:{user_home}/datadir:z"
            engine_args_.extend([
                "--volume", datadir_mount,
            ])

        if env:
            envs = ["--env=" + i for i in env]
            engine_args_.extend(envs)

        if datadir or script:
            engine_args_.extend([
                "--workdir", f"{user_home}",
            ])

        log.debug(f"Container options: {engine_args_}")
        return engine_args_

    def rmi(self, image):
        """
        Remove a container image.
        :param image: name of the image to remove (str).

        :returns: boolean.
        It returns True if image was successfully removed, False otherwise.
        """

        # podman rmi {image}
        cmd = [self.engine, "rmi", image]
        proc = self._exec(cmd,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
        log.debug(proc.stdout.strip())
        return not proc.returncode

    def _images(self):
        """
        Get all container images.

        :returns: a string in JSON format containing image details.
        """

        # podman images --format json --filter dangling=false

        cmd_args = ["--format", "json", "--filter", "dangling=false"]
        cmd = [self.engine, "images"]

        cmd.extend(cmd_args)
        img = self._exec(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
        log.debug(f"{self.engine} images\n%s", img.stdout)
        return img.stdout

    def run(self, image, container_cmd, user, tempdir, env=None,
            datadir=None, script=None, **kwargs):
        """
        Prepares and run the command.

        This method generates the engine command from the arguments
        and passes the full generated command to the "_exec()" method.

        :param image: name of the image to run container in (str).
        :param container_cmd: command to run in the container (str).
        :param user:  user to run as in the container.
        :param tempdir: path to a temporary directory.
        :param env: a list of string. Each string is an environmental variable.
        :param datadir: path to all the files and folder required to
                        run workloads.
        :param script: path to an executable script to kickstart
                       operations in the container.
        :param **kwargs: arguments passed to subprocess.run()

        e.g {
                "image": "ubuntu", "container_cmd": "/bin/sh", "user": 0,
                "tempdir": /path/to/dir, "env": ["FOO=bar"],
                "engine": "podman", "datadir": /path/to/data/dir"
            }
        :returns: an integer.

        The returned integer is the status code of the underlying process
        after completion.
        """

        # podman run --rm -it --user root --env FOO=bar {image} {cmd}
        #
        # Args to use when running the container
        #   --rm      stop inactive containers getting left behind
        #   --volume  to pass in the cloned git repo & config
        #   --ulimit  lower files limit for performance reasons
        #   --interactive
        #   --tty     Ensure we have ability to Ctrl-C the build

        cmd_args = ["--rm", "--interactive", "--tty"]

        build_args = self._build_args(
            user, tempdir, env=env, datadir=datadir, script=script
        )
        cmd_args.extend(build_args)

        cmd = [self.engine, "run"]
        cmd.extend(cmd_args)
        cmd.extend([image, container_cmd])

        log.debug(f"Run command: {cmd}")
        run = self._exec(cmd,
                         _exception=self._run_exception,
                         check=True, **kwargs)
        return run.returncode

    def build(self, filepath, tempdir, tag, **kwargs):
        """
        Prepares and runs the container engine's build command.

        This method generates the engine command from the arguments
        and passes the generated command to the "_exec()" method.

        :param filepath: path to a file containing the Dockerfile/Containerfile
        :param tempdir: path to a directory which would be used as
                         build context.
        :param tag: name of the image to be built.
        :param **kwargs: arguments passed to subprocess.run()

        e.g {
                "filepath": "/path/to/Dockerfile", "tempdir": /path/to/dir,
                "tag": "lcitool-fedora-36-libvirt-python"
            }

        :returns: an integer.
        The returned integer is the status code after completing the build.
        """

        # podman build --pull --tag $TAG --file='container/Dockerfile' .

        cmd_args = [
            "--pull",
            "--tag", tag,
            "--file", filepath,
            f"{tempdir}"
        ]

        cmd = [self.engine, "build"]
        cmd.extend(cmd_args)

        log.debug(f"Build command: {cmd}")
        build = self._exec(cmd,
                           _exception=self._build_exception,
                           check=True, **kwargs)
        return build.returncode
