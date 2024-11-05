# containers.py - module implementing generic container runtime wrapper logic
#
# Copyright (c) 2023 Abdulwasiu Apalowo.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pwd
import shutil
import logging
import subprocess

from abc import ABC, abstractmethod
from pathlib import Path

from lcitool import LcitoolError

log = logging.getLogger()


class ContainerError(LcitoolError):
    """Global exception type for this module."""

    def __init__(self, message):
        super().__init__(message, "Container")


class ContainerExecError(ContainerError):
    """ Thrown whenever an error occurs during container engine execution. """

    def __init__(self, rc, message=None):
        if message is None:
            message = f"Process exited with error code {rc}"

        super().__init__(message)
        self.returncode = rc


class Container(ABC):
    """Abstract class for containers"""

    def __init__(self):
        if self.__class__ is Container:
            self.engine = None
        else:
            self.engine = self.__class__.__name__.lower()

    @staticmethod
    def _exec(command, **kwargs):
        """
        Execute command in a subprocess.run call.

        :param command: a list of command to run in the process
        :param **kwargs: arguments passed to subprocess.run()

        :returns: an instance of subprocess.CompletedProcess
        """

        try:
            proc = subprocess.run(args=command, encoding="utf-8",
                                  **kwargs)
        except subprocess.CalledProcessError as ex:
            raise ContainerExecError(ex.returncode, ex.stderr)

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

        engine_args = []
        passwd_entry = self._passwd(user)
        user_home = passwd_entry[5]

        # We need the container process to run with current host IDs
        # so that it can access the passed in data directory
        uid, gid = passwd_entry[2], passwd_entry[3]

        #   --user    we execute as the same user & group account
        #             as dev so that file ownership matches host
        #             instead of root:root
        user = f"{uid}:{gid}"

        if uid != 0:
            # We mount these only when running as user other than root inside
            # the container, because standard operations over /etc/passwd and
            # /etc/group will fail due to the volumes being bind mounted. We
            # shouldn't need these when run as root.
            #
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

            # We mount a temporary directory as the user's home in
            # order to set correct home directory permissions.
            home = Path(tempdir, "home")
            home.mkdir(exist_ok=True)

            home_mount = f"{home}:{user_home}:z"
            engine_args.extend([
                ("--volume", passwd_mount),
                ("--volume", group_mount),
                ("--volume", home_mount),
            ])

        # Docker containers can have very large ulimits
        # for nofiles - as much as 1048576. This makes
        # some applications very slow at executing programs.
        ulimit_files = 1024
        ulimit = f"nofile={ulimit_files}:{ulimit_files}"

        engine_args.extend([
            ("--user", user),
            ("--workdir", f"{user_home}"),
            ("--ulimit", ulimit),
            ("--cap-add", "SYS_PTRACE"),
        ])

        if script:
            script_file = Path(shutil.copy2(script, Path(tempdir, "script")))

            # make the script an executable file
            script_file.chmod(script_file.stat().st_mode | 0o111)

            script_mount = f"{script_file}:{user_home}/script:z"
            engine_args.extend([
                ("--volume", script_mount)
            ])

        if datadir:
            datadir_mount = f"{datadir}:{user_home}/datadir:z"
            engine_args.extend([
                ("--volume", datadir_mount),
            ])

        if env:
            envs = [("--env=" + i,) for i in env]
            engine_args.extend(envs)

        log.debug(f"Container options: {engine_args}")
        return engine_args

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

    @abstractmethod
    def image_exists(self):
        pass

    def _run(self, image, container_cmd, engine_extra_args, **kwargs):
        tag = "latest"
        if ":" in image:
            image, tag = image.split(":")

        if not self.image_exists(image, tag):
            raise ContainerError(
                f"Image '{image}:{tag}' not found in local cache. "
                "Build it or pull from registry first."
            )

        cmd = [self.engine, "run"] + engine_extra_args
        cmd.extend([image, container_cmd])

        log.debug(f"Run command: {cmd}")
        run = self._exec(cmd, check=True, **kwargs)
        return run.returncode

    @abstractmethod
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

        engine_extra_args = ["--rm", "--interactive"]

        build_args = self._build_args(
            user, tempdir, env=env, datadir=datadir, script=script
        )
        engine_extra_args.extend([item for tuple_ in build_args for item in tuple_])

        return self._run(image, container_cmd, engine_extra_args, **kwargs)

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
        build = self._exec(cmd, check=True, **kwargs)
        return build.returncode

    @abstractmethod
    def shell(self, image, user, tempdir, env=None, datadir=None, script=None,
              **kwargs):
        """
        Spawns an interactive shell inside the container.

        This method is essentially just a convenience alternative over plain
        Container.run() with 'container_cmd' being '/bin/sh'. The rest of the
        arguments bear the exact same semantics.
        """

        engine_extra_args = ["--rm", "--interactive", "--tty"]

        build_args = self._build_args(
            user, tempdir, env=env, datadir=datadir, script=script
        )
        engine_extra_args.extend([item for tuple_ in build_args for item in tuple_])
        return self._run(image, "/bin/sh", engine_extra_args, **kwargs)
