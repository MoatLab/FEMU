# install.py - module providing VM installation abstraction layer
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import subprocess

from pathlib import Path
from pkg_resources import resource_filename

from lcitool import util, LcitoolError
from lcitool.config import Config
from lcitool.libvirt_wrapper import LibvirtWrapper

log = logging.getLogger(__name__)


class InstallerError(LcitoolError):
    def __init__(self, message):
        super().__init__(message, "Installer")


class InstallationNotSupported(InstallerError):
    def __init__(self, target):
        msg = f"Target '{target}' doesn't support installation"
        super().__init__(msg)


class VirtInstall:

    @classmethod
    def from_url(cls, name, facts):
        """ Shortcut constructor for a URL-based network installation. """

        runner = cls(name, facts)

        config = Config()
        conf_size = config.values["install"]["disk_size"]
        conf_pool = config.values["install"]["storage_pool"]
        disk_arg = (f"size={conf_size},"
                    f"pool={conf_pool},"
                    f"bus=virtio")

        conf_size = config.values["install"]["disk_size"]
        conf_pool = config.values["install"]["storage_pool"]
        disk_arg = f"size={conf_size},pool={conf_pool},bus=virtio"

        runner.args.extend(["--disk", disk_arg])
        runner.args.extend(runner._get_common_args())
        runner.args.extend(runner._get_unattended_args(facts))

        return runner

    def __init__(self, name, facts):
        """
        Instantiates the virt-install installer backend.

        :param name: name for the VM instance (str)
        :param facts: host facts for this OS instance (dict)
        :returns: VirtInstall object
        """

        self.name = name
        self.args = []
        self._facts = facts
        self._cmd = "virt-install"

    def __call__(self, wait=False):
        """
        Kick off the VM installation.

        Convenience wrapper around the run method. This is the same as if you
        built the object manually and ran the 'run' method:
            vi = VirtInstall(name, facts)
            vi.args = [custom_args]
            vi.run(wait=True)

        """

        return self.run(wait)

    def __str__(self):
        return " ".join([self._cmd] + self.args)

    @staticmethod
    def _get_common_args():
        config = Config()

        # Both memory size and disk size are stored as GiB in the
        # inventory, but virt-install expects the disk size in GiB
        # and the memory size in *MiB*, so perform conversion here
        memory_arg = str(config.values["install"]["memory_size"] * 1024)
        vcpus_arg = str(config.values["install"]["vcpus"])
        conf_network = config.values["install"]["network"]
        network_arg = f"network={conf_network},model=virtio"

        args = [
            "--os-variant", "unknown",
            "--virt-type", config.values["install"]["virt_type"],
            "--arch", config.values["install"]["arch"],
            "--machine", config.values["install"]["machine"],
            "--cpu", config.values["install"]["cpu_model"],
            "--vcpus", vcpus_arg,
            "--memory", memory_arg,
            "--network", network_arg,
            "--graphics", "none",
            "--console", "pty",
            "--sound", "none",
            "--rng", "device=/dev/urandom,model=virtio",
        ]

        return args

    @staticmethod
    def _get_unattended_args(facts):
        target = facts["target"]

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
            raise InstallationNotSupported(target)

        try:
            unattended_options = {
                "install.url": facts["install"]["url"],
            }
        except KeyError:
            raise InstallationNotSupported(target)

        # Unattended install scripts are being generated on the fly, based
        # on the templates present in lcitool/configs/
        filename = resource_filename("lcitool",
                                     f"configs/{install_config}")
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
        url_args = [
            "--location", facts["install"]["url"],
            "--initrd-inject", initrd_inject,
            "--extra-args", extra_arg,
        ]
        return url_args

    def run(self, wait=False):
        """
        Kick off the VM installation.

        :param wait: whether to wait for the installation to complete (boolean)
        """

        if not wait:
            self.args.append("--noautoconsole")

        self.args.extend(["--name", self.name])
        cmd = [self._cmd] + self.args
        log.debug(f"Running {cmd}")
        try:
            subprocess.check_call(cmd)

            # mark the host XML using XML metadata
            LibvirtWrapper().set_target(self.name, self._facts["target"])
        except Exception as ex:
            raise InstallerError(
                f"Failed to install host '{self.name}': {ex}"
            )
