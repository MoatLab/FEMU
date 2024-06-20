# cloud_init.py - module implementing cloud-init handling
#
# Copyright (C) 2023 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import sys
import yaml

from collections import UserDict
from pkg_resources import resource_filename

from lcitool import LcitoolError

log = logging.getLogger(__name__)


class CloudConfigError(LcitoolError):
    def __init__(self, msg):
        pass


class CloudConfig(UserDict):
    """ Cloud-config settings abstraction. """

    def __init__(self, file=None, **kwargs):
        """
        Creates the cloud-config configuration for cloud-init.

        :param file: base cloud-config file to load values from (str or Path)
        :param kwargs: parameters passed directly do the dict class
        """

        cloud_config_base = file
        if cloud_config_base is None:
            cloud_config_base = resource_filename(__name__,
                                                  "configs/cloud-init.conf.in")

        try:
            with open(cloud_config_base, "r") as fd:
                values = yaml.safe_load(fd)
        except Exception as ex:
            raise CloudConfigError(ex)
            sys.exit(1)

        kwargs.update(values)
        super().__init__(**kwargs)

    def dump(self, file=None):
        """
        Serialize the cloud config dict into a YAML stream.

        If file is None, return a formatted string instead
        :param file: Path object
        """

        # nasty hack to force PyYAML not to break long lines by default
        from math import inf

        _string = "#cloud-config\n"
        _string += yaml.dump(self.data, width=inf)

        if file is None:
            return _string

        with open(file, "w") as f:
            return f.write(_string)
