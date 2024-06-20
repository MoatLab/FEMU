# config.py - module containing configuration file handling primitives
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import logging
import yaml

from pathlib import Path

from lcitool import util, LcitoolError

log = logging.getLogger(__name__)


class ConfigError(LcitoolError):
    """
    Global exception type for the config module.

    Contains a detailed message coming from one of its subclassed exception
    types.
    """

    def __init__(self, message):
        super().__init__(message, "Configuration")


class LoadError(ConfigError):
    """Thrown when the configuration for lcitool could not be loaded."""

    def __init__(self, message):
        message_prefix = "Failed to load config: "
        message = message_prefix + message
        super().__init__(message)


class ValidationError(ConfigError):
    """Thrown when the configuration for lcitool could not be validated."""

    def __init__(self, message):
        message_prefix = "Failed to validate config: "
        message = message_prefix + message
        super().__init__(message)


class Config:

    @property
    def values(self):

        # lazy evaluation: most lcitool actions actually don't need the config
        if self._values is None:
            values = self._load_config()
            self._validate(values)
            self._values = values
        return self._values

    def __init__(self, path=None):
        self._values = None
        self._config_file_paths = None

        if path is not None:
            self._config_file_paths = [Path(path)]
        else:
            self._config_file_paths = [
                Path(util.get_config_dir(), fname) for fname in ["config.yml",
                                                                 "config.yaml"]
            ]

    def _load_config(self):
        # Load the template config containing the defaults first, this must
        # always succeed.
        default_config_path = util.package_resource(__package__,
                                                    "etc/config.yml")
        with open(default_config_path, "r") as fp:
            default_config = yaml.safe_load(fp)

        user_config_path = None
        for user_config_path in self._config_file_paths:
            if not user_config_path.exists():
                continue

            user_config_path_str = user_config_path.as_posix()
            log.debug(f"Loading configuration from '{user_config_path_str}'")
            try:
                with open(user_config_path, "r") as fp:
                    user_config = yaml.safe_load(fp)
                    if user_config is None:
                        user_config = {}
            except Exception as e:
                raise LoadError(f"'{user_config_path.name}': {e}")

            break
        else:
            user_config = {}

        # delete user params we don't recognize
        self._sanitize_values(user_config, default_config)

        # Override the default settings with user config
        values = self._merge_config(default_config, user_config)
        return values

    @staticmethod
    def _remove_unknown_keys(_dict, known_keys):
        keys = list(_dict.keys())

        for k in keys:
            if k not in known_keys:
                log.debug(f"Removing unknown key '{k}' from config")

                del _dict[k]

    @staticmethod
    def _merge_config(default_config, user_config):
        config = copy.deepcopy(default_config)
        for section in default_config.keys():
            if section in user_config:
                log.debug(f"Applying user values: '{user_config[section]}'")

                config[section].update(user_config[section])
        return config

    def _sanitize_values(self, user_config, default_config):
        # remove keys we don't recognize
        self._remove_unknown_keys(user_config, default_config.keys())
        for section in default_config.keys():
            if section in user_config:
                self._remove_unknown_keys(user_config[section],
                                          default_config[section].keys())

    def _validate_keys(self, values, pathprefix=""):
        log.debug(f"Validating section='[{pathprefix}]'")

        # check that all keys have values assigned and of the right type
        for key, value in values.items():
            if isinstance(value, dict):
                self._validate_keys(value, pathprefix + "." + key)
                continue

            if value is None:
                raise ValidationError(f"Missing value for '{pathprefix}.{key}'")

            if not isinstance(value, (str, int)):
                raise ValidationError(f"Invalid type for key '{pathprefix}.{key}'")

    def _validate(self, values):
        self._validate_keys(values)

        flavor = values["install"].get("flavor")
        if flavor not in ["test", "gitlab"]:
            raise ValidationError(
                f"Invalid value '{flavor}' for 'install.flavor'"
            )

        if flavor == "gitlab":
            secret = values["gitlab"]["runner_secret"]
            if secret == "NONE" or secret is None:
                raise ValidationError(
                    "Invalid value for 'gitlab.runner_secret'"
                )
