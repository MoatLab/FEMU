# targets.py - module containing accessors to per-target information
#
# Copyright (C) 2022 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

from lcitool import util, LcitoolError


log = logging.getLogger(__name__)


class TargetsError(LcitoolError):
    """Global exception type for the targets module."""

    def __init__(self, message):
        super().__init__(message, "Targets")


class Targets():

    @property
    def target_facts(self):
        if self._target_facts is None:
            self._load_target_facts()
        return self._target_facts

    @property
    def targets(self):
        return list(self.target_facts.keys())

    def __init__(self, data_dir=util.DataDir()):
        self._data_dir = data_dir
        self._target_facts = None

    @staticmethod
    def _validate_target_facts(target_facts, target):
        fname = target + ".yml"

        actual_osname = target_facts["os"]["name"].lower()
        if not target.startswith(actual_osname + "-"):
            raise TargetsError(f'OS name "{target_facts["os"]["name"]}" does not match file name {fname}')
        target = target[len(actual_osname) + 1:]

        actual_version = target_facts["os"]["version"].lower()
        expected_version = target.replace("-", "")
        if expected_version != actual_version:
            raise TargetsError(f'OS version "{target_facts["os"]["version"]}" does not match version in file name {fname} ({expected_version})')

    def _load_target_facts(self):
        facts = {}
        all_targets = {item.stem
                       for item in self._data_dir.list_files("facts/targets", ".yml")}

        # first load the shared facts from targets/all.yml
        shared_facts = self._data_dir.merge_facts("facts/targets", "all")

        # then load the rest of the facts
        for target in all_targets:
            if target == "all":
                continue

            facts[target] = self._data_dir.merge_facts("facts/targets", target)
            self._validate_target_facts(facts[target], target)
            facts[target]["target"] = target

            # missing per-distro facts fall back to shared facts
            util.merge_dict(shared_facts, facts[target])

        self._target_facts = facts


class BuildTarget:
    """
    Attributes:
        :ivar _targets: object to retrieve the target facts
        :ivar name: target name
        :ivar cross_arch: cross compilation architecture
    """

    def __init__(self, targets, packages, name, cross_arch=None):
        if name not in targets.target_facts:
            raise TargetsError(f"Target not found: {name}")
        self._packages = packages
        self.name = name
        self.cross_arch = cross_arch
        self.facts = targets.target_facts[self.name]

    def __str__(self):
        if self.cross_arch:
            return f"{self.name} (cross_arch={self.cross_arch}"
        else:
            return self.name

    def get_package(self, name):
        return self._packages.get_package(name, self)
