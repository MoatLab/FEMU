# inventory - module containing Ansible inventory handling primitives
#
# Copyright (C) 2017-2020 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import copy
import logging
import yaml

from pathlib import Path
from pkg_resources import resource_filename

from lcitool import util
from lcitool.singleton import Singleton

log = logging.getLogger(__name__)


class InventoryError(Exception):
    """
    Global exception type for the inventory module.

    Functions/methods in this module will raise either this exception or its
    subclass on failure.
    On the application level, this is the exception type you should be catching.
    """

    def __init__(self, message):
        self.message = message

    def __str__(self):
        return f"Inventory error: {self.message}"


class Inventory(metaclass=Singleton):

    @property
    def target_facts(self):
        if self._target_facts is None:
            self._target_facts = self._load_target_facts()
        return self._target_facts

    @property
    def targets(self):
        return list(self.target_facts.keys())

    @property
    def host_facts(self):
        if self._host_facts is None:
            self._host_facts = self._load_host_facts()
        return self._host_facts

    @property
    def hosts(self):
        return list(self.host_facts.keys())

    def __init__(self):
        self._target_facts = None
        self._host_facts = None

    @staticmethod
    def _read_facts_from_file(yaml_path):
        with open(yaml_path, "r") as infile:
            return yaml.safe_load(infile)

    def _get_ansible_inventory(self):
        from lcitool.ansible_wrapper import AnsibleWrapper

        inventory_path = Path(util.get_config_dir(), "inventory")
        inventory_path_str = inventory_path.as_posix()
        if not inventory_path.exists():
            raise InventoryError(
                f"Missing Ansible inventory '{inventory_path}'"
            )

        log.debug(f"Running ansible-inventory on '{inventory_path_str}'")
        ansible_runner = AnsibleWrapper()
        ansible_runner.prepare_env(inventory=inventory_path,
                                   group_vars=self.target_facts)
        inventory = ansible_runner.get_inventory()

        return inventory

    def _load_facts_from(self, facts_dir):
        facts = {}
        for entry in sorted(facts_dir.iterdir()):
            if not entry.is_file() or entry.suffix != ".yml":
                continue

            log.debug(f"Loading facts from '{entry}'")
            facts.update(self._read_facts_from_file(entry))

        return facts

    def _load_target_facts(self):
        facts = {}
        group_vars_path = Path(resource_filename(__name__, "ansible/group_vars/"))
        group_vars_all_path = Path(group_vars_path, "all")

        # first load the shared facts from group_vars/all
        shared_facts = self._load_facts_from(group_vars_all_path)

        # then load the rest of the facts
        for entry in group_vars_path.iterdir():
            if not entry.is_dir() or entry.name == "all":
                continue

            tmp = self._load_facts_from(entry)

            # override shared facts with per-distro facts
            target = entry.name
            facts[target] = copy.deepcopy(shared_facts)
            facts[target].update(tmp)

        return facts

    def _load_host_facts(self):
        facts = {}
        groups = {}

        def _rec(inventory, group_name):
            for key, subinventory in inventory.items():
                if key == "hosts":
                    for host_name, host_facts in subinventory.items():
                        log.debug(f"Host '{host_name}' is in group '{group_name}'")

                        # Keep track of all the groups we've seen each host
                        # show up in so that we can perform some validation
                        # later
                        if host_name not in groups:
                            groups[host_name] = set()
                        groups[host_name].add(group_name)

                        # ansible-inventory only includes the full list of facts
                        # the first time a host shows up, no matter how deeply
                        # nested that happens to be, and all other times just uses
                        # an empty dictionary as a position marker
                        if host_name not in facts:
                            log.debug(f"Facts for host '{host_name}': {host_facts}")
                            facts[host_name] = host_facts

                # Recurse into the group's children to look for more hosts
                elif key == "children":
                    _rec(subinventory, group_name)
                else:
                    log.debug(f"Group '{key}' is a children of group '{group_name}'")
                    _rec(subinventory, key)

        ansible_inventory = self._get_ansible_inventory()
        _rec(ansible_inventory["all"], "all")

        targets = set(self.targets)
        for host_name, host_groups in groups.items():
            host_targets = host_groups.intersection(targets)

            # Each host should have shown up in exactly one of the groups
            # that are defined based on the target OS
            if len(host_targets) == 0:
                raise InventoryError(
                    f"Host '{host_name}' not found in any target OS group"
                )
            elif len(host_targets) > 1:
                raise InventoryError(
                    f"Host '{host_name}' found in multiple target OS groups: {host_targets}"
                )

        return facts

    def expand_hosts(self, pattern):
        try:
            return util.expand_pattern(pattern, self.hosts, "hosts")
        except Exception as ex:
            raise InventoryError(f"Failed to expand '{pattern}': {ex}")
