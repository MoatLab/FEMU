# libvirt_wrapper.py - module abstracting the libvirt library
#
# Copyright (C) 2022 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import abc
import libvirt
import logging
import textwrap

import xml.etree.ElementTree as ET

from pathlib import Path

from lcitool import LcitoolError

log = logging.getLogger(__name__)

LCITOOL_XMLNS = "http://libvirt.org/schemas/lcitool/1.0"


class LibvirtWrapperError(LcitoolError):
    """
    Global exception type for this module.

    Contains a libvirt error message. On the application level, this is the
    exception type you should be catching.
    """

    def __init__(self, message):
        super().__init__(message, "LibvirtWrapper")


class LibvirtWrapper():
    def __init__(self):
        def nop_error_handler(_T, iterable):
            return None

        # Disable libvirt's default console error logging
        libvirt.registerErrorHandler(nop_error_handler, None)
        self._conn = libvirt.open()

    @property
    def hosts(self):
        """Return all lcitool hosts."""

        hosts = {}
        try:
            doms = self._conn.listAllDomains()
        except libvirt.libvirtError as e:
            raise LibvirtWrapperError("Failed to load libvirt domains: " + e)

        for dom in doms:
            try:
                domain_metadata_flags = libvirt.VIR_DOMAIN_AFFECT_CONFIG
                if not dom.isPersistent():
                    domain_metadata_flags = libvirt.VIR_DOMAIN_AFFECT_LIVE
                xml = dom.metadata(libvirt.VIR_DOMAIN_METADATA_ELEMENT,
                                   LCITOOL_XMLNS,
                                   domain_metadata_flags)
            except libvirt.libvirtError as e:
                if e.get_error_code() == libvirt.VIR_ERR_NO_DOMAIN_METADATA:
                    # skip hosts which don't have lcitool's metadata
                    continue

                raise LibvirtWrapperError(
                    f"Failed to query metadata for '{dom.name()}': " + str(e)
                )

            xmltree = ET.fromstring(xml)
            target = xmltree.find("target")
            if xmltree.tag != "host" or target is None or target.text is None:
                continue

            hosts[dom.name()] = target.text

        return hosts

    def set_target(self, host, target):
        """Inject target OS to host's XML metadata."""

        xml = textwrap.dedent(
            f"""
            <host>
              <target>{target}</target>
            </host>
            """)

        try:
            dom = self._conn.lookupByName(host)
            dom.setMetadata(libvirt.VIR_DOMAIN_METADATA_ELEMENT,
                            xml, "lcitool", LCITOOL_XMLNS,
                            flags=(libvirt.VIR_DOMAIN_AFFECT_CONFIG |
                                   libvirt.VIR_DOMAIN_AFFECT_LIVE))
        except libvirt.libvirtError as e:
            raise LibvirtWrapperError(
                f"Failed to set metadata for '{host}': " + str(e)
            )

    def pool_by_name(self, name):
        try:
            poolobj = self._conn.storagePoolLookupByName(name)
            return LibvirtStoragePoolObject(self._conn, poolobj)
        except libvirt.libvirtError as e:
            raise LibvirtWrapperError(
                f"Failed to retrieve storage pool '{name}' info: " + str(e)
            )


class LibvirtAbstractObject(abc.ABC):
    """
    Libvirt's vir<Any> obj wrapper base class.

    The wrapper object defines convenience methods and attribute shortcuts
    extracting data from libvirt's XML descriptions. To use the wrapped object
    directly, the libvirt object is available in the 'raw' attribute.

    Attributes:
        :ivar raw: Raw libvirt vir<Any> object

    """

    def __init__(self, conn, obj):
        self._conn = conn
        self.raw = obj

    def _get_xml_tree(self):
        return ET.fromstring(self.raw.XMLDesc())

    def _get_xml_node(self, node_name, root=None):
        if root is None:
            root = self._get_xml_tree()

        return root.find(node_name)


class LibvirtStoragePoolObject(LibvirtAbstractObject):

    def __init__(self, conn, obj):
        super().__init__(conn, obj)
        self.name = obj.name()
        self._path = None
        self.raw.refresh()

    @property
    def path(self):
        if self._path is None:
            path_node = self._get_xml_node("target/path")
            self._path = path_node.text
        return Path(self._path)

    @staticmethod
    def _lookup_volume_by_path(conn, path):
        try:
            return conn.storageVolLookupByPath(path)
        except libvirt.libvirtError:
            return None

    def _volume_by_path(self, path):
        volobj = self._lookup_volume_by_path(self._conn, path)
        if volobj:
            return LibvirtStorageVolObject(self, volobj)

    @staticmethod
    def _create_transient_pool(conn, name, target):
        """Creates a transient pool of type 'dir'"""

        pool_xml = textwrap.dedent(
            f"""
            <pool type='dir'>
              <name>{name}</name>
              <target>
                <path>{target}</path>
              </target>
            </pool>
            """)

        conn.storagePoolCreateXML(pool_xml)
        return conn.storagePoolLookupByName(name)

    def _create_from_xml(self, name, xmlstr):
        self.raw.createXML(xmlstr)
        return LibvirtStorageVolObject(self,
                                       self.raw.storageVolLookupByName(name))

    def create_volume(self, name, capacity, allocation=None, _format="qcow2",
                      units='bytes', owner=None, group=None, mode=None,
                      backing_store=None):

        import re
        unit_pattern = '^(bytes|B|[K,M,G,T,P,E](iB|B)?)$'

        if not re.match(unit_pattern, units):
            raise ValueError(
                f"Invalid value '{units}' passed to 'create_volume().units'"
            )

        # define a base XML template to be updated depending on other params
        volume_xml = textwrap.dedent(
            f"""
            <volume>
              <name>{name}</name>
              <capacity unit='{units}'>{capacity}</capacity>
            </volume>
            """)

        root_el = ET.fromstring(volume_xml)

        if allocation:
            allocation_el = ET.SubElement(root_el, "allocation")
            allocation_el.text = allocation

        if _format:
            target_el = ET.SubElement(root_el, "target")
            ET.SubElement(target_el, "format", {"type": _format})

        if any([owner, group, mode]):
            target_el = ET.SubElement(root_el, "target")
            perms_el = ET.SubElement(target_el, "permissions")
            for perm_var, perm in [(owner, "owner"),
                                   (group, "group"),
                                   (mode, "mode")]:
                if perm_var:
                    node_el = ET.SubElement(perms_el, perm)
                    node_el.text = perm_var

        if backing_store:
            backing_store_path_str = backing_store.as_posix()
            backingStore_el = ET.SubElement(root_el, "backingStore")
            path_el = ET.SubElement(backingStore_el, "path")
            format_el = ET.SubElement(backingStore_el, "format")
            path_el.text = backing_store_path_str

            volobj = self._volume_by_path(backing_store_path_str)
            if volobj:
                format_ = volobj.format
            else:
                import uuid

                # We could not locate the backing store in any storage pool.
                # In order to fill in the backingStore volume data correctly we
                # need to create a transient pool of type dir which contains
                # the backingStore file storage volume to let libvirt fetch the
                # information for us. We'll destroy the pool afterwards.

                pool_dir = backing_store.parent.as_posix()
                pool_name = "lcitool_" + str(uuid.uuid1())
                poolobj = self._create_transient_pool(self._conn, pool_name,
                                                      pool_dir)
                volobj = self._volume_by_path(backing_store_path_str)
                format_ = volobj.format
                poolobj.destroy()

            format_el.attrib["type"] = format_

        volume_xml = ET.tostring(root_el, encoding="UTF-8", method="xml")
        return self._create_from_xml(name, volume_xml.decode("UTF-8"))


class LibvirtStorageVolObject(LibvirtAbstractObject):

    def __init__(self, pool, obj):
        super().__init__(pool._conn, obj)
        self.pool = pool
        self.name = obj.name()
        self.path = obj.path()
        self._format = None

    @property
    def format(self):
        if self._format is None:
            format_node = self._get_xml_node("target/format")
            self._format = format_node.attrib["type"]
        return self._format
