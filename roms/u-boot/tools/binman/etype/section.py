# SPDX-License-Identifier:      GPL-2.0+
# Copyright (c) 2018 Google, Inc
# Written by Simon Glass <sjg@chromium.org>

"""Entry-type module for sections (groups of entries)

Sections are entries which can contain other entries. This allows hierarchical
images to be created.
"""

from collections import OrderedDict
import re
import sys

from binman.entry import Entry
from dtoc import fdt_util
from patman import tools
from patman import tout
from patman.tools import ToHexSize


class Entry_section(Entry):
    """Entry that contains other entries

    Properties / Entry arguments: (see binman README for more information):
        pad-byte: Pad byte to use when padding
        sort-by-offset: True if entries should be sorted by offset, False if
        they must be in-order in the device tree description

        end-at-4gb: Used to build an x86 ROM which ends at 4GB (2^32)

        skip-at-start: Number of bytes before the first entry starts. These
            effectively adjust the starting offset of entries. For example,
            if this is 16, then the first entry would start at 16. An entry
            with offset = 20 would in fact be written at offset 4 in the image
            file, since the first 16 bytes are skipped when writing.
        name-prefix: Adds a prefix to the name of every entry in the section
            when writing out the map
        align_default: Default alignment for this section, if no alignment is
            given in the entry

    Properties:
        allow_missing: True if this section permits external blobs to be
            missing their contents. The second will produce an image but of
            course it will not work.

    Since a section is also an entry, it inherits all the properies of entries
    too.

    A section is an entry which can contain other entries, thus allowing
    hierarchical images to be created. See 'Sections and hierarchical images'
    in the binman README for more information.
    """
    def __init__(self, section, etype, node, test=False):
        if not test:
            super().__init__(section, etype, node)
        self._entries = OrderedDict()
        self._pad_byte = 0
        self._sort = False
        self._skip_at_start = None
        self._end_4gb = False

    def ReadNode(self):
        """Read properties from the section node"""
        super().ReadNode()
        self._pad_byte = fdt_util.GetInt(self._node, 'pad-byte', 0)
        self._sort = fdt_util.GetBool(self._node, 'sort-by-offset')
        self._end_4gb = fdt_util.GetBool(self._node, 'end-at-4gb')
        self._skip_at_start = fdt_util.GetInt(self._node, 'skip-at-start')
        if self._end_4gb:
            if not self.size:
                self.Raise("Section size must be provided when using end-at-4gb")
            if self._skip_at_start is not None:
                self.Raise("Provide either 'end-at-4gb' or 'skip-at-start'")
            else:
                self._skip_at_start = 0x100000000 - self.size
        else:
            if self._skip_at_start is None:
                self._skip_at_start = 0
        self._name_prefix = fdt_util.GetString(self._node, 'name-prefix')
        self.align_default = fdt_util.GetInt(self._node, 'align-default', 0)
        filename = fdt_util.GetString(self._node, 'filename')
        if filename:
            self._filename = filename

        self._ReadEntries()

    def _ReadEntries(self):
        for node in self._node.subnodes:
            if node.name.startswith('hash') or node.name.startswith('signature'):
                continue
            entry = Entry.Create(self, node,
                                 expanded=self.GetImage().use_expanded)
            entry.ReadNode()
            entry.SetPrefix(self._name_prefix)
            self._entries[node.name] = entry

    def _Raise(self, msg):
        """Raises an error for this section

        Args:
            msg: Error message to use in the raise string
        Raises:
            ValueError()
        """
        raise ValueError("Section '%s': %s" % (self._node.path, msg))

    def GetFdts(self):
        fdts = {}
        for entry in self._entries.values():
            fdts.update(entry.GetFdts())
        return fdts

    def ProcessFdt(self, fdt):
        """Allow entries to adjust the device tree

        Some entries need to adjust the device tree for their purposes. This
        may involve adding or deleting properties.
        """
        todo = self._entries.values()
        for passnum in range(3):
            next_todo = []
            for entry in todo:
                if not entry.ProcessFdt(fdt):
                    next_todo.append(entry)
            todo = next_todo
            if not todo:
                break
        if todo:
            self.Raise('Internal error: Could not complete processing of Fdt: remaining %s' %
                       todo)
        return True

    def ExpandEntries(self):
        super().ExpandEntries()
        for entry in self._entries.values():
            entry.ExpandEntries()

    def AddMissingProperties(self, have_image_pos):
        """Add new properties to the device tree as needed for this entry"""
        super().AddMissingProperties(have_image_pos)
        if self.compress != 'none':
            have_image_pos = False
        for entry in self._entries.values():
            entry.AddMissingProperties(have_image_pos)

    def ObtainContents(self):
        return self.GetEntryContents()

    def GetPaddedDataForEntry(self, entry, entry_data):
        """Get the data for an entry including any padding

        Gets the entry data and uses the section pad-byte value to add padding
        before and after as defined by the pad-before and pad-after properties.
        This does not consider alignment.

        Args:
            entry: Entry to check

        Returns:
            Contents of the entry along with any pad bytes before and
            after it (bytes)
        """
        pad_byte = (entry._pad_byte if isinstance(entry, Entry_section)
                    else self._pad_byte)

        data = b''
        # Handle padding before the entry
        if entry.pad_before:
            data += tools.GetBytes(self._pad_byte, entry.pad_before)

        # Add in the actual entry data
        data += entry_data

        # Handle padding after the entry
        if entry.pad_after:
            data += tools.GetBytes(self._pad_byte, entry.pad_after)

        if entry.size:
            data += tools.GetBytes(pad_byte, entry.size - len(data))

        self.Detail('GetPaddedDataForEntry: size %s' % ToHexSize(self.data))

        return data

    def _BuildSectionData(self, required):
        """Build the contents of a section

        This places all entries at the right place, dealing with padding before
        and after entries. It does not do padding for the section itself (the
        pad-before and pad-after properties in the section items) since that is
        handled by the parent section.

        Args:
            required: True if the data must be present, False if it is OK to
                return None

        Returns:
            Contents of the section (bytes)
        """
        section_data = b''

        for entry in self._entries.values():
            entry_data = entry.GetData(required)
            if not required and entry_data is None:
                return None
            data = self.GetPaddedDataForEntry(entry, entry_data)
            # Handle empty space before the entry
            pad = (entry.offset or 0) - self._skip_at_start - len(section_data)
            if pad > 0:
                section_data += tools.GetBytes(self._pad_byte, pad)

            # Add in the actual entry data
            section_data += data

        self.Detail('GetData: %d entries, total size %#x' %
                    (len(self._entries), len(section_data)))
        return self.CompressData(section_data)

    def GetPaddedData(self, data=None):
        """Get the data for a section including any padding

        Gets the section data and uses the parent section's pad-byte value to
        add padding before and after as defined by the pad-before and pad-after
        properties. If this is a top-level section (i.e. an image), this is the
        same as GetData(), since padding is not supported.

        This does not consider alignment.

        Returns:
            Contents of the section along with any pad bytes before and
            after it (bytes)
        """
        section = self.section or self
        if data is None:
            data = self.GetData()
        return section.GetPaddedDataForEntry(self, data)

    def GetData(self, required=True):
        """Get the contents of an entry

        This builds the contents of the section, stores this as the contents of
        the section and returns it

        Args:
            required: True if the data must be present, False if it is OK to
                return None

        Returns:
            bytes content of the section, made up for all all of its subentries.
            This excludes any padding. If the section is compressed, the
            compressed data is returned
        """
        data = self._BuildSectionData(required)
        if data is None:
            return None
        self.SetContents(data)
        return data

    def GetOffsets(self):
        """Handle entries that want to set the offset/size of other entries

        This calls each entry's GetOffsets() method. If it returns a list
        of entries to update, it updates them.
        """
        self.GetEntryOffsets()
        return {}

    def ResetForPack(self):
        """Reset offset/size fields so that packing can be done again"""
        super().ResetForPack()
        for entry in self._entries.values():
            entry.ResetForPack()

    def Pack(self, offset):
        """Pack all entries into the section"""
        self._PackEntries()
        if self._sort:
            self._SortEntries()
        self._ExpandEntries()

        data = self._BuildSectionData(True)
        self.SetContents(data)

        self.CheckSize()

        offset = super().Pack(offset)
        self.CheckEntries()
        return offset

    def _PackEntries(self):
        """Pack all entries into the section"""
        offset = self._skip_at_start
        for entry in self._entries.values():
            offset = entry.Pack(offset)
        return offset

    def _ExpandEntries(self):
        """Expand any entries that are permitted to"""
        exp_entry = None
        for entry in self._entries.values():
            if exp_entry:
                exp_entry.ExpandToLimit(entry.offset)
                exp_entry = None
            if entry.expand_size:
                exp_entry = entry
        if exp_entry:
            exp_entry.ExpandToLimit(self.size)

    def _SortEntries(self):
        """Sort entries by offset"""
        entries = sorted(self._entries.values(), key=lambda entry: entry.offset)
        self._entries.clear()
        for entry in entries:
            self._entries[entry._node.name] = entry

    def CheckEntries(self):
        """Check that entries do not overlap or extend outside the section"""
        max_size = self.size if self.uncomp_size is None else self.uncomp_size

        offset = 0
        prev_name = 'None'
        for entry in self._entries.values():
            entry.CheckEntries()
            if (entry.offset < self._skip_at_start or
                    entry.offset + entry.size > self._skip_at_start +
                    max_size):
                entry.Raise('Offset %#x (%d) size %#x (%d) is outside the '
                            "section '%s' starting at %#x (%d) "
                            'of size %#x (%d)' %
                            (entry.offset, entry.offset, entry.size, entry.size,
                             self._node.path, self._skip_at_start,
                             self._skip_at_start, max_size, max_size))
            if entry.offset < offset and entry.size:
                entry.Raise("Offset %#x (%d) overlaps with previous entry '%s' "
                            "ending at %#x (%d)" %
                            (entry.offset, entry.offset, prev_name, offset, offset))
            offset = entry.offset + entry.size
            prev_name = entry.GetPath()

    def WriteSymbols(self, section):
        """Write symbol values into binary files for access at run time"""
        for entry in self._entries.values():
            entry.WriteSymbols(self)

    def SetCalculatedProperties(self):
        super().SetCalculatedProperties()
        for entry in self._entries.values():
            entry.SetCalculatedProperties()

    def SetImagePos(self, image_pos):
        super().SetImagePos(image_pos)
        if self.compress == 'none':
            for entry in self._entries.values():
                entry.SetImagePos(image_pos + self.offset)

    def ProcessContents(self):
        sizes_ok_base = super(Entry_section, self).ProcessContents()
        sizes_ok = True
        for entry in self._entries.values():
            if not entry.ProcessContents():
                sizes_ok = False
        return sizes_ok and sizes_ok_base

    def WriteMap(self, fd, indent):
        """Write a map of the section to a .map file

        Args:
            fd: File to write the map to
        """
        Entry.WriteMapLine(fd, indent, self.name, self.offset or 0,
                           self.size, self.image_pos)
        for entry in self._entries.values():
            entry.WriteMap(fd, indent + 1)

    def GetEntries(self):
        return self._entries

    def GetContentsByPhandle(self, phandle, source_entry, required):
        """Get the data contents of an entry specified by a phandle

        This uses a phandle to look up a node and and find the entry
        associated with it. Then it returns the contents of that entry.

        The node must be a direct subnode of this section.

        Args:
            phandle: Phandle to look up (integer)
            source_entry: Entry containing that phandle (used for error
                reporting)
            required: True if the data must be present, False if it is OK to
                return None

        Returns:
            data from associated entry (as a string), or None if not found
        """
        node = self._node.GetFdt().LookupPhandle(phandle)
        if not node:
            source_entry.Raise("Cannot find node for phandle %d" % phandle)
        for entry in self._entries.values():
            if entry._node == node:
                return entry.GetData(required)
        source_entry.Raise("Cannot find entry for node '%s'" % node.name)

    def LookupSymbol(self, sym_name, optional, msg, base_addr, entries=None):
        """Look up a symbol in an ELF file

        Looks up a symbol in an ELF file. Only entry types which come from an
        ELF image can be used by this function.

        At present the only entry properties supported are:
            offset
            image_pos - 'base_addr' is added if this is not an end-at-4gb image
            size

        Args:
            sym_name: Symbol name in the ELF file to look up in the format
                _binman_<entry>_prop_<property> where <entry> is the name of
                the entry and <property> is the property to find (e.g.
                _binman_u_boot_prop_offset). As a special case, you can append
                _any to <entry> to have it search for any matching entry. E.g.
                _binman_u_boot_any_prop_offset will match entries called u-boot,
                u-boot-img and u-boot-nodtb)
            optional: True if the symbol is optional. If False this function
                will raise if the symbol is not found
            msg: Message to display if an error occurs
            base_addr: Base address of image. This is added to the returned
                image_pos in most cases so that the returned position indicates
                where the targetted entry/binary has actually been loaded. But
                if end-at-4gb is used, this is not done, since the binary is
                already assumed to be linked to the ROM position and using
                execute-in-place (XIP).

        Returns:
            Value that should be assigned to that symbol, or None if it was
                optional and not found

        Raises:
            ValueError if the symbol is invalid or not found, or references a
                property which is not supported
        """
        m = re.match(r'^_binman_(\w+)_prop_(\w+)$', sym_name)
        if not m:
            raise ValueError("%s: Symbol '%s' has invalid format" %
                             (msg, sym_name))
        entry_name, prop_name = m.groups()
        entry_name = entry_name.replace('_', '-')
        if not entries:
            entries = self._entries
        entry = entries.get(entry_name)
        if not entry:
            if entry_name.endswith('-any'):
                root = entry_name[:-4]
                for name in entries:
                    if name.startswith(root):
                        rest = name[len(root):]
                        if rest in ['', '-img', '-nodtb']:
                            entry = entries[name]
        if not entry:
            err = ("%s: Entry '%s' not found in list (%s)" %
                   (msg, entry_name, ','.join(entries.keys())))
            if optional:
                print('Warning: %s' % err, file=sys.stderr)
                return None
            raise ValueError(err)
        if prop_name == 'offset':
            return entry.offset
        elif prop_name == 'image_pos':
            value = entry.image_pos
            if not self.GetImage()._end_4gb:
                value += base_addr
            return value
        if prop_name == 'size':
            return entry.size
        else:
            raise ValueError("%s: No such property '%s'" % (msg, prop_name))

    def GetRootSkipAtStart(self):
        """Get the skip-at-start value for the top-level section

        This is used to find out the starting offset for root section that
        contains this section. If this is a top-level section then it returns
        the skip-at-start offset for this section.

        This is used to get the absolute position of section within the image.

        Returns:
            Integer skip-at-start value for the root section containing this
                section
        """
        if self.section:
            return self.section.GetRootSkipAtStart()
        return self._skip_at_start

    def GetStartOffset(self):
        """Get the start offset for this section

        Returns:
            The first available offset in this section (typically 0)
        """
        return self._skip_at_start

    def GetImageSize(self):
        """Get the size of the image containing this section

        Returns:
            Image size as an integer number of bytes, which may be None if the
                image size is dynamic and its sections have not yet been packed
        """
        return self.GetImage().size

    def FindEntryType(self, etype):
        """Find an entry type in the section

        Args:
            etype: Entry type to find
        Returns:
            entry matching that type, or None if not found
        """
        for entry in self._entries.values():
            if entry.etype == etype:
                return entry
        return None

    def GetEntryContents(self):
        """Call ObtainContents() for each entry in the section
        """
        todo = self._entries.values()
        for passnum in range(3):
            next_todo = []
            for entry in todo:
                if not entry.ObtainContents():
                    next_todo.append(entry)
            todo = next_todo
            if not todo:
                break
        if todo:
            self.Raise('Internal error: Could not complete processing of contents: remaining %s' %
                       todo)
        return True

    def _SetEntryOffsetSize(self, name, offset, size):
        """Set the offset and size of an entry

        Args:
            name: Entry name to update
            offset: New offset, or None to leave alone
            size: New size, or None to leave alone
        """
        entry = self._entries.get(name)
        if not entry:
            self._Raise("Unable to set offset/size for unknown entry '%s'" %
                        name)
        entry.SetOffsetSize(self._skip_at_start + offset if offset is not None
                            else None, size)

    def GetEntryOffsets(self):
        """Handle entries that want to set the offset/size of other entries

        This calls each entry's GetOffsets() method. If it returns a list
        of entries to update, it updates them.
        """
        for entry in self._entries.values():
            offset_dict = entry.GetOffsets()
            for name, info in offset_dict.items():
                self._SetEntryOffsetSize(name, *info)

    def CheckSize(self):
        contents_size = len(self.data)

        size = self.size
        if not size:
            data = self.GetPaddedData(self.data)
            size = len(data)
            size = tools.Align(size, self.align_size)

        if self.size and contents_size > self.size:
            self._Raise("contents size %#x (%d) exceeds section size %#x (%d)" %
                        (contents_size, contents_size, self.size, self.size))
        if not self.size:
            self.size = size
        if self.size != tools.Align(self.size, self.align_size):
            self._Raise("Size %#x (%d) does not match align-size %#x (%d)" %
                        (self.size, self.size, self.align_size,
                         self.align_size))
        return size

    def ListEntries(self, entries, indent):
        """List the files in the section"""
        Entry.AddEntryInfo(entries, indent, self.name, 'section', self.size,
                           self.image_pos, None, self.offset, self)
        for entry in self._entries.values():
            entry.ListEntries(entries, indent + 1)

    def LoadData(self, decomp=True):
        for entry in self._entries.values():
            entry.LoadData(decomp)
        self.Detail('Loaded data')

    def GetImage(self):
        """Get the image containing this section

        Note that a top-level section is actually an Image, so this function may
        return self.

        Returns:
            Image object containing this section
        """
        if not self.section:
            return self
        return self.section.GetImage()

    def GetSort(self):
        """Check if the entries in this section will be sorted

        Returns:
            True if to be sorted, False if entries will be left in the order
                they appear in the device tree
        """
        return self._sort

    def ReadData(self, decomp=True):
        tout.Info("ReadData path='%s'" % self.GetPath())
        parent_data = self.section.ReadData(True)
        offset = self.offset - self.section._skip_at_start
        data = parent_data[offset:offset + self.size]
        tout.Info(
            '%s: Reading data from offset %#x-%#x (real %#x), size %#x, got %#x' %
                  (self.GetPath(), self.offset, self.offset + self.size, offset,
                   self.size, len(data)))
        return data

    def ReadChildData(self, child, decomp=True):
        tout.Debug("ReadChildData for child '%s'" % child.GetPath())
        parent_data = self.ReadData(True)
        offset = child.offset - self._skip_at_start
        tout.Debug("Extract for child '%s': offset %#x, skip_at_start %#x, result %#x" %
                   (child.GetPath(), child.offset, self._skip_at_start, offset))
        data = parent_data[offset:offset + child.size]
        if decomp:
            indata = data
            data = tools.Decompress(indata, child.compress)
            if child.uncomp_size:
                tout.Info("%s: Decompressing data size %#x with algo '%s' to data size %#x" %
                            (child.GetPath(), len(indata), child.compress,
                            len(data)))
        return data

    def WriteChildData(self, child):
        return True

    def SetAllowMissing(self, allow_missing):
        """Set whether a section allows missing external blobs

        Args:
            allow_missing: True if allowed, False if not allowed
        """
        self.allow_missing = allow_missing
        for entry in self._entries.values():
            entry.SetAllowMissing(allow_missing)

    def CheckMissing(self, missing_list):
        """Check if any entries in this section have missing external blobs

        If there are missing blobs, the entries are added to the list

        Args:
            missing_list: List of Entry objects to be added to
        """
        for entry in self._entries.values():
            entry.CheckMissing(missing_list)

    def _CollectEntries(self, entries, entries_by_name, add_entry):
        """Collect all the entries in an section

        This builds up a dict of entries in this section and all subsections.
        Entries are indexed by path and by name.

        Since all paths are unique, entries will not have any conflicts. However
        entries_by_name make have conflicts if two entries have the same name
        (e.g. with different parent sections). In this case, an entry at a
        higher level in the hierarchy will win over a lower-level entry.

        Args:
            entries: dict to put entries:
                key: entry path
                value: Entry object
            entries_by_name: dict to put entries
                key: entry name
                value: Entry object
            add_entry: Entry to add
        """
        entries[add_entry.GetPath()] = add_entry
        to_add = add_entry.GetEntries()
        if to_add:
            for entry in to_add.values():
                entries[entry.GetPath()] = entry
            for entry in to_add.values():
                self._CollectEntries(entries, entries_by_name, entry)
        entries_by_name[add_entry.name] = add_entry

    def MissingArgs(self, entry, missing):
        """Report a missing argument, if enabled

        For entries which require arguments, this reports an error if some are
        missing. If missing entries are being ignored (e.g. because we read the
        entry from an image rather than creating it), this function does
        nothing.

        Args:
            missing: List of missing properties / entry args, each a string
        """
        if not self._ignore_missing:
            entry.Raise('Missing required properties/entry args: %s' %
                       (', '.join(missing)))
