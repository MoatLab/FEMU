# osinfo.py - wraps OSInfoDB functionality
#
# Copyright (C) 2023 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import abc

from gi.repository import Libosinfo


class OSinfoAbstractObject(abc.ABC):
    def __init__(self, obj):
        self.raw = obj


class OSinfoDB():
    def __init__(self):
        loader = Libosinfo.Loader()
        loader.process_default_path()
        self._db = loader.get_db()

    def get_os_by_id(self, libosinfo_id):
        osinfo = self._db.get_os(libosinfo_id)
        return OSinfoObject(osinfo)

    def get_os_by_short_id(self, short_id):
        _filter = Libosinfo.Filter()
        _filter.add_constraint(Libosinfo.PRODUCT_PROP_SHORT_ID, short_id)

        oslist = self._db.get_os_list()
        filtered = Libosinfo.List.new_filtered(oslist, _filter).get_elements()
        return OSinfoObject(filtered[0])


class OSinfoImageObject(OSinfoAbstractObject):
    def __init__(self, obj):
        super().__init__(obj)
        self.name = self.url.split("/")[-1]
        self.variants = [v.get_id() for v in obj.get_os_variants().get_elements()]

    @property
    def arch(self):
        return self.raw.get_architecture()

    @property
    def format(self):
        return self.raw.get_format()

    @property
    def url(self):
        return self.raw.get_url()

    def has_cloud_init(self):
        return self.raw.get_cloud_init()


class OSinfoObject(OSinfoAbstractObject):
    def __init__(self, obj):
        super().__init__(obj)
        self._images = None

    @property
    def name(self):
        self.raw.get_name()

    @property
    def images(self):
        if not self._images:
            image_list = self.raw.get_image_list()
            self._images = [
                OSinfoImageObject(libosinfo_image)
                for libosinfo_image in image_list.get_elements()
            ]
        return self._images
