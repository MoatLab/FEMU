# image.py - manages downloaded vendor OS images
#
# Copyright (C) 2023 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os
import yaml

import lcitool.install.osinfo as osinfo

from collections import UserDict
from pathlib import Path
from tempfile import NamedTemporaryFile

from lcitool import util, LcitoolError

log = logging.getLogger(__name__)


class ImageError(LcitoolError):
    def __init__(self, message):
        super().__init__(message, "Image")


class MetadataLoadError(ImageError):
    """Thrown when metadata for an image could not be loaded"""


class MetadataValidationError(ImageError):
    """Thrown when image metadata validation fails"""


class NoImageError(ImageError):
    """Thrown when libosinfo doesn't return a link to a target OS cloud image"""


class Metadata(UserDict):
    @staticmethod
    def _validate(dict_):
        schema = set(["target", "image", "url", "arch", "format",
                      "libosinfo_id"])
        actual = set(dict_.keys())
        if actual != schema:
            raise ValueError(actual - schema)

    def load(self, file):
        # load image metadata
        with open(file, 'r') as f:
            try:
                m = yaml.safe_load(f)
            except Exception as ex:
                raise MetadataLoadError(ex)

            try:
                self._validate(m)
            except ValueError as e:
                invalid_keys = list(e.args)
                raise MetadataValidationError(
                    f"Metadata schema validation failed on '{f.name}', "
                    f"violating keys: {invalid_keys}"
                )
            self.update(m)
        return self

    def dump(self, file):
        try:
            self._validate(self)
        except ValueError as e:
            invalid_keys = list(e.args)
            raise MetadataValidationError(
                f"Metadata schema validation failed, "
                f"violating keys: {invalid_keys}"
            )
        with open(file, 'w') as fd:
            try:
                yaml.safe_dump(self.data, fd)
            except Exception as ex:
                name = file.name
                raise ImageError(
                    f"Failed to dump metadata for image '{name}': {ex}"
                )


class Images():
    @staticmethod
    def _get_cache_dir():
        cache_dir = Path(util.get_cache_dir(), "images")
        if not cache_dir.exists():
            cache_dir.mkdir()
        return cache_dir

    def __init__(self):
        self._cache_dir = self._get_cache_dir()
        self._osinfodb = osinfo.OSinfoDB()
        self._target_images = self._load(self._cache_dir)

    def get(self, target, facts, arch="x86_64", format_="qcow2"):

        # self.data is the underlying dict object
        if target in self._target_images:
            return self._target_images[target]

        osinfo_img = self._load_osinfo_image_data(self._osinfodb,
                                                  facts["os"]["libosinfo_id"],
                                                  arch,
                                                  format_)
        metadata = Metadata(target=target,
                            arch=arch,
                            format=format_,
                            libosinfo_id=facts["os"]["libosinfo_id"],
                            url=osinfo_img.url)

        self._target_images[target] = Image(metadata, self._cache_dir)
        return self._target_images[target]

    @staticmethod
    def _load(dir_):
        images = {}

        # load all image metadata files and store it in the ascending order,
        # i.e. from newest to oldest
        for entry in sorted(dir_.glob("*.metadata"),
                            reverse=True,
                            key=lambda x: x.stat().st_mtime):

            # check if image with the path exists, log warning and skip
            if not Path(dir_, entry.stem).exists():
                log.warning("Metadata found, but image is missing, skipping")
                continue

            # load image metadata
            metadata = Metadata().load(entry)

            # consider only the latest image/metadata of a given target, ignore
            # the old ones
            images.setdefault(metadata["target"], Image(metadata, dir_))

        return images

    @staticmethod
    def _load_osinfo_image_data(osinfo_db, libosinfo_id, arch, format_):
        def _filter_arch_format_cloud_init(osimg):
            if not osimg.has_cloud_init() or \
               osimg.arch != arch or \
               osimg.format != format_:
                return False

            if not osimg.variants:
                return True

            # some distros tailor cloud images for a certain platform
            # (e.g. Debian) and those were not created equal, so prefer the
            # following order of variants and if none is available then just
            # take whatever is provided.
            for v in ["nocloud", "generic", "genericcloud"]:
                if v in osimg.variants:
                    return True

            return False

        osinfo = osinfo_db.get_os_by_id(libosinfo_id)
        osimages = list(filter(_filter_arch_format_cloud_init, osinfo.images))

        if not osimages:
            raise NoImageError(f"No cloud image found for '{osinfo.name}'")

        # usually we'd only get a list consisting of a single image, unless
        # variant images were provided in which case these are going to be
        # 'nocloud', 'generic'; it should not matter (TM) which one we pick
        return osimages[0]


class Image:
    """
    Attributes:
        :ivar name: name of the image (None until the image is downloaded)
        :ivar path: path to the image (None until the image is downloaded)
        :ivar metadata: metadata for this image (as dict)
    """

    def __init__(self, metadata, download_dir):
        """
        Instantiates a base image handler.

        :param metadata: metadata for this disk image
        :param download_dir: base directory where the image should be
                             downloaded to
        """

        self._metadata = metadata
        self._download_dir = download_dir

    @property
    def name(self):
        if self.path:
            return self.path.name
        return None

    @property
    def path(self):
        val = self._metadata.get("image")
        if val:
            return Path(val)
        return None

    @property
    def metadata(self):
        return self._metadata

    def download(self):
        import requests
        from tqdm import tqdm

        url = self._metadata["url"]
        target = self._metadata["target"]
        suffix = self._metadata["format"]

        log.info(f"Downloading from {url}")
        with requests.get(url, stream=True) as r:
            total_size = int(r.headers.get("content-length", 0))
            with tqdm(ascii=" #",
                      total=total_size,
                      ncols=80,
                      unit="B",
                      unit_scale=True,
                      unit_divisor=1024,) as progress:

                with NamedTemporaryFile("wb",
                                        prefix=f"{target}_",
                                        suffix="." + suffix,
                                        dir=self._download_dir,
                                        delete=False) as fd:
                    chunk_size = 8 * (1 << 20)
                    for chunk in r.iter_content(chunk_size):
                        how_much = fd.write(chunk)
                        progress.update(how_much)
                    filepath = fd.name

        print()

        # We need to set 0644 permissions on the vendor image so that guestfs
        # tools can mount the backing chains utilizing with these vendor
        # images since owner:group permissions are never restored with
        # libvirt's dynamic ownership on any but the top image in the backing
        # chain.
        #
        # NOTE: we also couldn't have simply used umask when downloading the
        # vendor image, because the downloaded file is created using
        # NamedTemporaryFile which for security reasons has hardcoded
        # permissions 0600
        os.chmod(filepath, 0o644)

        # update missing metadata and dump it
        self._metadata["image"] = filepath
        self._metadata.dump(fd.name + ".metadata")
        return fd.name
