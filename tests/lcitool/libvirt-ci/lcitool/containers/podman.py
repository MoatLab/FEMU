# podman.py - module implementing podman container runtime wrapper logic
#
# Copyright (c) 2023 Abdulwasiu Apalowo.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import json
import logging

from .containers import Container, ContainerError

log = logging.getLogger()


class PodmanBuildError(ContainerError):
    """
    Thrown whenever error occurs during
    podman build operation.
    """
    pass


class PodmanRunError(ContainerError):
    """
    Thrown whenever error occurs during
    podman run operation.
    """
    pass


class Podman(Container):
    """Podman container class"""

    def __init__(self):
        super().__init__()
        self._run_exception = PodmanRunError
        self._build_exception = PodmanBuildError

    def _extra_args(self, user):
        """
        Get Podman specific host namespace mapping
        :param user: numerical ID (int) or username (str) of the user.

        :returns: a list of id mapping
        """

        # Podman cannot reuse host namespace when running non-root
        # containers.  Until support for --keep-uid is added we can
        # just create another mapping that will do that for us.
        # Beware, that in {uid,gid}map=container_id:host_id:range, the
        # host_id does actually refer to the uid in the first mapping
        # where 0 (root) is mapped to the current user and rest is
        # offset.
        #
        # In order to set up this mapping, we need to keep all the
        # user IDs to prevent possible errors as some images might
        # expect UIDs up to 90000 (looking at you fedora), so we don't
        # want the overflowuid to be used for them.  For mapping all
        # the other users properly, some math needs to be done.
        # Don't worry, it's just addition and subtraction.
        #
        # 65536 ought to be enough (tm), but for really rare cases the
        # maximums might need to be higher, but that only happens when
        # your /etc/sub{u,g}id allow users to have more IDs.  Unless
        # --keep-uid is supported, let's do this in a way that should
        # work for everyone.

        podman_args_ = []

        _, _, uid, gid, _, _, _ = self._passwd(user)
        if uid == 0:
            return podman_args_

        max_uid = int(open("/etc/subuid").read().split(":")[-1])
        max_gid = int(open("/etc/subgid").read().split(":")[-1])

        if max_uid is None:
            max_uid = 65536
        if max_gid is None:
            max_gid = 65536

        uid_other = uid + 1
        gid_other = gid + 1
        uid_other_range = max_uid - uid
        gid_other_range = max_gid - gid

        podman_args_.extend([
            "--uidmap", f"0:1:{uid}",
            "--uidmap", f"{uid}:0:1",
            "--uidmap", f"{uid_other}:{uid_other}:{uid_other_range}",
            "--gidmap", f"0:1:{gid}",
            "--gidmap", f"{gid}:0:1",
            "--gidmap", f"{gid_other}:{gid_other}:{gid_other_range}"
        ])
        return podman_args_

    def _build_args(self, user, tempdir, env=None, datadir=None, script=None):
        """
        Options for Podman engine.

        :returns: a list containing id mapping. e.g
        [
            '--user', '10:10',
            '--volume', '/home/path:/container/path',
            '--uidmap', '0:1:1000',
            '--gidmap', '0:1:1000'
        ]
        """

        args_ = super()._build_args(
            user, tempdir, env=env, datadir=datadir, script=script
        )
        args_podman = args_ + self._extra_args(user)
        log.debug(f"Options for podman engine: {args_podman}")

        return args_podman

    def _images(self):
        """
        Get all container images.

        :returns: a list of image details
        """

        img = super()._images()
        images = json.loads(img)

        log.debug(f"Deserialized {self.engine} images\n%s", images)
        return images

    def image_exists(self, image_ref):
        """
        Check if image exists in podman.
        :param image_ref: name/id/registry-path of image to check (str).

        :returns: boolean
        """

        image_name, _, image_tag = image_ref.partition(':')
        image_repository, _, image_name = image_name.rpartition('/')
        if not image_tag:
            image_tag = "latest"

        for img in self._images():
            id = img.get("Id")
            img_repository = img.get("Names")

            image_reference = image_name + ":" + image_tag
            if image_repository:
                image_reference = image_repository + '/' + image_reference
                repository_names = img_repository
            else:
                # parse `img_repository` just to get "<image_name>:<image_tag>"
                repository_names = list(map(lambda x: x.split('/')[-1], img_repository))

            if id.startswith(image_ref) or (image_reference in repository_names):
                return True

        return False
