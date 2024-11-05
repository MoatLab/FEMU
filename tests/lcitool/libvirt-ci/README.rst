==========
libvirt CI
==========

This repository provides tools and configuration for managing the CI needs of
libvirt and related projects. The current primary focus is on integration with
GitLab as the primary CI platform. For most platforms, containers are used for
the primary build environment, however, the tools are also able to build VM
images. This allows for use of custom runners for scenarios not served by the
GitLab container based shared runners.

The ``lcitool/`` directory provides the tooling and configuration for creating
VM images and container templates (which can be used to create images) to get an
isolated build and test environment for supported projects.

The ``containers/`` directory provides a handful of helper images for performing
common tasks that are not project specific, such as integrating with Cirrus CI
for non-Linux builds, running code style checks and validating commit signoff.

The ``docs/`` directory contains RST formatted documentation split logically
by topics into individual documents.

License
=======

The contents of this repository are distributed under the terms of
the GNU General Public License, version 2 (or later). See the
``COPYING`` file for full license terms and conditions.
