===================================================
Container for running clang-format code style check
===================================================

This container provides a simple way to invoke ``clang-format`` to validate
code style across a C codebase. It should be integrated into a CI by adding
the following flag in ``ci/manifest.yml``

::

   gitlab:
     jobs:
       clang-format: true

or adding the following snippet to ``.gitlab-ci.yml``

::

   clang-format:
     stage: sanity_checks
     image: registry.gitlab.com/libvirt/libvirt-ci/clang-format:latest
     needs: []
     script:
       - /clang-format
     artifacts:
       paths:
         - clang-format.patch
       expire_in: 1 week
       when: on_failure
