=============================================
Container for running flake8 code style check
=============================================

This container provides a simple way to invoke ``flake8`` to validate code
style across a Rust codebase. It should be integrated into CI by setting the
following flag in ``ci/manifest.yml``

::

   gitlab:
     jobs:
       flake8: true

or adding the following snippet to ``.gitlab-ci.yml``

::

   flake8:
     stage: sanity_checks
     image: registry.gitlab.com/libvirt/libvirt-ci/flake8:latest
     needs: []
     script:
       - /flake8
     artifacts:
       paths:
         - flake8.txt
       expire_in: 1 week
       when: on_failure
