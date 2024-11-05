=================================================
Container for running black code formatting check
=================================================

This container provides a simple way to invoke ``black`` to validate code
formatting across a Python codebase. It should be integrated into CI by setting
the following flag in ``ci/manifest.yml``

::

   gitlab:
     jobs:
       black: true

or adding the following snippet to ``.gitlab-ci.yml``

::

   black:
     stage: sanity_checks
     image: registry.gitlab.com/libvirt/libvirt-ci/black:latest
     needs: []
     script:
       - /black
     artifacts:
       paths:
         - black.txt
       expire_in: 1 week
       when: on_failure
