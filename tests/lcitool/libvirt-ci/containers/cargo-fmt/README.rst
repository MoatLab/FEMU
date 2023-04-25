================================================
Container for running cargo fmt code style check
================================================

This container provides a simple way to invoke ``cargo fmt`` to validate code
style across a Rust codebase. It should be integrated into CI by setting the
following flag in ``ci/manifest.yml``

::

   gitlab:
     jobs:
       cargo-fmt: true

or adding the following snippet to ``.gitlab-ci.yml``

::

   cargo-fmt:
     stage: sanity_checks
     image: registry.gitlab.com/libvirt/libvirt-ci/cargo-fmt:latest
     needs: []
     script:
       - /cargo-fmt
     artifacts:
       paths:
         - cargo-fmt.txt
       expire_in: 1 week
       when: on_failure
