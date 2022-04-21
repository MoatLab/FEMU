================================================
Container for running cargo fmt code style check
================================================

This container provides a simple way to invoke ``cargo fmt`` to validate code
style across a Rust codebase. It should be integrated into CI by adding
the following snippet to ``.gitlab-ci.yml``

::

   cargo-fmt:
     stage: prebuild
     image: registry.gitlab.com/libvirt/libvirt-ci/cargo-fmt:master
     script:
       - /cargo-fmt
     artifacts:
       paths:
         - cargo-fmt.patch
       expire_in: 1 week
       when: on_failure
