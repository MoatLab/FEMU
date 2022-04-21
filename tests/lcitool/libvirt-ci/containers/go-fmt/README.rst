=============================================
Container for running go fmt code style check
=============================================

This container provides a simple way to invoke ``go fmt`` to validate code
style across a Golang codebase. It should be integrated into a CI by adding
the following snippet to ``.gitlab-ci.yml``

::

   go-fmt:
     stage: prebuild
     image: registry.gitlab.com/libvirt/libvirt-ci/go-fmt:master
     script:
       - /go-fmt
     artifacts:
       paths:
         - go-fmt.patch
       expire_in: 1 week
       when: on_failure
