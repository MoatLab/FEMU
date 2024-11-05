Externally defined project package lists
========================================

Historically all projects have been defined in data files at the location::

  lcitool/facts/projects/$NAME.yml

This creates a chicken and egg problem when a project changes its build
pre-requisites, as libvirt-ci needs to be updated if-and-only-if the
project is updated and vice-versa.

To solve this problem, it is now possible to define the project package
lists outside the libvirt-ci repository. They can be located by giving
the ``--data-dir DIR`` argument to ``lcitool``. When this is present,
data files will be additionally loaded from::

  $DIR/projects/$NAME.yml
