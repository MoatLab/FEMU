Contributing platforms && package mappings
==========================================

In case we don't know about the OS distro/build pre-requisite that is desired
to be tested, please file an
`issue <https://gitlab.com/libvirt/libvirt-ci/-/issues/new>`__ . It's important
to file an issue first to avoid duplication of work since it will alert other
people who might have an interest in the same area. The other benefit is that
you'll get feedback from the maintainers on any tips to ease the addition.

The process of adding a new OS distribution is largely the same as adding a
package dependency with only a few differing details, but for the sake of
clarity and simplicity we document both processes separately.
Assuming there is agreement to the change you wish to make and you're willing
to take up on the task then depending on the type of contribution please
proceed with the following.

Adding a new OS distribution
----------------------------

In case you'd like to add a new OS distribution then:

#. Fork the project.

#. Add metadata under ``lcitool/facts/targets/``
   for the new OS distro. Have a look at the structure we use, pick a target
   OS that's closest to what you're adding, copy-paste the configuration and
   edit the relevant bits.
   Note that further code changes may be needed as well if the OS distro
   you're adding uses a package format we currently don't know about.
   Maintainers will advise on what to do in that case.

#. Edit the ``lcitool/facts/mappings.yml`` file to update all the
   existing package entries, providing details of the new OS distro.

#. Run the unit tests with::

   $ python3 -m pytest --regenerate-output

   Note that ``--regenerate-output`` serves at your convenience because it will
   automatically add a valid test output for your newly-added OS so that
   you don't have to dump the ordered list of all the correct package names
   by hand. Be careful though as you could inject other invalid test output
   data as well and proclaiming them as valid!

#. Commit the changes and submit a merge request. Try splitting the changes
   logically into multiple commits.

#. CI pipeline will run to validate the changes to the ``mappings.yml``
   are correct by attempting to install all the packages from the file on all
   OS distributions this project currently knows about
   (including the one you're adding)

#. Once the merge request is accepted, go back to your original project's
   repo where you want to consume your change and update the
   ``ci/manifest.yml`` file there to reflect the change you have made in this
   project.

#. From the root of the original project's git repository run::

   $ lcitool manifest

Adding a new package mapping
----------------------------

In order to simply add a new package mapping:

#. Fork the project.

#. Edit the ``lcitool/facts/mappings.yml`` file to add your desired
   mapping. Please refer to `Mappings naming scheme`_ to help you select the
   best possible name for your mapping.

#. Add the package mapping to the respective project's config file under
   ``lcitool/facts/projects/``.

#. Run the unit tests with::

   $ python3 -m pytest --regenerate-output

   Note that ``--regenerate-output`` serves at your convenience because it will
   automatically add a valid test output for your newly-added mapping so that
   you don't have correct the list of package mappings in the test output
   by hand. Be careful though as you could inject other invalid test output
   data as well and proclaiming them as valid!

#. Commit the changes and submit a merge request. Try splitting the changes
   logically into multiple commits.

#. CI pipeline will run to validate the changes to the ``mappings.yml``
   are correct by attempting to install all the packages from the file
   (including the one you're adding) on all OS distributions this project
   currently knows about.

#. Once the merge request is accepted, go back to your original project's
   repo  and from the root of the original project's git run::

   $ lcitool manifest

Mappings naming scheme
~~~~~~~~~~~~~~~~~~~~~~
When adding a new mapping please use the following generic naming schema:

* ``[package]`` - typically one specific command (or the main package deliverable)

* ``[package]-tools`` - collection of standalone commands shipped in a single
  package

* ``lib[package]`` - runtime library

* ``lib[package]-dev`` - development files for a library

* ``lib[package]-tools`` - tools intended to be used when developing against
  the respective library

Make sure you have a look at the examples below, but like with anything, if
unsure, then simply choose one of the above, make sure you explain your use
case in the merge request and the reviewers will gladly assist you in choosing
the right mapping name for the mapping you're adding.

**Note that many of our existing mappings don't follow the naming scheme above
simply because we didn't have any guideline in place at that time. We'll try to
fix that gradually, but given that the mappings are already in use outside of
this repository, we can't change these at will without the projects agreeing to
it first to avoid breaking their usage.**

Examples:
^^^^^^^^^

* ``iptables`` - this package is usually distributed with more commands: the
  main command ``/usr/sbin/iptables`` and then a few helper tools like
  ``/usr/sbin/iptables-translate`` or ``/usr/sbin/iptables-apply``. Technically,
  both ``[package]-tools`` and ``[package]`` schemes are applicable, but
  arguably given that ``/usr/sbin/iptables`` is the main deliverable of the
  package going with the latter and hence becoming the ``iptables`` mapping is
  likely going to be a better choice for the mapping name with the end result
  looking like so::

   iptables:
     default: iptables
     ...

* ``sdl-config`` - ``sdl-config``  is a tool that is used to configure and
  determine the compiler and linker flags that should be used to compile and
  link programs, libraries, and plugins that use SDL. As such it is often
  distributed with the SDL library development package, so given the naming
  scheme above, it could either be mapped as ``lib[package]`` or
  ``lib[package]-tools``, whatever feels more sensible with the end
  results looking like so::

   libsdl-tools:
     default: sdl2
     deb: libsdl2-dev
     ...

  OR

  ::

   libsdl:
     default: sdl2
     deb: libsdl2-dev
     ...

Project-specific mappings
-------------------------

Some projects may need different mappings, for example if they want the
tests to use specific versions of packages from PyPI or CPAN.
For this reason the possibility to use YAML files stored outside
the libvirt-ci repository, located using the ``--data-dir DIR``
argument to ``lcitool``, is extended to the following paths::

  $DIR/mappings.yml
  $DIR/targets/$NAME.yml
