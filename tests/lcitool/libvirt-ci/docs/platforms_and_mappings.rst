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
   mapping.

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

Project-specific mappings
-------------------------

Some projects may need different mappings, for example if they want the
tests to use specific versions of packages from PyPI or CPAN.
For this reason the possibility to use YAML files stored outside
the libvirt-ci repository, located using the ``--data-dir DIR``
argument to ``lcitool``, is extended to the following paths::

  $DIR/mappings.yml
  $DIR/targets/$NAME.yml
