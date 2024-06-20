Packaging
=========

This is a guide mainly for packagers who want to distribute lcitool.

Building distributions
----------------------

Build backend
~~~~~~~~~~~~~

This project is based on setuptools and is fully compliant with
`PEP 517 <https://peps.python.org/pep-0517/>`_
relying solely on ``pyproject.toml`` as the only build configuration source.

Building the package
~~~~~~~~~~~~~~~~~~~~

lcitool package can be simply built with

::

   # from the git root
   $ python3 -m build

if for some reason you want only a source distribution or a wheel distributable
then use the following respectively:

::

   # build source distribution
   $ python3 -m build --sdist

   # build a wheel
   $ python3 -m build --wheel

Note that if only a wheel is requested, it is built out of the source code base
rather than from an `sdist` like it normally would.
