Installation
============

Dependencies
------------

In order to use ``lcitool`` you'll need to install at least the common
dependencies that are listed in the ``requirements.txt`` file. You can use
``pip3`` for the convenience of having the ``requirements.txt`` file or you can
use your system package manager (applies to **all** dependencies discussed in
this section) in which case you'll have to find the correct package names for
your OS distribution. If you decide to go with ``pip3``, then proceed with

::

   $ pip3 install --user -r requirements.txt

or into a virtual environment

::

   # this will install only the very basic dependencies
   $ python3 -m venv <path_to_venv>
   $ source <path_to_venv>/bin/activate
   $ pip install -r requirements

More dependencies may be needed depending on your intended use case for
lcitool, see below.

VM dependencies
~~~~~~~~~~~~~~~

If you want to create and manage VMs be it for your CI workloads or simply
for local testing with ``lcitool``, you will need more than just the very basic
dependencies:

* libvirt - library & daemons driving hypervisors underneath
* qemu - emulation & virtualization
* virt-install - creates VMs from the selected install source with libvirt

All of the above dependencies will have to be installed from your system
package manager (they're not available from PyPI).
Additionally to the above there are other Python dependencies that lcitool
requires in the VM scenario

::

   $ pip3 install --user -r vm-requirements.txt

Development dependencies
~~~~~~~~~~~~~~~~~~~~~~~~

If you want to contribute to the libvirt-ci project then you'll need the
largest superset of dependencies (including the virtualization ones mentioned
in the previous section)

::

   $ pip3 install --user -r test-requirements.txt

In addition, the ``ansible-inventory`` executable needs to be installed.

Installing lcitool
------------------

This is a standard python package, so you can install it either as your local
user

::

   $ python3 setup.py install --user

or system-wide with

::

   $ sudo python3 setup.py install

If you prefer, you can have it installed inside a virtual-env too.

For development purposes you may find convenient to do

::

   $ python3 setup.py develop --user

which will create the necessary links to your working directory and so you
won't need to re-install the lcitool package locally after every code change.

If you don't want to install this tool into your environment and instead wish
to run it directly, just run the `bin/lcitool` script that is located at the
root of this repository.
