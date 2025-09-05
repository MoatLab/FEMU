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
   $ pip install -r requirements.txt

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

Note: In case you plan on installing lcitool itself (refer to `Installing
lcitool`_), you can install ``vm-requirements.txt`` along with lcitool in a
single step with:

::

   $ pip3 install .["vm_support"]

where ``vm_support`` denotes the same set of dependencies as extra dependencies
in a way ``pip`` recognizes for installable packages. Additionally, for the
VM use case we require some of the *general* Ansible community modules, so
**Ansible >= 2.10** along with the corresponding Ansible community collections
package (often called simply ``ansible``) is required. This is only relevant if
you install most of your packages from the OS package management software. If
you use the ``pip`` method no action is needed, it'll do the right thing.


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

Like any other python package, you can install this using pip using one of the
following ways depending on your preference (run from the git root):

in a Python virtual environment

::

   $ . <your_virtual_env>/bin/activate
   (<your_virtual_env>) $ pip install .

as your local user:

::

   $ pip3 install --user .

or system-wide with

::

   $ sudo pip3 install .

For development purposes you may find convenient to use an editable install
with pip like this:

::

   $ pip3 install -e .

which will create the necessary links to your working directory and so you
won't need to re-install the lcitool package locally after every code change.

Running lcitool from git
------------------------
If you don't want to install this tool into your environment at all and instead
wish to run it directly, just run the ``bin/lcitool`` script that is located at
the root of this repository which will mangle ``PYTHONPATH`` so that the
package is imported correctly by Python.
