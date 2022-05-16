==========================================
lcitool - libvirt CI guest management tool
==========================================

Installation
============

Installing dependencies
-----------------------

``virt-install`` need to be available on the host. Since it is not distributed
via PyPI, this needs to be installed with your package manager.

You need to install also a few Python dependencies using your package manager
or using ``pip3`` (see the provided ``requirements.txt`` file). You can install
to the Python user install directory

::

   # this will install only the very basic dependencies
   $ pip3 install --user -r requirements.txt

or, system-wide

::

   # this will install only the very basic dependencies
   $ sudo pip3 install -r requirements.txt

Depending on your intended use case for lcitool you can pick which dependencies
you need to have installed, e.g.

If you want to create and manage VMs for your CI workloads with ``lcitool``,
you will need more than just the very basic dependencies:

::

   $ pip3 install --user -r vm-requirements.txt

or if you want to contribute to the project, you'll need the largest set
containing even the test dependencies

::

   $ pip3 install --user -r test-requirements.txt


.. note:: If you prefer you can try to find those requirements in your package
   manager as well.

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
to run it directly, just run the `lcitool` script that is located at the
root of this repository.


Configuration
=============

Before you can start installing or managing machines, you need to create
``~/.config/lcitool/config.yml``, ideally by copying the
``config.yml`` template, and set at least the options marked as
"(mandatory)" depending on the flavor (``test``, ``gitlab``) you wish to
use with your machines.

If managing VMs installed locally with libvirt you can use the
`libvirt NSS plugin <https://libvirt.org/nss.html>`_ to your
convenience and after installing an enabling the plugin on the host you can
refer to your machines by their name in the Ansible inventory.
As for the plugin settings, you'll be mainly interested in the ``libvirt_guest``
variant of the plugin.

To keep guests up to date over time, you might find it useful to have an entry
such as this one

::

   0 0 * * * lcitool update all all

in your crontab.


Ansible inventory
=================

In addition to creating a configuration file, as described in the section
above, you also need to provide an Ansible inventory for the machines you wish
to manage with lcitool.  This gives you the flexibility to also utilize
external hosts (e.g. machines hosted in a public cloud) with lcitool.

The inventory needs to be placed in the ``~/.config/lcitool`` directory and
must be named ``inventory``. The inventory itself can either be a single file
or a directory containing multiple inventory sources just like Ansible would
allow. You can use any format Ansible recognizes for inventories - it can
even be a dynamic one, i.e. a script conforming to Ansible's requirements.

There's one requirement however that any inventory source **must** comply with
to be usable with lcitool - every single host must be a member of a group
corresponding to one of our supported target OS platforms (see the next section
on how to obtain the list of targets).
Please avoid naming your hosts and inventory groups identically, otherwise
Ansible will complain by issuing a warning about this which may in turn result
in an unexpected Ansible behaviour.

Managed hosts
-------------

Since hosts may come from a public cloud environment, we don't execute all the
Ansible tasks which set up the VM environment by default because some of the
tasks could render such hosts unusable. However, for hosts that are going to
be installed as local VMs, we do recommend adding ``fully_managed=True`` as
an inventory variable because it is safe to run all the Ansible tasks in this
case.

An example of a simple INI inventory:

::

    [centos-stream-8]
    centos-stream-8-1
    centos-stream-8-2
    some-other-centos-stream-8

    [fedora-35]
    fedora-test-1
    fedora-test-2   fully_managed=True

    [debian-10]
    192.168.1.30


Usage and examples
==================

Depending on whether you're bringing an external host or you're installing
a guest locally, there are two/three steps respectively to prepare such a
machine for building projects:

* update the local inventory, as explained in the previous section,
  so that it includes the new machine;

* only for machines that are local VMs, run ``lcitool install $host``:
  this will create a libvirt VM named ``$host`` and perform an unattended
  OS installation inside it. Not all guests can be installed this way: see
  the "FreeBSD" section below;

* ``lcitool update $guest $project`` will go through all the
  post-installation configuration steps required to make the newly-added
  machine usable and ready to be used for building ``$project``.

Once those steps have been performed, maintenance will involve running:

::

   $ lcitool update $guest $project

periodically to ensure the machine configuration is sane and all installed
packages are updated.

To get a list of known target platforms run:

::

   $ lcitool targets

If you're interested in the list of hosts currently provided through the
inventory sources, run:

::

   $ lcitool hosts

To see the list of supported projects that can be built from source with
lcitool, run:

::

   $ lcitool projects

You can run operations involving multiple guests and projects during a single
execution as well since both hosts and project specification support shell
globbing. Using the above inventory as an example, running

::

   $ lcitool update '*fedora*' '*osinfo*'

will update all Fedora guests and get them ready to build libosinfo and related
projects. Once hosts have been prepared following the steps above, you can use
``lcitool`` to perform builds as well: for example, running

::

   $ lcitool build '*debian*' libvirt-python

will fetch libvirt-python's ``master`` branch from the upstream repository
and build it on all Debian hosts.

You can add more git repositories by tweaking the ``git_urls`` dictionary
defined in ``playbooks/build/jobs/defaults.yml`` and then build arbitrary
branches out of those with

::

   $ lcitool build -g github/cool-feature all libvirt

Note that unlike other lcitool commands which take projects as input the 'build'
command doesn't accept the project list specified either as 'all' or with a
wildcard.


Test use
========

If you are a developer trying to reproduce a bug on some OS you don't
have easy access to, you can use these tools to create a suitable test
environment.

The ``test`` flavor is used by default, so you don't need to do anything
special in order to use it: just follow the steps outlined above. Once
a guest has been prepared, you'll be able to log in as ``test`` either
via SSH (your public key will have been authorized) or on the serial
console (password: ``test``).

Once logged in, you'll be able to perform administrative tasks using
``sudo``. Regular root access will still be available, either through
SSH or on the serial console.

Since guests created for this purpose are probably not going to be
long-lived or contain valuable information, you can configure your
SSH client to skip some of the usual verification steps and thus
prompt you less frequently; moreover, you can have the username
selected automatically for you to avoid having to type it in every
single time you want to connect. Just add

::

   Host libvirt-*
       User test
       GSSAPIAuthentication no
       StrictHostKeyChecking no
       CheckHostIP no
       UserKnownHostsFile /dev/null

to your ``~/.ssh/config`` file to achieve all of the above.


Cloud-init
==========

If you intend to use the generated images as templates to be instantiated in
a cloud environment like OpenStack, then you want to set the
``install.cloud_init`` key to ``true`` in ``~/.config/lcitool/config.yaml``. This will
install the necessary cloud-init packages and enable the corresponding services
at boot time. However, there are still a few manual steps involved to create a
generic template. You'll need to install the ``libguestfs-tools`` package for that.

Once you have it installed, shutdown the machines gracefully. First, we're going to
"unconfigure" the machine in a way, so that clones can be made out of it.

::

    $ virt-sysprep -a libvirt-<machine_distro>.qcow2

Then, we sparsify and compress the image in order to shrink the disk to the
smallest size possible

::

    $ virt-sparsify --compress --format qcow2 <indisk> <outdisk>

Now you're ready to upload the image to your cloud provider, e.g. OpenStack

::

    $ glance image-create --name <image_name> --disk-format qcow2 --file <outdisk>

FreeBSD is tricky with regards to cloud-init, so have a look at the
`Cloud-init with FreeBSD`_ section instead.


FreeBSD
=======

Installation of FreeBSD guests must be performed manually; alternatively,
the official qcow2 images can be used to quickly bring up such guests.

::

   $ MAJOR=12
   $ MINOR=1
   $ VER=$MAJOR.$MINOR-RELEASE
   $ sudo wget -O /var/lib/libvirt/images/libvirt-freebsd-$MAJOR.qcow2.xz \
     https://download.freebsd.org/ftp/releases/VM-IMAGES/$VER/amd64/Latest/FreeBSD-$VER-amd64.qcow2.xz
   $ sudo unxz /var/lib/libvirt/images/libvirt-freebsd-$MAJOR.qcow2.xz
   $ virt-install \
     --import \
     --name libvirt-freebsd-$MAJOR \
     --vcpus 2 \
     --graphics vnc \
     --noautoconsole \
     --console pty \
     --sound none \
     --rng device=/dev/urandom,model=virtio \
     --memory 2048 \
     --os-variant freebsd$MAJOR.0 \
     --disk /var/lib/libvirt/images/libvirt-freebsd-$MAJOR.qcow2

The default qcow2 images are sized too small to be usable. To enlarge
them do

::

   $ virsh blockresize libvirt-freebsd-$MAJOR \
     /var/lib/libvirt/images/libvirt-freebsd-$MAJOR.qcow2 15G

Then inside the guest, as root, enlarge the 3rd partition & filesystem
to consume all new space:

::

   # gpart resize -i 3 vtbd0
   # service growfs onestart

Some manual tweaking will be needed, in particular:

* ``/etc/ssh/sshd_config`` must contain the ``PermitRootLogin yes`` directive;

* ``/etc/rc.conf`` must contain the ``sshd_enable="YES"`` setting;

* the root password must be manually set to "root" (without quotes).

Once these steps have been performed, FreeBSD guests can be managed just
like all other guests.

Cloud-init with FreeBSD
-----------------------

FreeBSD doesn't fully support cloud-init, so in order to make use of it, there
are a bunch of manual steps involved. First, you want to install the base OS
manually rather than use the official qcow2 images, in contrast to the
suggestion above, because cloud-init requires a specific disk partitioning scheme.
Best you can do is to look at the official
`OpenStack guide <https://docs.openstack.org/image-guide/freebsd-image.html>`_
and follow only the installation guide (along with the ``virt-install`` steps
outlined above).

Now, that you have and OS installed and booted, set the ``install.cloud_init``
key to ``true`` in ``~/.config/lcitool/config.yaml`` and update it with the
desired project.

The sysprep phase is completely manual, as ``virt-sysprep`` cannot work with
FreeBSD's UFS filesystem (because the Linux kernel can only mount it read-only).

Compressing and uploading the image looks the same as was mentioned in the
earlier sections

::

    $ virt-sparsify --compress --format qcow2 <indisk> <outdisk>
    $ glance image-create --name <image_name> --disk-format qcow2 --file <outdisk>


Externally defined project package lists
========================================

Historically all projects have been defined in data files at the location::

  guests/lcitool/lcitool/ansible/vars/projects/$NAME.yml

This creates a chicken and egg problem when a project changes its build
pre-requisites, as libvirt-ci needs to be updated if-and-only-if the
project is updated and vica-versa.

To solve this problem, it is now possible to define the project package
lists outside the libvirt-ci repository. They can be located by giving
the ``--data-dir DIR`` argument to ``lcitool``. When this is present,
data files will be additionally loaded from::

  $DIR/projects/$NAME.yml

Adding a new target OS
======================

If you want to contribute a new target OS to lcitool, you'll have to create
a directory with the corresponding name under the
``guests/lcitool/lcitool/ansible/group_vars`` and place a YAML configuration of
the target OS inside. The structure of the configuration file should correspond
with the other targets, so please follow them by example.
Unless your desired target OS uses a packaging format which lcitool can't work
with yet, you're basically done, just record the OS name in the
``guests/lcitool/lcitool/ansible/vars/mappings.yml`` file in the commentary
section at the beginning of the file - again, follow the existing entries by
example. However, if you're introducing a new packaging format, you'll have to
update **all** the mappings in the file so that lcitool knows what the name of
a specific package is on your target OS.


Contributing tests
==================

This project utilizes the pytest framework. Make sure you add a new test case
with any new logic you introduce to the lcitool code base.
Whenever you add new package mappings the test suite will naturally fail
because it simply doesn't know about them. In that case, just re-run the test
suite as

::

    $ cd guests/lcitool
    $ python3 -m pytest --regenerate-output

and the expected package data sets will be updated. You can then just grab the
changes and add them to your commit.
