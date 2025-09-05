===========
VM handling
===========

Configuration
=============

User configuration is read from ``~/.config/lcitool/config.yml``. In case no
configuration is provided all the defaults are pulled from
``lcitool/etc/config.yml``. We recommend reading it to get familiar with the
options and their defaults. We also strongly recommend to set the
``root_password`` to something else than the default value ``root`` in the user
configuration file unless you never plan to use use VMs provisioned with the
default password in a production environment and instead just wish to use
lcitool to create local throw-away test VMs immediately.

If managing VMs installed locally with libvirt you can use the
`libvirt NSS plugin <https://libvirt.org/nss.html>`_ to your
convenience and after installing an enabling the plugin on the host you can
refer to your machines by their name in the Ansible inventory.
As for the plugin settings, you'll be mainly interested in the ``libvirt_guest``
variant of the plugin.

Ansible inventory
-----------------

In addition to creating a configuration file as described in `Configuration`_,
you may also need to provide an Ansible inventory depending on whether
you want to manage external hosts (e.g. machines hosted in public cloud) with
lcitool. The inventory will then have to be placed under the
``~/.config/lcitool`` directory and must be named ``inventory``. It can either
be a single file or a directory containing multiple inventory sources just like
Ansible would allow. You can use any format Ansible recognizes for inventories
- it can even be a dynamic one, i.e. a script conforming to Ansible's
requirements.

There's one requirement however that any inventory source **must** comply with
to be usable with lcitool - every single host must be a member of a group
corresponding to one of our supported target OS platforms (see the next section
on how to obtain the list of targets).
Please avoid naming your hosts and inventory groups identically, otherwise
Ansible will complain by issuing a warning about this which may in turn result
in an unexpected Ansible behaviour.

Managed hosts
~~~~~~~~~~~~~

Since hosts may come from a public cloud environment, we don't execute all the
Ansible tasks which set up the VM environment by default because some of the
tasks could render such hosts unusable. However, for hosts that are going to
be installed as local VMs, we do recommend adding ``fully_managed=True`` as
an inventory variable because it is safe to run all the Ansible tasks in this
case.

An example of a simple INI inventory:

::

    [centos-stream-9]
    centos-stream-9-1
    centos-stream-9-2
    some-other-centos-stream-9

    [fedora-35]
    fedora-test-1
    fedora-test-2   fully_managed=True

    [debian-10]
    192.168.1.30


Installing local VMs
====================

Local VMs can be installed using either of the two ways described below:

Installing using an OS tree URL
-------------------------------

This is the original and most reliable way of installing local VMs based on
URLs pointing to distro OS trees where kernel, init ramdisk and packages can be
pulled from. The main advantage of this method is that most modern distros we
support in this project provide this way of installation with a few exceptions,
e.g. FreeBSD (please refer to `Installing FreeBSD VMs`_). The main downside is
that this installation is slow to be done repeatedly just to spin up a few
instances of the same OS.
To install a local VM using this way, run:

::

    lcitool install $host --target $target_os

where ``$host`` is the name for the VM and ``$target_os`` is one of the
supported target OS plaforms (see `Usage and examples`_ below).
Another option of installing guests with lcitool is by adding a managed host
entry in the Ansible inventory in which case lcitool's invocation would look
like this:

::

    lcitool install $host

Please refer to the `Ansible inventory`_ and `Managed hosts`_ sections
respectively on how to use an inventory with lcitool. Note that not all guests
can be installed using the ways described above, e.g. FreeBSD or Alpine guests.
See `Installing FreeBSD VMs`_ to know how to add such a host in that case.


Installing using vendor cloud-init images
-----------------------------------------

This way of installing VMs is based on the *osinfo* database which is continuously
updated by the community to provide all kinds of useful installation related
information about an OS. One of such information is a URL to the latest distro
vendor provided cloud-init image. This image is then downloaded directly from
the vendor, cached locally, and used for future VM instantiations. This makes
the method significantly faster then the one using URLs, however it comes at a
cost. Here are a few downsides to using this method, so make sure you evaluate
them before deciding which install strategy (as we call it) is best for you:

* even though *osinfo*'s database is constantly updating, your host system may
  either be too old (an LTS release) with no updates apart from security and bug
  fixes or simply not be scheduled to update the *osinfo* package more than once
  a release by *osinfo*'s package maintainers on that given distro. If that's the
  case, the version of *osinfo* database you have may not have all (if any) URLs
  to the vendor provided cloud-init images of the OS distro you wish to install
  in a VM. Naturally, installation of such an OS distro in a VM would fail
  using this method and you can either fall back to the URL-based install
  mentioned above or you can install the latest *osinfo* database manually
  yourself. If you decide to with the latter, there's a few ways of installing
  a fresh osinfo database on your system:

  * by running ``osinfo-db-import --nightly`` which downloads and installs
    the latest unofficial automated database build directly from the
    project's GitLab CI pipeline
    *Note: your* ``osinfo-db-tools`` *package needs to be new enough to support
    the* ``--nightly`` *option.*

  * by using the URL to the
    `Gitlab nightly database build archive <https://gitlab.com/libosinfo/osinfo-db/-/jobs/artifacts/main/raw/osinfo-db-latest.tar.xz?job=publish>`__
    directly in ``osinfo-db-import <db local archive file | db archive URL>``

  * by building the osinfo-db project locally from source and installing the
    database that way (**discouraged**)

* some distro vendors don't provide a symbolic link (e.g. Fedora) always
  pointing to the latest image build. What this means for you is that the image
  that is pulled from the vendor may not be latest one available or even worse
  may not even exist anymore because it has since been removed by the vendor,
  but the link in *osinfo*'s database hasn't been properly updated upstream yet.
  In either case, if that happens, you need to fall back to the URL-based
  install.

* vendor provided cloud-init images may not be built on a daily basis, so if
  you're looking for the latest contents right out of the box without running
  any additional operations on the VM, you need to use the URL-based install
  which is guaranteed to always pull the latest contents.

* the locally cached cloud-init images get easily out of sync. Essentially the
  situation is similar to the previous one with the exception that some vendors
  provide daily image builds, so if fresh content is more important than speedy
  VM installs and lower storage footprint of the VM, then you need to fall back
  to using the URL-based install.


To install a local VM using this way, run::

    lcitool install $host --target $target_os --strategy cloud

To force a new download of a new image (potentially a newer one if the vendor
has refreshed the images since you downloaded your last one), run::

    lcitool install $host --target $target_os --strategy cloud --force

Installing using custom template images
---------------------------------------

Vendor cloud images are convenient to use because they're stripped down to
the bare minimum so they don't take long to download, they're publicly
accessible from potentially multiple mirrors, and they're rebuilt often so you
should get fresh contents regularly. The problem is that sometimes you need to
install a bunch of other packages to get your environment going, including some
complex system configuration. The obvious option is to perform the
configuration each time you provision a new system backed by the vendor cloud
image. However, that takes time and it would be better if the provisioning
could be sped up even more by pre-installing and pre-configuring the vendor
cloud image to your liking and then use that image as a template.

To install a local VM using your pre-configured template image, run ::

    lcitool install $host --target $target_os --strategy template --template <path to your base image>

Note that in order for the above to work your template image needs to have
cloud-init enabled as lcitool will provide a minimalistic NoCloud ISO to the
VM (injecting the public SSH key specified in lcitool's config).

Installing FreeBSD VMs
----------------------

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

Then inside the guest, FreeBSD should detect the enlarged volume
and have automatically increased the vtbd0 partition size. Thus
all that is required is to accept the changes and then rexize
the filesystem.

::

   # gpart commit vtbd0
   # service growfs onestart

Some manual tweaking will be needed, in particular:

* ``/etc/ssh/sshd_config`` must contain the ``PermitRootLogin yes`` directive;

* ``/etc/rc.conf`` must contain the ``sshd_enable="YES"`` setting;

* the root password must be manually set to "root" (without quotes).

Once these steps have been performed, FreeBSD guests can be managed just
like all other guests.


Updating VMs with a given project dependencies
==============================================

So you've installed your VM with lcitool. What's next? Next the VM needs to
go through all the post-installation configuration steps required to
make the newly-added machine usable and ready to be used for building a
project. This includes resetting the root password to the one you set in
``$HOME/.config/lcitool/config.yml``, uploading your SSH key, updating the
system, etc.


``$project``. set up (in other words update) with a given project's package dependencies so
that the respective project

::

    $ lcitool projects

You can run update on the VM with

::

    # the syntax is 'lcitool update $guest $project'
    $ lcitool update my_vm_name libvirt

More hosts (external bare metal hosts are supported as well) can be updated
with more projects at the same time

::

    $ lcitool update my_vm_name,my_bare_metal_host libvirt,qemu

It is also recommended to run the same command periodically to
ensure the machine configuration is sane and all installed packages are updated
for maintenance purposes. This is where the special keyword **all** might come
handy as you can go as far as putting the following in your crontab

::

   0 0 * * * lcitool update all all


Injecting software repositories & custom pre-tasks
--------------------------------------------------

If you wish to use the above procedure with one of the enterprise distros out
there you'll quickly find out it doesn't work because those don't use publicly
accessible (or subscription managed) repositories which we could make use of.
You'll have to inject these using Ansible pre-tasks file which we'll runs very
early during the bootstrap stage of the ``update`` command before performing
any update or configuration changes on the target system. First you need to
create a data directory which you'll pass to lcitool

::

    $ mkdir <lcitool_datadir>

then you'll create a ``<lcitool_datadir>/ansible/pre/tasks/main.yml`` Ansible
task file containing tasks necessary to enable the base repositories. Finally,
you need to tell lcitool about this data directory when running the ``update``
command

::

    $ lcitool --data-dir <lcitool_datadir> update <hosts> <projects>

Note that ``main.yml`` is a regular Ansible tasks file (not a playbook!), so
you're constrained by what Ansible allows to be in a tasks file. We recommend
to keep the file as simple as possible by not adding any tasks unrelated to
software installation or package updates in order to not collide with any
system configuration changes (e.g. SSH key uploads) lcitool performs as part of
the ``update`` sequence. If you need more configuration changes you can always
execute ``ansible-playbook`` yourself after performing ``update`` and that way
you'll have full control over the expected outcome.


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


More VM examples
================

This section provides more usage examples once you have a VM installed and
updated.

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
projects.


Useful tips
===========

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
