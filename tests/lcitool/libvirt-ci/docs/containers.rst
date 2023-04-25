==========
Containers
==========

Container functionality
=======================

lcitool also supports running container workloads, be it directly by executing
your script or manually over an interactive shell session to have full control
when debugging a container execution issue.

The idea here is to wrap common container engines' functionality by exposing
a simpler and convenient interface for common throwaway test environment based
scenarios. In other words, you can take your workload data and an execution script
and use lcitool to mount all of it inside a container of your choice
(including software dependencies) and potentially run the script.


Listing available container engines
===================================

Currently both Podman and Docker engines are supported to power your
workload execution via lcitool. To list which of them is enabled and
available to use, run

::

    lcitool container engines


Note that for ``Docker``, unlike with ``Podman``, you need to make sure
your user is part of the "docker" group and that the docker daemon is
running, otherwise ``Docker`` wouldn't show up with the above command.


Building supported container images
===================================

This requires ``--target $target_os`` and ``--projects $projects``
arguments to be passed to the CLI.

**lcitool** is used to generate a *Dockerfile* which is used to build
an image with tag ``lcitool.$target_os`` e.g ``lcitool.fedora-36``.

``$target_os`` is one of the supported target OS platforms and
``$projects`` are the supported projects in lcitool.
Check `More VM examples <https://gitlab.com/libvirt/libvirt-ci/-/blob/master/docs/vms.rst>`_
::

    lcitool container build -t $target_os -p $projects


::

    lcitool container build --target $target_os --projects $projects


Executing a workload inside a container
=======================================

Executing a workload in a container with lcitool can be anything from
building an application from sources to test a new feature of your app
in an isolated throwaway environment etc.

In either case, you'll need to provide a "workload" directory (or data
directory) containing all your necessary data (if you need any) to lcitool
to be mounted inside the container along with the script you wish to execute
as follows:

::

    $ pwd
    /home/<container_user>
    $ ls
    script datadir

Providing a script in this case is mandatory (unlike with the "shell" command,
see `Running an interactive shell session`_).

The data directory is mounted to the *datadir/* directory in the
home directory inside the container, and the working directory is
switched to the home directory to make execution easier.

The script file is mounted to the *script* file in the home directory
inside the container. Ensure the file is an executable by running:

::

    chmod +x <path_to_your_script>


It can also be used as a standalone script (e.g an ``echo hello" script``).

Then, it's just a matter of running:

::

    lcitool container run
        --script <path_to_your_script>
        --workload-dir <path_to_dir>
        <image>


See `Usage examples`_ for more examples.


Running an interactive shell session
====================================

This is used to gain access to the shell in a container. Gaining access to
the shell in a container can be a very helpful for debugging processes
in the container.

Unlike with the ``run`` command, you don't need to provide any data
(i.e ``--script`` or ``--workload-dir``) to get a shell, but if you do,
those will be mounted in the same way as for the ``run`` command before
the script would be executed.

To get a plain shell, simply run:

::

    lcitool container shell <image>


Check below for more examples


Usage examples
==============

- To run the workload contained in ``$SCRIPT`` file in a *fedora-36*
  image with *libvirt-python* dependencies installed on it with
  environment variable ``BAR=baz`` using *podman* engine with
  user *1000*.

  First, we need to build the actual container image to be able to run any
  workloads in it
  ::

      lcitool container build \
          --projects libvirt-python --target fedora-36

  When the image is ready, we can proceed with running the workload
  ::

      lcitool container run \
          --script $SCRIPT \
          --user 1000 --env BAR=baz \
          lcitool.fedora-36


- To run the workload contained in the *build* file in an upstream
  *debian-11* image that has ``$DATADIR`` mounted in its home directory
  with environment variable ``F00=bar`` using *podman* engine with
  user *1000*.

  First, we need to pull the actual container image to be able to run any
  workloads in it
  ::

      podman pull registry.gitlab.com/libvirt/libvirt/ci-debian-11

  When the image is ready, we can proceed with running the workload
  ::

      lcitool container run \
          --workload-dir $DATADIR --script build \
          --user 1000 --env FOO=bar \
          registry.gitlab.com/libvirt/libvirt/ci-debian-11


- To run the workload contained in ``$SCRIPT`` file on a *ubuntu-2204* image
  that has ``$DATADIR`` mounted in its home directory with *libvirt-python*
  and *libvirt-go* dependencies installed on it with environment variables,
  ``BAZ=foo``, ``BAR=baz`` using *docker* engine with *root* user.

  First, we need to build the actual container image to be able to run any
  workloads in it
  ::

      lcitool container build \
          -p libvirt-python,libvirt-go -t ubuntu-2204 \
          --engine docker

  When the image is ready, we can proceed with running the workload
  ::

      lcitool container run \
          --workload-dir $DATADIR --script $SCRIPT \
          --env BAZ=foo --env BAR=baz \
          --engine docker \
          lcitool.ubuntu-2204


- To access interactive shell with ``$DATADIR`` in the ``PWD`` in an
  *alpine-316* image with *libvirt-go* dependencies installed on it with
  environment variable ``FOO=bar`` using *podman* engine with user $USER.

  First, we need to build the actual container image to be able to run any
  workloads in it
  ::

      lcitool container build \
          --projects libvirt-go --target alpine-316

  When the image is ready, we can proceed with running the workload
  ::

      lcitool container shell \
          --env FOO=baz --user $USER \
          --workload-dir $DATADIR \
          lcitool.alpine-316:latest


- To access interactive shell with ``$DATADIR`` and ``$SCRIPT`` in the ``PWD``
  in a *opensuse-leap-154* image with *libvirt-go* dependencies installed on it with
  environment variable ``FOO=bar`` with user *1000* using *podman* engine.

  First, we need to build the actual container image to be able to run any
  workloads in it
  ::

      lcitool container build \
          --projects libvirt-go --target opensuse-leap-154


  When the image is ready, we can proceed with running the workload
  ::

      lcitool container shell \
          --workload-dir $DATADIR --script $SCRIPT \
          --env FOO=baz --user 1000 \
          lcitool.opensuse-leap-154


- To access interactive shell with ``$SCRIPT`` in the ``PWD`` in a
  *debian-11* image with the dependencies for all *libvirt* projects supported
  by lcitool installed on it with environment variable ``FOO=bar``, user *1000*
  with the *podman* engine.

  First, we need to build the actual container image to be able to run any
  workloads in it
  ::

      lcitool container build \
          --projects libvirt* --target debian-11

  When the image is ready, we can proceed with running the workload
  ::

      lcitool container shell \
          --env FOO=baz --user 1000 \
          --script $SCRIPT \
          lcitool.debian-11


- To access the shell in an upstream *almalinux-8* image with *root* user with
  the *docker* engine.

  First, we need to pull the actual container image to be able to run any
  workloads in it
  ::

      docker pull registry.gitlab.com/libvirt/libvirt/ci-almalinux-8

  When the image is ready, we can proceed with running the workload
  ::

      lcitool container shell \
          --engine docker \
          registry.gitlab.com/libvirt/libvirt/ci-almalinux-8
