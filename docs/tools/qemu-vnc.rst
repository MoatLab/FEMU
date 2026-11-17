.. _qemu-vnc:

==========================
QEMU standalone VNC server
==========================

Synopsis
--------

**qemu-vnc** [*OPTION*]...

Description
-----------

``qemu-vnc`` is a standalone VNC server that connects to a running QEMU instance
via the D-Bus display interface (:ref:`dbus-display`). It serves the guest
display, input, audio, clipboard, and serial console chardevs over the VNC
protocol, allowing VNC clients to interact with the virtual machine without QEMU
itself binding a VNC socket.

Options
-------

.. program:: qemu-vnc

.. option:: -h, --help

  Display help and exit.

.. option:: -V, --version

  Print version information and exit.

.. option:: -a ADDRESS, --dbus-address=ADDRESS

  D-Bus address to connect to. When not specified, ``qemu-vnc`` connects to the
  session bus.

.. option:: -p FD, --dbus-p2p-fd=FD

  File descriptor of an inherited Unix socket for a peer-to-peer D-Bus
  connection to QEMU. This is mutually exclusive with ``--dbus-address`` and
  ``--bus-name``.

.. option:: -n NAME, --bus-name=NAME

  D-Bus bus name of the QEMU instance to connect to. The default is
  ``org.qemu``. When a custom ``--dbus-address`` is given without a bus name,
  peer-to-peer D-Bus is used.

.. option:: -W, --wait

  Wait for the D-Bus bus name to appear. Only for bus connections.

.. option:: --password

  Require VNC password authentication from connecting clients. The password is
  set at runtime via the D-Bus ``SetPassword`` method (see
  :doc:`/interop/dbus-vnc`). Clients will not be able to connect until a
  password has been set.

  This option is ignored when a systemd credential password is present, since
  password authentication is already enabled via ``password-secret`` in that
  case.

.. option:: -l ADDR, --vnc-addr=ADDR

  VNC listen address in the same format as the QEMU ``-vnc`` option (default
  ``localhost:0``, i.e. TCP port 5900).

.. option:: -w ADDR, --websocket=ADDR

  Enable WebSocket transport on the given address. *ADDR* can be a port number
  or an *address:port* pair.

.. option:: -O OBJDEF, --object=OBJDEF

  Create a QEMU user-creatable object. *OBJDEF* uses the same key=value syntax
  as the QEMU ``-object`` option. This option may be given multiple times. It is
  needed, for example, to create authorization objects referenced by
  ``--tls-authz``.

.. option:: -t DIR, --tls-creds=DIR

  Directory containing TLS x509 credentials (``ca-cert.pem``,
  ``server-cert.pem``, ``server-key.pem``). When specified, the VNC server
  requires TLS from connecting clients.

.. option:: --tls-authz=ID

  ID of a ``QAuthZ`` object previously created with ``--object`` for TLS client
  certificate authorization. When specified, the TLS credentials are created
  with ``verify-peer=yes`` so connecting clients must present a valid
  certificate. After the TLS handshake, the client certificate Distinguished
  Name is checked against the authorization object. This option requires
  ``--tls-creds``.

.. option:: --sasl

  Require that the client use SASL to authenticate with the VNC server. The
  exact choice of authentication method used is controlled from the system /
  user's SASL configuration file for the 'qemu' service. This is typically found
  in ``/etc/sasl2/qemu.conf``. If running QEMU as an unprivileged user, an
  environment variable ``SASL_CONF_PATH`` can be used to make it search
  alternate locations for the service config. While some SASL auth methods can
  also provide data encryption (eg GSSAPI), it is recommended that SASL always
  be combined with the 'tls' and 'x509' settings to enable use of SSL and server
  certificates. This ensures a data encryption preventing compromise of
  authentication credentials. See the :ref:`VNC security` section in the System
  Emulation Users Guide for details on using SASL authentication.

.. option:: --sasl-authz=ID

  ID of a ``QAuthZ`` object previously created with ``--object`` for SASL
  username authorization. After successful SASL authentication, the
  authenticated username is checked against the authorization object. If the
  check fails, the client is disconnected. This option requires ``--sasl``.

.. option:: -s POLICY, --share=POLICY

  Set display sharing policy. *POLICY* is one of ``allow-exclusive``,
  ``force-shared``, or ``ignore``.

  ``allow-exclusive`` allows clients to ask for exclusive access. As suggested
  by the RFB spec this is implemented by dropping other connections. Connecting
  multiple clients in parallel requires all clients asking for a shared session
  (vncviewer: -shared switch). This is the default.

  ``force-shared`` disables exclusive client access. Useful for shared desktop
  sessions, where you don't want someone forgetting to specify -shared
  disconnect everybody else.

  ``ignore`` completely ignores the shared flag and allows everybody to connect
  unconditionally. Doesn't conform to the RFB spec but is traditional QEMU
  behavior.

.. option:: -C NAME, --vt-chardev=NAME

  Chardev type name to expose as a VNC text console. This option may be given
  multiple times to expose several chardevs. When not specified, the defaults
  ``org.qemu.console.serial.0`` and ``org.qemu.monitor.hmp.0`` are used.

.. option:: -N, --no-vt

  Do not expose any chardevs as text consoles. This overrides the default
  chardev list and any ``--vt-chardev`` options.

.. option:: -k LAYOUT, --keyboard-layout=LAYOUT

  Keyboard layout (e.g. ``en-us``). Passed through to the VNC server for
  key-code translation.

.. option:: --lossy

  Enable lossy compression methods (gradient, JPEG, ...). If this option is set,
  VNC client may receive lossy framebuffer updates depending on its encoding
  settings. Enabling this option can save a lot of bandwidth at the expense of
  quality.

.. option:: --non-adaptive

  Disable adaptive encodings. Adaptive encodings are enabled by default. An
  adaptive encoding will try to detect frequently updated screen regions, and
  send updates in these regions using a lossy encoding (like JPEG). This can be
  really helpful to save bandwidth when playing videos. Disabling adaptive
  encodings restores the original static behavior of encodings like Tight.

.. option:: -T, --trace [[enable=]PATTERN][,events=FILE][,file=FILE]

  .. include:: ../qemu-option-trace.rst.inc

Examples
--------

Start QEMU with the D-Bus display backend::

    qemu-system-x86_64 -display dbus ...

Then attach ``qemu-vnc``::

    qemu-vnc

A VNC client can now connect to ``localhost:5900``.

To listen on a different port with TLS::

    qemu-vnc --vnc-addr localhost:1 --tls-creds /etc/pki/qemu-vnc

To require TLS with client certificate authorization::

    qemu-vnc --object authz-list-file,id=auth0,filename=/etc/qemu/vnc.acl,refresh=on \
             --tls-creds /etc/pki/qemu-vnc --tls-authz auth0

To enable SASL authentication with TLS::

    qemu-vnc --tls-creds /etc/pki/qemu-vnc --sasl

VNC password authentication
----------------------------

There are two ways to enable VNC password authentication:

1. ``--password`` flag -- start ``qemu-vnc`` with ``--password`` and
   then set the password at runtime using the D-Bus ``SetPassword``
   method.  Clients will be rejected until a password is set.

2. systemd credentials -- if the ``CREDENTIALS_DIRECTORY``
   environment variable is set (see :manpage:`systemd.exec(5)`) and
   contains a file named ``vnc-password``, the VNC server will use
   that file's contents as the password automatically.  The
   ``--password`` flag is not needed in this case.

D-Bus interface
---------------

``qemu-vnc`` exposes a D-Bus interface for management and monitoring of
VNC connections.  See :doc:`/interop/dbus-vnc` for the full interface
reference.

See also
--------

:manpage:`qemu(1)`,
:doc:`/interop/dbus-display`,
:doc:`/interop/dbus-vnc`,
`The RFB Protocol <https://github.com/rfbproto/rfbproto>`_
