D-Bus VNC
=========

The ``qemu-vnc`` standalone VNC server exposes a D-Bus interface for management
and monitoring of VNC connections.

The service is available on the bus under the well-known name ``org.qemu.vnc``.
Objects are exported under ``/org/qemu/Vnc1/``.

.. contents::
   :local:
   :depth: 1

.. only:: sphinx4

   .. dbus-doc:: tools/qemu-vnc/qemu-vnc1.xml

.. only:: not sphinx4

   .. warning::
      Sphinx 4 is required to build D-Bus documentation.

      This is the content of ``tools/qemu-vnc/qemu-vnc1.xml``:

   .. literalinclude:: ../../tools/qemu-vnc/qemu-vnc1.xml
      :language: xml
