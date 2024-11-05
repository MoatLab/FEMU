.. _skiboot-6.0.22:

==============
skiboot-6.0.22
==============

skiboot 6.0.22 was released on Friday March 27th, 2020. It replaces
:ref:`skiboot-6.0.21` as the current stable release in the 6.0.x series.

It is recommended that 6.0.22 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- errorlog: Increase the severity of abnormal reboot events

- eSEL: Make sure PANIC logs are sent to BMC before calling assert

- core/ipmi: Fix use-after-free

- ipmi: ensure forward progress on ipmi_queue_msg_sync()
