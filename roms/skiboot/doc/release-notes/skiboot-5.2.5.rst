skiboot-5.2.5
-------------

skiboot-5.2.5 was released on Thursday July 28th, 2016.

skiboot-5.2.5 contains all bug fixes as of skiboot-5.1.17.

This is the second release that will follow the (now documented) Skiboot
stable rules - see :ref:`stable-rules`.

Over skiboot-5.2.4, the following fixes are included:

- pflash: Fix the makefile
  (cherry picked from commit fd599965f723330da5ec55519c20cdb6aa2b3a2d)
- pflash: Clean up makefiles and resolve build race
  (cherry picked from commit c327eddd9b291a0e6e54001fa3b1e547bad3fca2)
- FSP/ELOG: Fix OPAL generated elog resend logic
  (cherry picked from commit a6d4a7884e95cb9c918b8a217c11e46b01218358)
- FSP/ELOG: Fix possible event notifier hangs
  (cherry picked from commit e7c8cba4ad773055f390632c2996d3242b633bf4)
- FSP/ELOG: Disable event notification if list is not consistent
  (cherry picked from commit 1fb10de164d3ca034193df81c1f5d007aec37781)
- FSP/ELOG: Improve elog event states
  (cherry picked from commit cec5750a4a86ff3f69e1d8817eda023f4d40c492)
- FSP/ELOG: Fix OPAL generated elog event notification
  (cherry picked from commit ec366ad4e2e871096fa4c614ad7e89f5bb6f884f)
- FSP/ELOG: Disable event notification during kexec
  (cherry picked from commit d2ae07fd97bb9408456279cec799f72cb78680a6)
- hw/xscom: Reset XSCOM engine after querying sleeping core FIR
  (cherry picked from commit 15cec493804ff14e6246eb1b65e9d0c7cb469a81)
- hw/xscom: Reset XSCOM engine after finite number of retries when busy
  (cherry picked from commit e761222593a1ae932cddbc81239b6a7cd98ddb70)
- xscom: Return OPAL_WRONG_STATE on XSCOM ops if CPU is asleep
  (cherry picked from commit 9c2d82394fd2303847cac4a665dee62556ca528a)
- fsp/console: Ignore data on unresponsive consoles
  (cherry picked from commit fd6b71fcc6912611ce81f455b4805f0531699d5e)
- SEL: Fix eSEL ID while logging eSEL event
