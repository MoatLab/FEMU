GCOV for skiboot
================

Unit tests
----------
All unit tests are built+run with gcov enabled. ::

 make coverage-report

will generate a unit test coverage report like:
http://open-power.github.io/skiboot/coverage-report/

Skiboot
-------
You can now build Skiboot itself with gcov support, boot it on a machine,
do things, and then extract out gcda files to generate coverage reports
from real hardware (or a simulator).

Building Skiboot with GCOV
--------------------------
::

  SKIBOOT_GCOV=1 make

You may need to ``make clean`` first.

This will build a skiboot lid roughly *twice* the size.

Flash/Install the skiboot.lid and boot.

Extracting GCOV data
--------------------
The way we extract the gcov data from a system is by dumping the contents
of skiboot memory and then parsing the data structures in user space with
the extract-gcov utility in the skiboot repo.

mambo: ::

  mysim memory fwrite 0x30000000 0x240000 skiboot.dump

FSP: ::

  getmemproc 30000000 3407872 -fb skiboot.dump

linux (e.g. petitboot environment): ::

  dd if=/proc/kcore skip=1572864 count=6656  of=skiboot.dump

You basically need to dump out the first 3MB of skiboot memory.

Then you need to find out where the gcov data structures are: ::

  perl -e "printf '0x%x', 0x30000000 + 0x`grep gcov_info_list skiboot.map|cut -f 1 -d ' '`"

That address needs to be supplied to the extract-gcov utility: ::

  ./extract-gcov skiboot.dump 0x3023ec40

Once you've run extract-gcov, it will have extracted the gcda files
from the skiboot memory image.

You can then run lcov: ::

  lcov -b . -q -c -d . -o skiboot-boot.info
  --gcov-tool
  /opt/cross/gcc-4.8.0-nolibc/powerpc64-linux/bin/powerpc64-linux-gcov

*IMPORTANT* you should point lcov to the gcov for the compiler you used
to build skiboot, otherwise you're likely to get errors.


