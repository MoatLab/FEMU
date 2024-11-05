.. _skiboot-5.5.0:

skiboot-5.5.0
=============

skiboot-5.5.0 was released on Friday April 7th 2017. It is the new stable
release of skiboot, taking over from the 5.4 release, first released on
November 11th 2016.

skiboot-5.5.0 contains all bug fixes as of :ref:`skiboot-5.4.3`
and :ref:`skiboot-5.1.19` (the currently maintained stable releases).

For how the skiboot stable releases work, see :ref:`stable-rules` for details.

This release is a good level set of POWER9 support for bringup activities.
If you are doing bringup, it is strongly suggested you continue to follow
skiboot master.

After skiboot 5.5.0, we move to a regular six week release cycle,
similar to op-build, but slightly offset to allow for a short stabilisation
period. Expected release dates and contents are tracked using GitHub milestone
and issues: https://github.com/open-power/skiboot/milestones

Changes in skiboot-5.5.0
------------------------

See changes in the release candidates:

- :ref:`skiboot-5.5.0-rc1`
- :ref:`skiboot-5.5.0-rc2`
- :ref:`skiboot-5.5.0-rc3`

Changes since skiboot-5.5.0-rc3
-------------------------------

- hdat: parse processor attached i2c devices

  Adds basic parsing for i2c devices that are attached to the processor
  I2C interfaces. This is mainly VPD SEEPROMs.
- libflash/blocklevel: Add blocklevel_smart_erase()

  With recent changes to flash drivers in linux not all erase blocks are
  4K anymore. While most level of the pflash/gard tool stacks were written
  to not mind, it turns out there are bugs which means not 4K erase block
  backing stores aren't handled all that well. Part of the problem is the
  FFS layout that is 4K aligned and with larger block sizes pflash and the
  gard tool don't check if their erase commands are erase block aligned -
  which they are usually not with 64K erase blocks.

  This patch aims to add common functionality to blocklevel so that (at
  least) pflash and the gard tool don't need to worry about the problem
  anymore.
- external/pflash: Use blocklevel_smart_erase()
- external/gard: Use blocklevel_smart_erase()
- libstb/create-container: Add full container build and sign with imprint keys

  This adds support for writing all the public key and signature fields to the
  container header, and for dumping the prefix and software headers so they may
  may be signed, and for signing those headers with the imprint keys.
- asm: do not set SDR1 on POWER9. This register does not exist in ISAv3.

Testing:

- mambo: Allow setting the Linux command line from the environment

  For automated testing it's helpful to be able to set the Linux command
  line via an environment variable.
- mambo: Add util function for breaking on console output


Contributors
------------

Processed 408 csets from 31 developers

3 employers found

A total of 24073 lines added, 16759 removed (delta 7314)

Extending the analysis done for the last few releases, we can see our trends
in code review across versions:

======== ====== ======= ======= ======  ========
Release	 csets	Ack	Reviews	Tested	Reported
======== ====== ======= ======= ======  ========
5.0	 329	 15	     20	     1	       0
5.1	 372	 13	     38	     1	       4
5.2-rc1	 334	 20	     34	     6	      11
5.3-rc1  302     36          53      4         5
5.4.0    361     16          28      1         9
5.5.0    408     11          48     14        10
======== ====== ======= ======= ======  ========

I am absolutely *thrilled* as to the uptick of reviews and tested-by occuring
over our 5.4.0 release. Although we are not yet back up to 5.3 era levels for
review, we're much closer. For tested-by, we've set a new record, which is
excellent!


Developers with the most changesets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
========================== === =======
Developer                    # %
========================== === =======
Benjamin Herrenschmidt     139 (34.1%)
Stewart Smith               60 (14.7%)
Oliver O'Halloran           54 (13.2%)
Gavin Shan                  23 (5.6%)
Michael Neuling             20 (4.9%)
Vasant Hegde                15 (3.7%)
Cyril Bur                   15 (3.7%)
Claudio Carvalho            14 (3.4%)
Andrew Donnellan            11 (2.7%)
Ananth N Mavinakayanahalli   9 (2.2%)
Alistair Popple              6 (1.5%)
Nicholas Piggin              5 (1.2%)
Cédric Le Goater             5 (1.2%)
Pridhiviraj Paidipeddi       5 (1.2%)
Michael Ellerman             4 (1.0%)
Shilpasri G Bhat             4 (1.0%)
Russell Currey               3 (0.7%)
Jack Miller                  2 (0.5%)
Chris Smart                  2 (0.5%)
Dave Heller                  1 (0.2%)
Akshay Adiga                 1 (0.2%)
Reza Arbab                   1 (0.2%)
Matt Brown                   1 (0.2%)
Frederic Barrat              1 (0.2%)
Hank Chang                   1 (0.2%)
Willie Liauw                 1 (0.2%)
Werner Fischer               1 (0.2%)
Jeremy Kerr                  1 (0.2%)
Patrick Williams             1 (0.2%)
Joel Stanley                 1 (0.2%)
Alexey Kardashevskiy         1 (0.2%)
========================== === =======

Developers with the most changed lines
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== ===== =======
Developer                      # %
========================== ===== =======
Oliver O'Halloran          18278 (48.5%)
Benjamin Herrenschmidt      5512 (14.6%)
Cyril Bur                   3184 (8.4%)
Alistair Popple             3102 (8.2%)
Stewart Smith               2757 (7.3%)
Gavin Shan                   802 (2.1%)
Ananth N Mavinakayanahalli   544 (1.4%)
Claudio Carvalho             489 (1.3%)
Dave Heller                  425 (1.1%)
Willie Liauw                 361 (1.0%)
Andrew Donnellan             315 (0.8%)
Michael Neuling              290 (0.8%)
Vasant Hegde                 253 (0.7%)
Shilpasri G Bhat             228 (0.6%)
Nicholas Piggin              222 (0.6%)
Reza Arbab                   198 (0.5%)
Russell Currey               158 (0.4%)
Jack Miller                  127 (0.3%)
Cédric Le Goater             126 (0.3%)
Chris Smart                   95 (0.3%)
Akshay Adiga                  57 (0.2%)
Hank Chang                    56 (0.1%)
Pridhiviraj Paidipeddi        47 (0.1%)
Michael Ellerman              29 (0.1%)
Matt Brown                    29 (0.1%)
Alexey Kardashevskiy           2 (0.0%)
Frederic Barrat                1 (0.0%)
Werner Fischer                 1 (0.0%)
Jeremy Kerr                    1 (0.0%)
Patrick Williams               1 (0.0%)
Joel Stanley                   1 (0.0%)
========================== ===== =======

Developers with the most lines removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
========================== ===== =======
Developer                      # %
========================== ===== =======
Oliver O'Halloran           8516 (50.8%)
Werner Fischer                 1 (0.0%)
========================== ===== =======

Developers with the most signoffs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Total: 364

======================== ===== =======
Developer                    # %
======================== ===== =======
Stewart Smith              348 (95.6%)
Michael Neuling              6 (1.6%)
Oliver O'Halloran            3 (0.8%)
Benjamin Herrenschmidt       2 (0.5%)
Vaidyanathan Srinivasan      1 (0.3%)
Hank Chang                   1 (0.3%)
Jack Miller                  1 (0.3%)
Gavin Shan                   1 (0.3%)
Alistair Popple              1 (0.3%)
======================== ===== =======


Developers with the most reviews
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Total 50

======================== ===== =======
Developer                    # %
======================== ===== =======
Vasant Hegde                14 (28.0%)
Andrew Donnellan             9 (18.0%)
Russell Currey               6 (12.0%)
Cédric Le Goater             5 (10.0%)
Oliver O'Halloran            4 (8.0%)
Vaidyanathan Srinivasan      3 (6.0%)
Gavin Shan                   3 (6.0%)
Alistair Popple              2 (4.0%)
Frederic Barrat              2 (4.0%)
Mahesh Salgaonkar            1 (2.0%)
Cyril Bur                    1 (2.0%)
======================== ===== =======

Developers with the most test credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Total 14

======================== ===== =======
Developer                    # %
======================== ===== =======
Willie Liauw                 4 (28.6%)
Mark E Schreiter             3 (21.4%)
Claudio Carvalho             3 (21.4%)
Gavin Shan                   1 (7.1%)
Michael Neuling              1 (7.1%)
Pridhiviraj Paidipeddi       1 (7.1%)
Chris Smart                  1 (7.1%)
======================== ===== =======

Developers who gave the most tested-by credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Total 14

========================== === =======
Developer                    # %
========================== === =======
Gavin Shan                   7 (50.0%)
Stewart Smith                4 (28.6%)
Chris Smart                  1 (7.1%)
Oliver O'Halloran            1 (7.1%)
Ananth N Mavinakayanahalli   1 (7.1%)
========================== === =======


Developers with the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Total 10

============================ = =======
Developer                    # %
============================ = =======
Hank Chang                   4 (40.0%)
Mark E Schreiter             3 (30.0%)
Guilherme G. Piccoli         1 (10.0%)
Colin Ian King               1 (10.0%)
Pradipta Ghosh               1 (10.0%)
============================ = =======


Developers who gave the most report credits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Total 10

============================ = =======
Developer                    # %
============================ = =======
Gavin Shan                   8 (80.0%)
Andrew Donnellan             1 (10.0%)
Jeremy Kerr                  1 (10.0%)
============================ = =======

Top changeset contributors by employer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================== === =======
Employer                     # %
========================== === =======
IBM                        406 (99.5%)
SuperMicro                   1 (0.2%)
Thomas-Krenn AG              1 (0.2%)
========================== === =======

Top lines changed by employer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

========================= ===== =======
Employer                      # %
========================= ===== =======
IBM                       37329 (99.0%)
SuperMicro                  361 (1.0%)
Thomas-Krenn AG               1 (0.0%)
========================= ===== =======

Employers with the most signoffs
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Total 364

========================= ==== =======
Employer                     # %
========================= ==== =======
IBM                        363 (99.7%)
(Unknown)                    1 (0.3%)
========================= ==== =======

Employers with the most hackers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Total 31

========================= ==== =======
Employer                     # %
========================= ==== =======
IBM                         29 (93.5%)
Thomas-Krenn AG              1 (3.2%)
SuperMicro                   1 (3.2%)
========================= ==== =======
