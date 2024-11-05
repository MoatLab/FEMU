skiboot-5.1.3
-------------

skiboot-5.1.3 was released on September 15th, 2015.

skiboot-5.1.3 is the 4th stable release of 5.1, it follows skiboot-5.1.2
(which was released September 9th, 2015).

Skiboot 5.1.3 contains all fixes from skiboot-5.1.2 and is a minor bugfix
release.

Changes
^^^^^^^
Over skiboot-5.1.2, we have the following changes:

- slot names for firestone platform
- fix display of LPC errors
- SBE based timer support

  - on supported platforms limits reliance on Linux heartbeat
- fix use-after-free in fsp/ipmi
- fix hang on TOD/TB errors (time-of-day/timebase) on OpenPower systems

  - On getting a Hypervizor Maintenance Interrupt to get the timebase
    back into a running state, we would call prlog which would use
    the LPC UART console driver on OpenPower systems, which depends on
    a working timebase, leading to a hang.
    We now don't depend on a working timebase in this recovery codepath.
- enable prd for garrison platform
- PCI: Clear error bits after changing MPS
  Chaning MPS on PCI upstream bridge might cause error bits set on
  downstream endpoints when system boots into Linux as below case
  shows: ::

   host# lspci -vvs 0001:06:00.0
   0001:06:00.0 Ethernet controller: Broadcom Corporation \
                NetXtreme II BCM57810 10 Gigabit Ethernet (rev 10)
   DevSta:	CorrErr+ UncorrErr- FatalErr- UnsuppReq+ AuxPwr- TransPend-
   CESta:	RxErr- BadTLP- BadDLLP- Rollover- Timeout- NonFatalErr+

  This clears those error bits in AER and PCIe capability after MPS
  is changed. With the patch applied, no more error bits are seen.

Contributors
^^^^^^^^^^^^
Processed 14 csets from 6 developers
1 employers found
A total of 462 lines added, 163 removed (delta 299)

Developers with the most changesets

============================ =========
============================ =========
Benjamin Herrenschmidt       5 (35.7%)
Stewart Smith                4 (28.6%)
Mahesh Salgaonkar            2 (14.3%)
Gavin Shan                   1 (7.1%)
Jeremy Kerr                  1 (7.1%)
Neelesh Gupta                1 (7.1%)
============================ =========

Developers with the most changed lines

========================== ===========
========================== ===========
Benjamin Herrenschmidt     407 (80.8%)
Mahesh Salgaonkar           23 (4.6%)
Gavin Shan                  19 (3.8%)
Stewart Smith               18 (3.6%)
Jeremy Kerr                  5 (1.0%)
Neelesh Gupta                2 (0.4%)
========================== ===========

Developers with the most lines removed

========================== ===========
========================== ===========
Stewart Smith                8 (4.9%)
Jeremy Kerr                  3 (1.8%)
Neelesh Gupta                1 (0.6%)
========================== ===========

Developers with the most signoffs (total 10)

========================== ===========
========================== ===========
Stewart Smith               10 (100.0%)
========================== ===========

Developers with the most reviews (total 1)

========================== ===========
========================== ===========
Joel Stanley                 1 (100.0%)
========================== ===========

Developers with the most test credits (total 0)

Developers who gave the most tested-by credits (total 0)

Developers with the most report credits (total 1)

========================== ===========
========================== ===========
John Walthour                1 (100.0%)
========================== ===========

Developers who gave the most report credits (total 1)

========================== ===========
========================== ===========
Gavin Shan                   1 (100.0%)
========================== ===========

Top changeset contributors by employer

========================== ===========
========================== ===========
IBM                         14 (100.0%)
========================== ===========

Top lines changed by employer

========================== ===========
========================== ===========
IBM                        504 (100.0%)
========================== ===========

Employers with the most signoffs (total 10)

========================== ===========
========================== ===========
IBM                         10 (100.0%)
========================== ===========

Employers with the most hackers (total 6)

========================== ===========
========================== ===========
IBM                          6 (100.0%)
========================== ===========
