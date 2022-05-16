Contributing to skiboot
=======================

skiboot is OPAL (OpenPOWER Abstraction Layer) boot and runtime firmware for
POWER.

If you haven't already, join us on IRC (#openpower on Freenode) and on
the mailing list ( skiboot@lists.ozlabs.org - subscribe by
going to https://lists.ozlabs.org/listinfo/skiboot )

While we do use GitHub Issues, patches are accepted via the mailing list.
We expect participants to adhere to the GitHub Community Guidelines (found
at https://help.github.com/articles/github-community-guidelines/ ).

All contributions should have a Developer Certificate of Origin (see below).

Development Environment
-----------------------

A host GCC of at least 4.9 is recommended (all modern Linux distributions
provide this).

You can build on x86-64, ppc64 or ppc64le, you just need a powerpc64 (BE)
cross compiler. The powerpc64le cross compilers packaged in Linux distributions
can build BE code, so they are fine.

Developer Certificate of Origin
-------------------------------

Contributions to this project should conform to the `Developer Certificate
of Origin` as defined at http://elinux.org/Developer_Certificate_Of_Origin.
Commits to this project need to contain the following line to indicate
the submitter accepts the DCO:
```
Signed-off-by: Your Name <your_email@domain.com>
```
By contributing in this way, you agree to the terms as follows:
```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```


