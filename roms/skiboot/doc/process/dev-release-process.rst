.. _release-process:

Development and Release Process
===============================

Skiboot follows the release cycle of `op-build`, so that each new op-build
has a new stable skiboot. Currently, this means that we release once every
six weeks (or so). Our *goal* is to have roughly the first 4 weeks of a
6 week cycle open for merging new features, and reserving the final two
weeks for stabilisation efforts after the first -rcX release.

It is *strongly* preferred to have new features (especially new APIs and
device tree bindings) to come in *early* in the cycle.

Once the final release is cut, the :ref:`stable-rules` process takes over.

Our process has evolved, and will so into the future. It's inspired by the
Linux process, but not a slave to it. For example, there is currently not
the volume of patches to justify a next tree.

Here's how some of the recent (at time of writing) releases have gone:

============= =========
Date          Release
============= =========
Oct 31st 2017 v5.9
Feb 6th 2018  v5.10-rc1
Feb 9th 2018  v5.10-rc2
Feb 15th 2018 v5.10-rc3
Feb 21st 2018 v5.10-rc4
Feb 23rd 2018 v5.10
Mar 28th 2018 v5.11-rc1
Apr 6th 2018  v5.11
============= =========

Lifecycle of a patch
--------------------

Roughly speaking, a patch has the following lifecycle:

- Design

  It is best to do design work in the open, although sometimes this is hard
  when upcoming unannounced hardware is involved. Often, it can be useful to
  post an RFC design or patch to encourage discussion. This is especially
  useful when designing new OPAL APs or device tree bindings. Never be afraid
  to send a patch (or series of patches) as RFC (Request for Comment) with
  whatever disclaimer you deem appropriate.

  Once you have a design, sharing it is an important part of the process of
  getting the applicable code upstream. Different perspectives are important
  in coming to elegant solutions, as is having more than one person understand
  the reasoning behind design decisions.
- Review and Test

  Once you think your patch is a state suitable for merging, send it to the
  mailing list for others to review and test. Using `git format-patch` and
  `git send-email` is good practice to ensure your patches survive being sent
  to the list. Ensure you have followed `CONTRIBUTING.md` and have your
  Signed-off-by present on your patches (`git commit -s` will add this for you).

  It is good practice to solicit review from an expert in the area of code
  you're modifying. A reviewer will add their Reviewed-by or Acked-by tags as
  replies, as will anybody testing it add Tested-by. The aim of reviewing and
  testing code before we merge it is to limit any problems to the smallest
  number of people possible, only merging code we are collectively confident
  that will *improve* life for all users and developers.
- Merged to master

  The maintainer as merged your patches to the development tree (the 'master'
  git branch). Soon after this, many more people are going to be running your
  code, so good review and testing helps ensure your inbox isn't flooded with
  bug reports.

  If your patch has also been sent to the stable tree, it's possible it also
  gets merged there soonafter.
- Stable release

  Once a stable release is made, it's likely that your code makes its way into
  vendor's firmware releases via their test cycles.
- Bug fixes and maintenance

  Bugs are a fact of life, sometimes in our own code, sometimes in others, and
  sometimes in hardware. After your patch is accepted, being available for
  input on possible bugs found and possible fixes is invaluable so that all
  can ship high quality firmware.


On closed source branches and forks
-----------------------------------

Even though the license that skiboot is distributed under does *allow* you
to keep your changes private, we (the skiboot developers) cannot in any way
provide support on the resulting code base.

Additionally, the broader PowerPC Linux community has neither the capacity,
time, or resources to support Linux running on such closed source forks.
The kernel developers have said that patches to the kernel to support or
work around closed skiboot changes will *not* be accepted upstream.

If you keep your changes private, you are *entirely* on your own.

License
-------

Skiboot is licensed under the Apache 2.0 license (see the LICENSE file in the
source tree for the full text).

Portions (e.g. our libc, CCAN modules we use) are made available under a CC0, BSD,
or BSD-MIT license (see LICENSE files for specifics).
