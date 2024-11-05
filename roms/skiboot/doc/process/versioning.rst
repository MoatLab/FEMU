.. _versioning:

Versioning Scheme of skiboot
============================

History
-------
For roughly the first six months of public life, skiboot just presented a
git SHA1 as a version "number". This was "user visible" in two places:

1. ``/sys/firmware/opal/msglog``
   the familiar ``SkiBoot 71664fd-dirty starting...`` message
2. device tree:
   ``/proc/device-tree/ibm,opal/firmware/git-id``

Builds were also referred to by date and by corresponding PowerKVM release.
Clearly, this was unlikely to be good practice going forward.

As of skiboot-4.0, this scheme has changed and we now present a version
string instead. This better addresses the needs of everybody who is building
OpenPower systems.


Current practice
----------------
The version string is constructed from a few places and is designed to
be *highly* informative about what you're running. For the most part,
it should be automatically constructed by the skiboot build system. The
only times you need to do something is if you are a) making an upstream
skiboot release or b) building firmware to release for your platform(s).

OPAL/skiboot has several consumers, for example:

* IBM shipping POWER8 systems with an FSP (FW810.XX and future)
* OpenPower
* OpenPower partners manufacturing OpenPower systems
* developers, test and support needing to understand what code a system
  is running

and there are going to be several concurrent maintained releases in the wild,
likely build by different teams of people at different companies.

tl;dr; is you're likely going to see version numbers like this (for the
hypothetical platforms 'ketchup' and 'mustard'):

* ``skiboot-4.0-ketchup-0``
* ``skiboot-4.0-ketchup-1``
* ``skiboot-4.1-mustard-4``
* ``skiboot-4.1-ketchup-0``

If you see *extra* things on the end of the version, then you're running
a custom build from a developer
(e.g. ``skiboot-4.0-1-g23f147e-stewart-dirty-f42fc40`` means something to
us - explained below).

If you see less, for example ``skiboot-4.0``, then you're running a build
directly out of the main git tree. Those producing OPAL builds for users
must *not* ship like this, even if the tree is identical.

Here are the components of the version string from master: ::

 skiboot-4.0-1-g23f147e-debug-occ-stewart-dirty-f42fc40
 ^       ^^^ ^  ^^^^^^^ ^-------^    ^      ^   ^^^^^^^
 |        |  |     |        |        |      |      |
 |        |  |     |        |         \    /        - 'git diff|sha1sum'
 |        |  |     |        |          \  /
 |        |  |     |        |            - built from a dirty tree of $USER
 |        |  |     |        |
 |        |  |     |         - $EXTRA_VERSION (optional)
 |        |  |     |
 |        |  |      - git SHA1 of commit built
 |        |  |
 |        |   - commits head of skiboot-4.0 tag
 |        |
 |         - skiboot version number ---\
 |                                      >--  from  the 'skiboot-4.0' git tag
  - product name (always skiboot)   ---/


When doing a release for a particular platform, you are expected to create
and tag a branch from master. For the (hypothetical) ketchup platform which
is going to do a release based on skiboot-4.0, you would create a tag
'skiboot-4.0-ketchup-0' pointing to the same revision as the 'skiboot-4.0' tag
and then make any additional modifications to skiboot that were not in the 4.0
release. So, you could ship a skiboot with the following version string: ::

 skiboot-4.0-ketchup-1
 ^       ^^^ ^       ^
 |        |  |       |
 |        |  |        - revision for this platform
 |        |  |      
 |        |  |
 |        |   - Platform name/version
 |        |
 |         - skiboot version number
 |
  - product name (always skiboot)

This version string tells your users to expect what is in skiboot-4.0 plus
some revisions for your platform.


Practical Considerations
------------------------

You MUST correctly tag your git tree for sensible version numbers to be
generated. Look at the (generated) version.c file to confirm you're building
the correct version number. You will need annotated tags (git tag -a).

If your build infrastructure does *not* build skiboot from a git tree, you
should specify SKIBOOT_VERSION as an environment variable (following this
versioning scheme), otherwise the build will fail.
