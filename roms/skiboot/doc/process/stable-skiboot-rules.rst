.. _stable-rules:

======================================
Skiboot stable tree rules and releases
======================================

If you're at all familiar with the Linux kernel stable trees, this should
seem fairly familiar.

The purpose of a -stable tree is to give vendors a stable base to create
firmware releases from and to incorporate into service packs. New stable
releases contain critical fixes only.

As a general rule, on the most recent skiboot release gets a maintained
-stable tree. If you wish to maintain an older tree, speak up! For example,
with my IBMer hat on, we'll maintain branches that we ship in products.

What patches are accepted?
--------------------------

* Patches must be obviously correct and tested

  * A Tested-by signoff is *important*
* A patch must fix a real bug
* No trivial patches, such fixups belong in main branch
* Not fix a purely theoretical problem unless you can prove how
  it's exploitable
* The patch, or an equivalent one, must already be in master

  * Submitting to both at the same time is okay, but backporting is better

HOWTO submit to stable
----------------------
Two ways:

1. Send patch to the skiboot-stable@lists.ozlabs.org list with
   "[PATCH <stable version>]" in subject

   * This targets the patch *ONLY* to the stable branch.

     * Such commits will *NOT* be merged into master.
   * Use this when:

     a. cherry-picking a fix from master
     b. fixing something that is only broken in stable
     c. fix in stable needs to be completely different than in master

     If b or c: explain why.
   * If cherry-picking, include the following at the top of your
     commit message: ::

       commit <sha1> upstream.
   * If the patch has been modified, explain why in description.

2. Add "Cc: skiboot-stable@lists.ozlabs.org" above your Signed-off-by line
   when sending to skiboot@

   * This targets the patch to master and stable.
   * You can target a patch to a specific stable tree with: ::

      Cc: skiboot-stable@lists.ozlabs.org # 5.1.x

     and that will target it to the 5.1.x branch.
   * You can ask for prerequisites to be cherry-picked: ::

        Cc: skiboot-stable@lists.ozlabs.org # 5.1.x 55ae15b Ensure we run pollers in cpu_wait_job()
        Cc: skiboot-stable@lists.ozlabs.org # 5.1.x

     Which means:

       1. please ``git cherry-pick 55ae15b``
       2. then apply this patch to 5.1.x".

Trees
-----

* https://github.com/open-power/skiboot/ (or via ssh at ``git@github.com:open-power/skiboot.git`` )

  * (branches are skiboot-X.Y.x - e.g. skiboot-5.1.x)

* Some stable versions may last longer than others

  * So there may be skiboot-5.1.x and skiboot-5.2.x actively maintained
    and skiboot-5.1.x could possibly outlast skiboot-5.2.x
