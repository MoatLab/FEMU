==========================
Contributing to libvirt-ci
==========================

The libvirt CI project accepts code contributions via merge requests
on the GitLab project:

https://gitlab.com/libvirt/libvirt-ci/-/merge_requests

It is required that automated CI pipelines succeed before a merge request
will be accepted. The global pipeline status for the ``master`` branch is
visible at:

https://gitlab.com/libvirt/libvirt-ci/pipelines

CI pipeline results for merge requests will be visible via the contributors'
own private repository fork:

https://gitlab.com/yourusername/libvirt-ci/pipelines

Contributions submitted to the project must be in compliance with the
Developer Certificate of Origin Version 1.1. This is documented at:

https://developercertificate.org/

To indicate compliance, each commit in a series must have a "Signed-off-by"
tag with the submitter's name and email address. This can be added by passing
the ``-s`` flag to ``git commit`` when creating the patches.
