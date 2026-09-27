# Shared Namespace Management

With `femu-subsys,ns_mgmt=on`, the subsystem owns one namespace table,
backend capacity pool and full-geometry FTL per bbssd namespace. This prevents
controllers allocating the same NSID independently or deleting only a private
copy. Realize the subsystem before its controllers. The first controller
establishes the pool and boot namespaces; later controllers join that pool with
no initial attachments. Namespace Attachment selects their active namespaces.

The subsystem retains the first controller's configuration object as the storage
context, independently of its PCI transport lifetime. Its namespace table and
backend survive removal of that controller, including removal of every controller.
They are released at subsystem teardown. Namespace identity and the creation
sequence belong to this context. Controllers must agree on the storage mode and
format capabilities. Runtime construction uses the original storage configuration.

Each controller keeps its own queues, pollers, FTL thread, attachment bitmap and
namespace-change log. Pollers reach the common table through their controller;
active lookup additionally checks that controller's attachment bitmap. A subsystem
mutex serializes data and FTL processing. Existing pause/resume interfaces pause
all controllers in a managed subsystem, so Format, Sanitize and lifecycle changes
cannot race another controller's workers. Delete retires namespace references in
every controller's request containers before releasing storage, without waiting
for guest consumption of a full CQ. Detach retires only the selected controllers.
Reset preserves attachments. Transport removal stops its workers and drops its
attachments without releasing the subsystem's namespaces.

CNS 10h/11h describe the common allocated set. CNS 02h describes the issuing
controller's attachments. CNS 12h lists attached controllers and CNS 13h lists
eligible controllers, in ascending order with inclusive CNTID filtering.
Attach/detach records changes and sends enabled Attached Namespace Attribute
Changed notices on each affected controller. Delete does the same except that
its issuer receives no notice. Allocated Namespace Attribute notices are not
advertised. Create produces a detached namespace and no attached-set notice.

The model is opt-in on the subsystem. Existing standalone management and
unmanaged subsystems retain their behavior. Only homogeneous NoSSD or bbssd is
supported; FDP and Streams remain excluded. Full-geometry bbssd allocation and
its namespace-count cap are retained. Scaled FTL geometry, allocated-namespace
notices, persistent storage and other namespace modes are outside this change.
