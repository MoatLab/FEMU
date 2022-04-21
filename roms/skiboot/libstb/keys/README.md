# Important Information About Secure and Trusted Boot And Signing Keys

## Background

IBM P8 OpenPOWER systems support a limited set of Secure and Trusted Boot
functionality.  Secure Boot implements a processor based chain of trust.  The
chain starts with an implicitly trusted component with other components being
authenticated and integrity checked before being executed on the host processor
cores.  At the root of this trust chain is the Host Platform Core Root of Trust
for Measurement (CRTM).  Immutable Read Only Memory (ROM - fixed in the POWER
processor chip) verifies the initial firmware load.  That firmware verifies
cryptographic signatures on all subsequent "to be trusted" firmware that is
loaded for execution on the P8 cores.  Trusted Boot also makes use of this same
CRTM by measuring and recording FW images via a Trusted Platform Module (TPM)
before control is passed on to the next layer in the boot stack.  The CRTM
design is based on a Public Key Infrastructure (PKI) process to validate the
firmware images before they are executed.  This process makes use of a set of
hardware and firmware asymmetric keys.  Multiple organizations will want to
deliver POWER hardware, digitally signed firmware, signed boot code,
hypervisors, and operating systems.  Each platform manufacturer wants to
maintain control over its own code and sign it with its own keys.  A single key
hash is stored in host processor module SEEPROM representing the anchoring root
set of hardware keys.  The P8 Trusted Boot supports a key management flow that
makes use of two kinds of hardware root keys, a wide open, well-known, openly
published public/private key pair (imprint keys) and a set of production keys
where the private key is protected by a hardware security module (HSM) internal
to the manufacturing facility of the key owner.

## Purpose Of Imprint Public/Private Keys

It is critical to note that the imprint keys are not to be used for production.
These are strictly for manufacturing and development level support given the
open nature of the private part of the Hardware keys.  This allows developers
and testers to sign images and create builds for Secure and Trusted Boot
development lab testing.  Systems must be transitioned to production level
keys for customer environments.

## Manufacturer Key Management Role

If a system is shipped from the System Manufacturer with imprint keys installed
rather than production level hardware keys, the system must be viewed as running
with a set of well-known default keys and vulnerable to exploitation.  The
System Access Administrator must work with the System Manufacturer to insure
that a key transition process is utilized once a hardware based chain of trust
is to be enabled as part of Secure or Trusted Boot functionality.

## Intentional Public Release Of Imprint Public/Private Keys

All public and private keys in this directory are being intentionally released
to enable the developer community to sign code images.  For true security, a
different set of production signing keys should be used, and the private
production signing key should be carefully guarded.  Currently, we do not yet
support production key signing, only development signing.

### Imprint Private Keys

#### Hardware Private Keys

The following files contain the Imprint private keys, in PEM format:

hw_key_a.key
hw_key_b.key
hw_key_c.key

#### Software Private Keys

The project does not contain any Software keys.  The sample scripts reuse the
Hardware keys where input is required for the Software keys.  To generate your
own software keys use the openssl "ecparam" command.  The following commands
will generate private software keys P, Q and R:

$ openssl ecparam -genkey -outform pem -noout -name secp521r1 -out sw_key_p.key
$ openssl ecparam -genkey -outform pem -noout -name secp521r1 -out sw_key_q.key
$ openssl ecparam -genkey -outform pem -noout -name secp521r1 -out sw_key_r.key

OpenPOWER secure boot supports three keys for Hardware (HW) key signing and (up
to) three keys for Software (SW) key signing,  This permits a "separation of
duties" in the firmware signing process, if such a separation is desired.  All
three HW keys are required, but the SW keys allow for the use of one, two or
three keys.  A signature is required (i.e. must be present in the container) by
*all three* firmare keys, and by every (1-3) SW key in use, to create a
container that will boot with secure mode on.  If a separation of duties is not
required, the signer may use the same key for all three required HW keys, and
for the (1-3) required SW keys.  The container will boot as long as all required
signatures are present.

#### Hardware and Software Public Keys

The public keys can be easily extracted from the private keys.  Use the openssl
"pkey" command, for example:

$ openssl pkey -pubout -inform pem -outform pem -in sw_key_p.key -out sw_key_p.pub

To build and sign a container locally, the public keys are not required.  The
signing tool will automatically extract the public key from the private key (for
inclusion in the container) and will use the private key to create the required
signatures.

The recommended process for production keys is to not have the private keys
present on thy system used to build firmware.  In this mode you want to create
the signatures independently from the op-build process.  Create your private HW
and SW keys as described above.  Protect the private portion of the key (the
private key).  Add the public portion of the key (the public key) to ./keys
directory.  The signing tool will use the public key to populate the container.

In this mode of operation you must sign the Prefix header and Software header
with the HW and SW keys, respectively.  TODO: Instructions to follow.

#### Hardware Keys Hash

As mentioned above, a single key hash is stored in host processor module SEEPROM
representing the anchoring root set of HW keys.  This is a 64 byte, SHA512 hash
of the three HW keys.  On a running OpenPOWER machine this hash may be read from
an entry in the device tree:

# cat /proc/device-tree/ibm,secureboot/hw-key-hash | xxd -p
40d487ff7380ed6ad54775d5795fea0de2f541fea9db06b8466a42a320e6
5f75b48665460017d907515dc2a5f9fc50954d6ee0c9b67d219dfb708535
1d01d6d1

Note this file is readable both from the target OS and the petitboot shell
environment.

OpenPOWER secure boot protects the containerized firmware by comparing this hash
to the hash of the HW public keys in the container (as well as verifying the
signatures, of course).  If the hashes don't match, the machine won't boot.  For
this reason you might want to check that the HW keys hash will be correct in
container you are building.

To check the hash of your HW keys, run the "create-container" tool from the
sb-signing-utils project.  This command will create no container, but will
display the SHA512 hash of the input keys:

$ create-container -v -w0 -a /tmp/keys/hw_key_a.key \
                          -b /tmp/keys/hw_key_b.key \
                          -c /tmp/keys/hw_key_c.key \
                          --payload /dev/zero --imagefile /dev/null \
                          | grep "HW keys hash"

HW keys hash = 40d487ff7380ed6a...

Note this command will work with either public or private keys as input.  The
tool will also display the hash during normal container creation, when the
program is run in verbose mode.

To check the hash of the HW keys in an existing container, run the
"print-container" tool: TODO
