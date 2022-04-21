#!/bin/bash

PAYLOAD=$1
OUTPUT=$2

if [ ! -f $PAYLOAD ]; then
	echo "Can't read PAYLOAD";
	exit 1;
fi

KEYLOC=$3
LABEL=$4

T=$(mktemp -d)
LABEL_ARG=""
if [ ! -z "$LABEL" ]; then
	LABEL_ARG="-L $LABEL"
fi

# Build enough of the container to create the Prefix and Software headers.
# (reuse HW key for SW key P)
./libstb/create-container -a $KEYLOC/hw_key_a.key -b $KEYLOC/hw_key_b.key -c $KEYLOC/hw_key_c.key \
                   -p $KEYLOC/hw_key_a.key \
                    --payload $PAYLOAD --imagefile $OUTPUT $LABEL_ARG \
                    --dumpPrefixHdr $T/prefix_hdr --dumpSwHdr $T/software_hdr

# Sign the Prefix header.
openssl dgst -SHA512 -sign $KEYLOC/hw_key_a.key $T/prefix_hdr > $T/hw_key_a.sig
openssl dgst -SHA512 -sign $KEYLOC/hw_key_b.key $T/prefix_hdr > $T/hw_key_b.sig
openssl dgst -SHA512 -sign $KEYLOC/hw_key_c.key $T/prefix_hdr > $T/hw_key_c.sig

# Sign the Software header.
openssl dgst -SHA512 -sign $KEYLOC/hw_key_a.key $T/software_hdr > $T/sw_key_p.sig

# Build the full container with signatures.
./libstb/create-container -a $KEYLOC/hw_key_a.key -b $KEYLOC/hw_key_b.key -c $KEYLOC/hw_key_c.key \
                   -p $KEYLOC/hw_key_a.key $LABEL_ARG \
                   -A $T/hw_key_a.sig -B $T/hw_key_b.sig -C $T/hw_key_c.sig \
                   -P $T/sw_key_p.sig \
                    --payload $PAYLOAD --imagefile $OUTPUT

rm -rf $T
