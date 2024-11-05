#Number of times to sleep
BOOT_TIMEOUT="5";

#Username/password for ssh to BMC machines
SSHUSER=${SSHUSER:-root};
export SSHPASS=${SSHPASS:-0penBmc};

PFLASH_TO_COPY=${PFLASH_TO_COPY:-}
PFLASH_BINARY=/usr/sbin/pflash

# How do we SSH/SCP in?
SSHCMD="sshpass -e ssh -l $SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $target";

IPMI_AUTH="-P ${IPMI_PASS:-0penBmc}"

# Strip control characters from IPMI before grepping?
STRIP_CONTROL=0

function sshcmd {
	$SSHCMD $*;
}

# remotecp file target target_location
function remotecp {
	sshpass -e scp -o User=$SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $1 $2:$3
}

function is_off {
    return $([ "$($SSHCMD /usr/sbin/obmcutil power|grep 'state')" = "state = 0" ]);
}

function poweroff {
    $SSHCMD /usr/sbin/obmcutil poweroff
    # give it some time
    sleep 5
}

function force_primary_side {
    true
}

function flash {
	if [ ! -z "$PFLASH_TO_COPY" ]; then
		remotecp $PFLASH_TO_COPY $target /tmp/pflash
		$SSHCMD chmod +x /tmp/pflash
		PFLASH_BINARY=/tmp/pflash
	fi
	if [ ! -z "$PNOR" ]; then
		remotecp $PNOR $target /tmp/image.pnor;
	fi
        if [ "${LID[0]}" != "" ]; then
		remotecp ${LID[0]} $target /tmp/skiboot.lid;
	fi
	if [ "${LID[1]}" != "" ]; then
		remotecp ${LID[1]} $target /tmp/bootkernel
	fi
	if [ "${arbitrary_lid[1]}" != "" ]; then
		remotecp ${arbitrary_lid[1]} $target /tmp/$(basename ${arbitrary_lid[1]})
	fi

	if [ "$?" -ne "0" ] ; then
		error "Couldn't copy firmware image";
	fi

	if [ ! -z "$PNOR" ]; then
		msg "Flashing full PNOR"
		$SSHCMD "$PFLASH_BINARY -E -f -p /tmp/image.pnor"
		if [ "$?" -ne "0" ] ; then
			error "An unexpected pflash error has occurred";
		fi
		msg "Removing /tmp/image.pnor"
		$SSHCMD "rm /tmp/image.pnor"
	fi

	if [ ! -z "${LID[0]}" ] ; then
		msg "Flashing PAYLOAD PNOR partition"
		$SSHCMD "$PFLASH_BINARY -e -f -P PAYLOAD -p /tmp/skiboot.lid"
		if [ "$?" -ne "0" ] ; then
                        error "An unexpected pflash error has occurred";
		fi
		msg "Removing /tmp/pskiboot.lid"
		$SSHCMD "rm /tmp/skiboot.lid"
	fi

        if [ ! -z "${LID[1]}" ] ; then
                msg "Flashing BOOTKERNEL PNOR partition"
                $SSHCMD "$PFLASH_BINARY -e -f -P BOOTKERNEL -p /tmp/bootkernel"
                if [ "$?" -ne "0" ] ; then
                        error "An unexpected pflash error has occurred";
		fi
		msg "Removing /tmp/bootkernel"
		$SSHCMD "rm /tmp/bootkernel"
        fi

	if [ ! -z "${arbitrary_lid[0]}" -a ! -z "${arbitrary_lid[1]}" ] ; then
		msg "Flashing ${arbitrary_lid[0]} PNOR partition"
		$SSHCMD "$PFLASH_BINARY -e -f -P ${arbitrary_lid[0]} -p /tmp/$(basename ${arbitrary_lid[1]})"
                if [ "$?" -ne "0" ] ; then
                        error "An unexpected pflash error has occurred";
		fi
		msg "Removing /tmp/$(basename ${arbitrary_lid[1]})"
		$SSHCMD "rm /tmp/$(basename ${arbitrary_lid[1]})"
	fi

}

function boot_firmware {
    	$SSHCMD /usr/sbin/obmcutil poweron
	i=0;
	while [ "$($SSHCMD /usr/sbin/obmcutil power|grep state)" = "state = 0" -a \( "$i" -lt "$BOOT_TIMEOUT" \) ] ; do
		msg -n ".";
		sleep $BOOT_SLEEP_PERIOD;
		i=$(expr $i + 1);
	done
	if [ "$i" -eq "$BOOT_TIMEOUT" ] ; then
		error "Couldn't power on $target";
	fi
}

function machine_sanity_test {
    sshcmd true;
    if [ $? -ne 0 ]; then
	echo "$target: Failed to SSH to $target..."
        echo "$target: Command was: $SSHCMD true"
	error "Try connecting manually to diagnose the issue."
    fi
    # No further sanity tests for BMC machines.
    true
}
