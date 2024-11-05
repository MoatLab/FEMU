#Number of times to sleep
BOOT_TIMEOUT="5";

#Username/password for ssh to BMC machines
SSHUSER=${SSHUSER:-ADMIN};
export SSHPASS=${SSHPASS:-ADMIN};

#Username/password for IPMI
IPMI_AUTH="-U ${IPMI_USER:-ADMIN} -P ${IPMI_PASS:-ADMIN}"
PFLASH_TO_COPY=${PFLASH_TO_COPY:-}
PFLASH_BINARY=/tmp/pflash

# Strip control characters from IPMI before grepping?
STRIP_CONTROL=0

# How do we SSH/SCP in?
SSHCMD="sshpass -e ssh -l $SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $target";

function sshcmd {
    # because BMC:
    $IPMI_COMMAND $SMC_PRESSHIPMICMD;
    expect -c "spawn $SSHCMD" -c "set timeout 600" -c "expect \"#\" { send \"$*\\r\" }" -c 'expect "#" { send "exit\r" }' -c 'wait';
}

# remotecp file target target_location
function remotecp {
    rsync -av $1 rsync://$2/files/$3
}

function is_off {
    return $([ "$($IPMI_COMMAND chassis power status)" = "Chassis Power is off" ]);
}

function poweroff {
    $IPMI_COMMAND chassis power off
    # give it some time
    sleep 10
}

function force_primary_side {
    true
}

function flash {
	if [ ! -z "$PFLASH_TO_COPY" ]; then
		remotecp $PFLASH_TO_COPY $target pflash
		sshcmd chmod +x /tmp/rsync_file/pflash
		PFLASH_BINARY=/tmp/rsync_file/pflash
	fi
	if [ ! -z "$PNOR" ]; then
		remotecp $PNOR $target image.pnor;
	fi
        if [ "${LID[0]}" != "" ]; then
		remotecp ${LID[0]} $target skiboot.lid;
	fi
	if [ "${LID[1]}" != "" ]; then
		remotecp ${LID[1]} $target bootkernel
	fi
	if [ "${arbitrary_lid[1]}" != "" ]; then
		remotecp ${arbitrary_lid[1]} $target $(basename ${arbitrary_lid[1]})
	fi

	if [ "$?" -ne "0" ] ; then
		error "Couldn't copy firmware image";
	fi

	# flash it
	if [ ! -z "$PNOR" ]; then
		msg "Flashing full PNOR"
		sshcmd "$PFLASH_BINARY -E -f -p /tmp/rsync_file/image.pnor"
		if [ "$?" -ne "0" ] ; then
			error "An unexpected pflash error has occurred";
		fi
		msg "Removing /tmp/rsync_file/image.pnor"
		sshcmd "rm /tmp/rsync_file/image.pnor"
	fi

	if [ ! -z "${LID[0]}" ] ; then
		msg "Flashing PAYLOAD PNOR partition"
		sshcmd "$PFLASH_BINARY -e -f -P PAYLOAD -p /tmp/rsync_file/skiboot.lid"
		if [ "$?" -ne "0" ] ; then
                        error "An unexpected pflash error has occurred";
		fi
		msg "Removing /tmp/rsync_file/skiboot.lid"
		sshcmd "rm /tmp/skiboot.lid"
	fi

        if [ ! -z "${LID[1]}" ] ; then
                msg "Flashing BOOTKERNEL PNOR partition"
                sshcmd "$PFLASH_BINARY -e -f -P BOOTKERNEL -p /tmp/rsync_file/bootkernel"
                if [ "$?" -ne "0" ] ; then
                        error "An unexpected pflash error has occurred";
		fi
		msg "Removing /tmp/rsync_file/bootkernel"
		sshcmd "rm /tmp/rsync_file/bootkernel"
        fi

	if [ ! -z "${arbitrary_lid[0]}" -a ! -z "${arbitrary_lid[1]}" ] ; then
		msg "Flashing ${arbitrary_lid[0]} PNOR partition"
		sshcmd "$PFLASH_BINARY -e -f -P ${arbitrary_lid[0]} -p /tmp/rsync_file/$(basename ${arbitrary_lid[1]})"
                if [ "$?" -ne "0" ] ; then
                        error "An unexpected pflash error has occurred";
		fi
		msg "Removing /tmp/rsync_file/$(basename ${arbitrary_lid[1]})"
		sshcmd "rm /tmp/rsync_file/$(basename ${arbitrary_lid[1]})"
	fi

	msg "Clearing mboxd caches..."
	sshcmd "/bin/mboxctl --clear-cache"
}

function boot_firmware {
    	$IPMI_COMMAND chassis power on > /dev/null;
	i=0;
	while [ "$($IPMI_COMMAND chassis power status)" = "Chassis Power is off" -a \( "$i" -lt "$BOOT_TIMEOUT" \) ] ; do
		msg -n ".";
		sleep $BOOT_SLEEP_PERIOD;
		i=$(expr $i + 1);
	done
	if [ "$i" -eq "$BOOT_TIMEOUT" ] ; then
		error "Couldn't power on $target";
	fi
}

function machine_sanity_test {
    # No further sanity tests for BMC machines.
    true
}
