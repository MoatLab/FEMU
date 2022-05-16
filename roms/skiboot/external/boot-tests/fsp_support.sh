#Number of times to sleep
BOOT_TIMEOUT="20";

#Username/password for for ssh to FSP machines
SSHUSER=${FSPSSHUSER:-}
SSHPASS=${FSPSSHPASS:-}

if [ -z $SSHUSER ] || [ -z $SSHPASS ] ; then
	msg "Set FSPSSHUSER and FSPSSHPASS in ENV or ~/.skiboot_boot_tests"
	exit 1;
fi

export SSHUSER SSHPASS

#IPMI
IPMI_AUTH="-P ${IPMI_PASS:-foo}";

# Strip control characters from IPMI before grepping?
STRIP_CONTROL=1

# How do we SSH in, cp files across?
SSHCMD="sshpass -e ssh -l $SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $target";
REMOTECPCMD="sshpass -e scp -o User=$SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ";

GET_PROFILE='. /etc/profile; test -e /home/dev/.profile && . /home/dev/.profile';

function sshcmd {
	$SSHCMD $*;
}

function is_off {
    state=$($SSHCMD "$GET_PROFILE; smgr mfgState");
    return $([ "$state" = "standby" ]);
}

function poweroff {
    i=0;
    state=$($SSHCMD "$GET_PROFILE; smgr mfgState");
    if [ "$state" = "standby" ]; then
	# already off
	return 0
    fi
    $SSHCMD "$GET_PROFILE; panlexec -f 8";
    msg "Waiting 30 seconds..."
    sleep 30
    state=$($SSHCMD "$GET_PROFILE; smgr mfgState");
    while [ "$state" != "standby" -a "$i" -lt "$BOOT_TIMEOUT" ] ; do
	msg "Waiting $BOOT_SLEEP_PERIOD more seconds..."
	sleep $BOOT_SLEEP_PERIOD;
	i=$(expr $i + 1);
	state=$($SSHCMD "$GET_PROFILE; smgr mfgState");
    done;
    # sleep a little bit longer --- p81 was getting a bit confused.
    sleep 10
    msg "Finishing with state '$state'."
}

function force_primary_side {
    return 0
}

function flash {
	#Make a backup of the current lids
	$REMOTECPCMD $target:/opt/extucode/80f00100.lid 80f00100.lid.bak &&
	$REMOTECPCMD $target:/opt/extucode/80f00101.lid 80f00101.lid.bak &&
	$REMOTECPCMD $target:/opt/extucode/80f00102.lid 80f00102.lid.bak;
	if [ $? -ne 0 ] ; then
		error "Couldn't make backup of currently installed lids";
	fi

	if [ "${LID[0]}" != "" ]; then
	    $REMOTECPCMD ${LID[0]} $target:/opt/extucode/80f00100.lid ||
		error "Error copying lid ${LID[0]}";
	    sum=$(md5sum ${LID[0]} | cut -f 1 -d ' ');
	    $SSHCMD "$GET_PROFILE;
		sumr=\$(md5sum /opt/extucode/80f00100.lid | cut -f 1 -d ' ');
		if [ \"$sum\" != \"\$sumr\" ] ; then
			exit 1;
		fi;" || error "MD5sum doesn't match for ${LID[0]}"

	fi

	if [ "${LID[1]}" != "" ]; then
	    $REMOTECPCMD ${LID[1]} $target:/opt/extucode/80f00101.lid ||
		error "Error copying lid";
	    sum=$(md5sum ${LID[1]} | cut -f 1 -d ' ');
	    $SSHCMD "$GET_PROFILE;
		sumr=\$(md5sum /opt/extucode/80f00101.lid | cut -f 1 -d ' ');
		if [ \"$sum\" != \"\$sumr\" ] ; then
			exit 1;
		fi;" || error "MD5sum doesn't match for ${LID[1]}"
	fi

	if [ "${LID[2]}" != "" ]; then
	    $REMOTECPCMD ${LID[2]} $target:/opt/extucode/80f00102.lid ||
		error "Error copying lid";
	    sum=$(md5sum ${LID[2]} | cut -f 1 -d ' ');
	    $SSHCMD "$GET_PROFILE;
		sumr=\$(md5sum /opt/extucode/80f00102.lid | cut -f 1 -d ' ');
		if [ \"$sum\" != \"\$sumr\" ] ; then
			exit 1;
		fi;" || error "MD5sum doesn't match for ${LID[2]}"
	fi


	$SSHCMD "$GET_PROFILE;
	if [ \$(smgr mfgState) != 'standby' ] ; then
		exit 1;
	fi
	cupdmfg -opt | grep '80f0010'";
	if [ $? -ne 0 ] ; then
		error "Could not install lids on the FSP";
	fi

	sleep 2; #Don't rush the fsp
}

function boot_firmware {
	ISTEP_LOG=$(mktemp --tmpdir builder-1.XXXXXX);
	$SSHCMD "$GET_PROFILE; istep" &> $ISTEP_LOG &
	msg "Waiting 90 seconds for $target to boot";
	sleep 90;
	i=0;
	state=$($SSHCMD "$GET_PROFILE; smgr mfgState");
	while [ \( "$state" != "runtime" \) -a \( "$i" -lt "$BOOT_TIMEOUT" \) ] ; do
		msg "Waiting $BOOT_SLEEP_PERIOD more seconds (istep: `grep iStep $ISTEP_LOG|tail -n 1`)";
		sleep "$BOOT_SLEEP_PERIOD";
		i=$(expr $i + 1);
		state=$($SSHCMD "$GET_PROFILE; smgr mfgState");
	done;

	if [ "$i" -eq "$BOOT_TIMEOUT" ] ; then
		state=$($SSHCMD "$GET_PROFILE; smgr mfgState");
		case "$state" in
			"ipling")
				echo "$target: still hasn't come up but firmware hasn't specifically crashed";
				;;
			"dumping")
				echo "$target: has crashed";
				;;
			"runtime")
				echo "$target: Oops, looks like system has managed to come up...";
				;;
			"standby")
				echo "$target: System is powered off? How can this be?";
				;;
			*)
				echo "$target: is an unknown state '$state'";
				;;
		esac
		echo "$target: istep log";
		cat $ISTEP_LOG;
		rm -rf $ISTEP_LOG
		error "Boot test on $target failed";
	fi
	rm -rf $ISTEP_LOG;
}

function machine_sanity_test {
    sshcmd true;
    if [ $? -ne 0 ]; then
	echo "$target: Failed to SSH to $target..."
        echo "$target: Command was: $SSHCMD true"
	error "Try connecting manually to diagnose the issue."
    fi

    $SSHCMD "$GET_PROFILE; test -d /nfs/bin"
    if [ $? -ne 0 ]; then
	echo "$target: Failed to read /nfs/bin"
	error "Is /nfs mounted on the FSP?"
    fi

    $SSHCMD "$GET_PROFILE; which md5sum > /dev/null && which cupdmfg > /dev/null"
        if [ $? -ne 0 ]; then
	echo "$target: Missing md5sum or cupdmfg on the FSP?"
	error "Is /nfs mounted on the FSP?"
    fi
}
