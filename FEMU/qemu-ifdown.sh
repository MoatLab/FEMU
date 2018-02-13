################################qemu-ifdown.sh
#!/bin/bash
switch=virbr0
if [ -n "$1" ]; then
#shutdown the tap interface
ip link set $1 down
brctl delif $switch $1
ip link set $switch  down
brctl delbr $switch
iptables -t nat -F
exit 0
else
echo "error: no interface specified"
exit 1
fi
