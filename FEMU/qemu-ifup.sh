################################qemu-ifup.sh
#!/bin/bash
switch=virbr0
if [ -n "$1" ]; then
#create a tap interface
#tunctl -u $(whoami) -t $1
#start up the tap interface
ip link set $ up
sleep 1
#add tap interface to the bridge
brctl addif ${switch} $1
exit 0
else
echo "error: no interface specified"
exit 1
fi
################################qemu-ifdown.sh
#!/bin/bash
switch=br0
if [ -n "$1" ]; then
#delete the specified interface
tunctl -d $1
#rlease tap interface from bridge
brctl delif $(switch) $1
#shutdown the tap interface
ip link set $1 down
exit 0
else
echo "error: no interface specified"
exit 1
fi
