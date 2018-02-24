#!/bin/bash
# Huaicheng <huaicheng@cs.uchicago.edu>
# Tuning script for low latencies

# turn off unrelated services
{
sudo /etc/init.d/nfs-kernel-server stop
sudo /etc/init.d/libvirt-bin stop
sudo /etc/init.d/mdadm stop
sudo service cron stop
#sudo /etc/init.d/rpcbind stop
sudo /etc/init.d/atd stop
} 2>&1 > /dev/null
