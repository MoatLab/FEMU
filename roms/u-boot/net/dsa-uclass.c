// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2019-2021 NXP
 */

#include <net/dsa.h>
#include <dm/lists.h>
#include <dm/device_compat.h>
#include <dm/device-internal.h>
#include <dm/uclass-internal.h>
#include <linux/bitmap.h>
#include <miiphy.h>

#define DSA_PORT_CHILD_DRV_NAME "dsa-port"

/* per-device internal state structure */
struct dsa_priv {
	struct phy_device *cpu_port_fixed_phy;
	struct udevice *master_dev;
	int num_ports;
	u32 cpu_port;
	int headroom;
	int tailroom;
};

/* external API */
int dsa_set_tagging(struct udevice *dev, ushort headroom, ushort tailroom)
{
	struct dsa_priv *priv;

	if (!dev)
		return -EINVAL;

	if (headroom + tailroom > DSA_MAX_OVR)
		return -EINVAL;

	priv = dev_get_uclass_priv(dev);

	if (headroom > 0)
		priv->headroom = headroom;
	if (tailroom > 0)
		priv->tailroom = tailroom;

	return 0;
}

/* returns the DSA master Ethernet device */
struct udevice *dsa_get_master(struct udevice *dev)
{
	struct dsa_priv *priv;

	if (!dev)
		return NULL;

	priv = dev_get_uclass_priv(dev);

	return priv->master_dev;
}

/*
 * Start the desired port, the CPU port and the master Eth interface.
 * TODO: if cascaded we may need to _start ports in other switches too
 */
static int dsa_port_start(struct udevice *pdev)
{
	struct udevice *dev = dev_get_parent(pdev);
	struct dsa_priv *priv = dev_get_uclass_priv(dev);
	struct udevice *master = dsa_get_master(dev);
	struct dsa_ops *ops = dsa_get_ops(dev);
	int err;

	if (ops->port_enable) {
		struct dsa_port_pdata *port_pdata;

		port_pdata = dev_get_parent_plat(pdev);
		err = ops->port_enable(dev, port_pdata->index,
				       port_pdata->phy);
		if (err)
			return err;

		err = ops->port_enable(dev, priv->cpu_port,
				       priv->cpu_port_fixed_phy);
		if (err)
			return err;
	}

	return eth_get_ops(master)->start(master);
}

/* Stop the desired port, the CPU port and the master Eth interface */
static void dsa_port_stop(struct udevice *pdev)
{
	struct udevice *dev = dev_get_parent(pdev);
	struct dsa_priv *priv = dev_get_uclass_priv(dev);
	struct udevice *master = dsa_get_master(dev);
	struct dsa_ops *ops = dsa_get_ops(dev);

	if (ops->port_disable) {
		struct dsa_port_pdata *port_pdata;

		port_pdata = dev_get_parent_plat(pdev);
		ops->port_disable(dev, port_pdata->index, port_pdata->phy);
		ops->port_disable(dev, priv->cpu_port, NULL);
	}

	eth_get_ops(master)->stop(master);
}

/*
 * Insert a DSA tag and call master Ethernet send on the resulting packet
 * We copy the frame to a stack buffer where we have reserved headroom and
 * tailroom space.  Headroom and tailroom are set to 0.
 */
static int dsa_port_send(struct udevice *pdev, void *packet, int length)
{
	struct udevice *dev = dev_get_parent(pdev);
	struct dsa_priv *priv = dev_get_uclass_priv(dev);
	int head = priv->headroom, tail = priv->tailroom;
	struct udevice *master = dsa_get_master(dev);
	struct dsa_ops *ops = dsa_get_ops(dev);
	uchar dsa_packet_tmp[PKTSIZE_ALIGN];
	struct dsa_port_pdata *port_pdata;
	int err;

	if (length + head + tail > PKTSIZE_ALIGN)
		return -EINVAL;

	memset(dsa_packet_tmp, 0, head);
	memset(dsa_packet_tmp + head + length, 0, tail);
	memcpy(dsa_packet_tmp + head, packet, length);
	length += head + tail;
	/* copy back to preserve original buffer alignment */
	memcpy(packet, dsa_packet_tmp, length);

	port_pdata = dev_get_parent_plat(pdev);
	err = ops->xmit(dev, port_pdata->index, packet, length);
	if (err)
		return err;

	return eth_get_ops(master)->send(master, packet, length);
}

/* Receive a frame from master Ethernet, process it and pass it on */
static int dsa_port_recv(struct udevice *pdev, int flags, uchar **packetp)
{
	struct udevice *dev = dev_get_parent(pdev);
	struct dsa_priv *priv = dev_get_uclass_priv(dev);
	int head = priv->headroom, tail = priv->tailroom;
	struct udevice *master = dsa_get_master(dev);
	struct dsa_ops *ops = dsa_get_ops(dev);
	struct dsa_port_pdata *port_pdata;
	int length, port_index, err;

	length = eth_get_ops(master)->recv(master, flags, packetp);
	if (length <= 0)
		return length;

	/*
	 * If we receive frames from a different port or frames that DSA driver
	 * doesn't like we discard them here.
	 * In case of discard we return with no frame and expect to be called
	 * again instead of looping here, so upper layer can deal with timeouts.
	 */
	port_pdata = dev_get_parent_plat(pdev);
	err = ops->rcv(dev, &port_index, *packetp, length);
	if (err || port_index != port_pdata->index || (length <= head + tail)) {
		if (eth_get_ops(master)->free_pkt)
			eth_get_ops(master)->free_pkt(master, *packetp, length);
		return -EAGAIN;
	}

	/*
	 * We move the pointer over headroom here to avoid a copy.  If free_pkt
	 * gets called we move the pointer back before calling master free_pkt.
	 */
	*packetp += head;

	return length - head - tail;
}

static int dsa_port_free_pkt(struct udevice *pdev, uchar *packet, int length)
{
	struct udevice *dev = dev_get_parent(pdev);
	struct udevice *master = dsa_get_master(dev);
	struct dsa_priv *priv;

	priv = dev_get_uclass_priv(dev);
	if (eth_get_ops(master)->free_pkt) {
		/* return the original pointer and length to master Eth */
		packet -= priv->headroom;
		length += priv->headroom - priv->tailroom;

		return eth_get_ops(master)->free_pkt(master, packet, length);
	}

	return 0;
}

static int dsa_port_of_to_pdata(struct udevice *pdev)
{
	struct dsa_port_pdata *port_pdata;
	struct dsa_pdata *dsa_pdata;
	struct eth_pdata *eth_pdata;
	struct udevice *dev;
	const char *label;
	u32 index;
	int err;

	if (!pdev)
		return -ENODEV;

	err = ofnode_read_u32(dev_ofnode(pdev), "reg", &index);
	if (err)
		return err;

	dev = dev_get_parent(pdev);
	dsa_pdata = dev_get_uclass_plat(dev);

	port_pdata = dev_get_parent_plat(pdev);
	port_pdata->index = index;

	label = ofnode_read_string(dev_ofnode(pdev), "label");
	if (label)
		strncpy(port_pdata->name, label, DSA_PORT_NAME_LENGTH);

	eth_pdata = dev_get_plat(pdev);
	eth_pdata->priv_pdata = port_pdata;

	dev_dbg(pdev, "port %d node %s\n", port_pdata->index,
		ofnode_get_name(dev_ofnode(pdev)));

	return 0;
}

static const struct eth_ops dsa_port_ops = {
	.start		= dsa_port_start,
	.send		= dsa_port_send,
	.recv		= dsa_port_recv,
	.stop		= dsa_port_stop,
	.free_pkt	= dsa_port_free_pkt,
};

static int dsa_port_probe(struct udevice *pdev)
{
	struct udevice *dev = dev_get_parent(pdev);
	struct eth_pdata *eth_pdata, *master_pdata;
	unsigned char env_enetaddr[ARP_HLEN];
	struct dsa_port_pdata *port_pdata;
	struct dsa_priv *dsa_priv;
	struct udevice *master;
	int ret;

	port_pdata = dev_get_parent_plat(pdev);
	dsa_priv = dev_get_uclass_priv(dev);

	port_pdata->phy = dm_eth_phy_connect(pdev);
	if (!port_pdata->phy)
		return -ENODEV;

	master = dsa_get_master(dev);
	if (!master)
		return -ENODEV;

	/*
	 * Probe the master device. We depend on the master device for proper
	 * operation and we also need it for MAC inheritance below.
	 *
	 * TODO: we assume the master device is always there and doesn't get
	 * removed during runtime.
	 */
	ret = device_probe(master);
	if (ret)
		return ret;

	/*
	 * Inherit port's hwaddr from the DSA master, unless the port already
	 * has a unique MAC address specified in the environment.
	 */
	eth_env_get_enetaddr_by_index("eth", dev_seq(pdev), env_enetaddr);
	if (!is_zero_ethaddr(env_enetaddr))
		return 0;

	master_pdata = dev_get_plat(master);
	eth_pdata = dev_get_plat(pdev);
	memcpy(eth_pdata->enetaddr, master_pdata->enetaddr, ARP_HLEN);
	eth_env_set_enetaddr_by_index("eth", dev_seq(pdev),
				      master_pdata->enetaddr);

	return 0;
}

static int dsa_port_remove(struct udevice *pdev)
{
	struct udevice *dev = dev_get_parent(pdev);
	struct dsa_port_pdata *port_pdata;
	struct dsa_priv *dsa_priv;

	port_pdata = dev_get_parent_plat(pdev);
	dsa_priv = dev_get_uclass_priv(dev);

	port_pdata->phy = NULL;

	return 0;
}

U_BOOT_DRIVER(dsa_port) = {
	.name	= DSA_PORT_CHILD_DRV_NAME,
	.id	= UCLASS_ETH,
	.ops	= &dsa_port_ops,
	.probe	= dsa_port_probe,
	.remove	= dsa_port_remove,
	.of_to_plat = dsa_port_of_to_pdata,
	.plat_auto = sizeof(struct eth_pdata),
};

/*
 * This function mostly deals with pulling information out of the device tree
 * into the pdata structure.
 * It goes through the list of switch ports, registers an eth device for each
 * front panel port and identifies the cpu port connected to master eth device.
 * TODO: support cascaded switches
 */
static int dsa_post_bind(struct udevice *dev)
{
	struct dsa_pdata *pdata = dev_get_uclass_plat(dev);
	ofnode node = dev_ofnode(dev), pnode;
	int i, err, first_err = 0;

	if (!ofnode_valid(node))
		return -ENODEV;

	pdata->master_node = ofnode_null();

	node = ofnode_find_subnode(node, "ports");
	if (!ofnode_valid(node))
		node = ofnode_find_subnode(node, "ethernet-ports");
	if (!ofnode_valid(node)) {
		dev_err(dev, "ports node is missing under DSA device!\n");
		return -EINVAL;
	}

	pdata->num_ports = ofnode_get_child_count(node);
	if (pdata->num_ports <= 0 || pdata->num_ports > DSA_MAX_PORTS) {
		dev_err(dev, "invalid number of ports (%d)\n",
			pdata->num_ports);
		return -EINVAL;
	}

	/* look for the CPU port */
	ofnode_for_each_subnode(pnode, node) {
		u32 ethernet;

		if (ofnode_read_u32(pnode, "ethernet", &ethernet))
			continue;

		pdata->master_node = ofnode_get_by_phandle(ethernet);
		pdata->cpu_port_node = pnode;
		break;
	}

	if (!ofnode_valid(pdata->master_node)) {
		dev_err(dev, "master eth node missing!\n");
		return -EINVAL;
	}

	if (ofnode_read_u32(pnode, "reg", &pdata->cpu_port)) {
		dev_err(dev, "CPU port node not valid!\n");
		return -EINVAL;
	}

	dev_dbg(dev, "master node %s on port %d\n",
		ofnode_get_name(pdata->master_node), pdata->cpu_port);

	for (i = 0; i < pdata->num_ports; i++) {
		char name[DSA_PORT_NAME_LENGTH];
		struct udevice *pdev;

		/*
		 * If this is the CPU port don't register it as an ETH device,
		 * we skip it on purpose since I/O to/from it from the CPU
		 * isn't useful.
		 */
		if (i == pdata->cpu_port)
			continue;

		/*
		 * Set up default port names.  If present, DT port labels
		 * will override the default port names.
		 */
		snprintf(name, DSA_PORT_NAME_LENGTH, "%s@%d", dev->name, i);

		ofnode_for_each_subnode(pnode, node) {
			u32 reg;

			if (ofnode_read_u32(pnode, "reg", &reg))
				continue;

			if (reg == i)
				break;
		}

		/*
		 * skip registration if port id not found or if the port
		 * is explicitly disabled in DT
		 */
		if (!ofnode_valid(pnode) || !ofnode_is_available(pnode))
			continue;

		err = device_bind_driver_to_node(dev, DSA_PORT_CHILD_DRV_NAME,
						 name, pnode, &pdev);
		if (pdev) {
			struct dsa_port_pdata *port_pdata;

			port_pdata = dev_get_parent_plat(pdev);
			strncpy(port_pdata->name, name, DSA_PORT_NAME_LENGTH);
			pdev->name = port_pdata->name;
		}

		/* try to bind all ports but keep 1st error */
		if (err && !first_err)
			first_err = err;
	}

	if (first_err)
		return first_err;

	dev_dbg(dev, "DSA ports successfully bound\n");

	return 0;
}

/**
 * Initialize the uclass per device internal state structure (priv).
 * TODO: pick up references to other switch devices here, if we're cascaded.
 */
static int dsa_pre_probe(struct udevice *dev)
{
	struct dsa_pdata *pdata = dev_get_uclass_plat(dev);
	struct dsa_priv *priv = dev_get_uclass_priv(dev);

	priv->num_ports = pdata->num_ports;
	priv->cpu_port = pdata->cpu_port;
	priv->cpu_port_fixed_phy = fixed_phy_create(pdata->cpu_port_node);
	if (!priv->cpu_port_fixed_phy) {
		dev_err(dev, "Failed to register fixed-link for CPU port\n");
		return -ENODEV;
	}

	uclass_find_device_by_ofnode(UCLASS_ETH, pdata->master_node,
				     &priv->master_dev);
	return 0;
}

UCLASS_DRIVER(dsa) = {
	.id = UCLASS_DSA,
	.name = "dsa",
	.post_bind = dsa_post_bind,
	.pre_probe = dsa_pre_probe,
	.per_device_auto = sizeof(struct dsa_priv),
	.per_device_plat_auto = sizeof(struct dsa_pdata),
	.per_child_plat_auto = sizeof(struct dsa_port_pdata),
	.flags = DM_UC_FLAG_SEQ_ALIAS,
};
