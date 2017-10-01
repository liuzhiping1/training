/*
 * drivers/net/ethernet/lep-eth.c
 *
 * Copyright (c) 2017 Barry Song <21cnbao@gmail.com>, LEP
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>

#include <linux/netdevice.h>
#include <linux/platform_device.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/hrtimer.h>

#define CARDNAME "lep-eth"
#define LEP_PACKETIN_INTERVAL 100000
#define INCOMING_PACKET_LEN   200
struct lep_eth_priv {
	spinlock_t lock;
	struct hrtimer timer;
	struct net_device *ndev;
	unsigned char pkt[INCOMING_PACKET_LEN]; /* a pesudo incoming packet */
};

static int
lep_eth_hard_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	/* as a driver to emulate high softirq load, we don't tx */
	dev_kfree_skb_any(skb);
	ndev->stats.tx_dropped++;

	return NETDEV_TX_OK;
}

static void lep_eth_receive(struct net_device *ndev)
{
	struct lep_eth_priv *priv = netdev_priv(ndev);
	unsigned char *data;
	struct sk_buff *skb;
	int len = INCOMING_PACKET_LEN;

	skb = netdev_alloc_skb(ndev, len);
	if (unlikely(skb == NULL)) {
		ndev->stats.rx_dropped++;
		return;
	}

	data = skb_put(skb, len);
	memcpy(data, priv->pkt, len);
	skb->protocol = eth_type_trans(skb, ndev);
	netif_rx(skb);
	ndev->stats.rx_packets++;
	ndev->stats.rx_bytes += len;
}

static int lep_eth_open(struct net_device *ndev)
{
	netif_start_queue(ndev);

	return 0;
}

static int lep_eth_close(struct net_device *ndev)
{
	netif_stop_queue(ndev);

	return 0;
}

static void lep_eth_timeout(struct net_device *ndev)
{
	netif_wake_queue(ndev);
}

static const struct net_device_ops lep_eth_netdev_ops = {
	.ndo_open		= lep_eth_open,
	.ndo_stop		= lep_eth_close,
	.ndo_start_xmit		= lep_eth_hard_start_xmit,
	.ndo_tx_timeout		= lep_eth_timeout,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
};

static enum hrtimer_restart lep_timer_callback(struct hrtimer *hrt)
{
	struct lep_eth_priv *priv = container_of(hrt,struct lep_eth_priv,timer);
	struct net_device *ndev = priv->ndev;
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);

	lep_eth_receive(ndev);

	spin_unlock_irqrestore(&priv->lock, flags);

	hrtimer_forward_now(hrt,ns_to_ktime(LEP_PACKETIN_INTERVAL));
	return HRTIMER_RESTART;
}

static int lep_eth_drv_probe(struct platform_device *pdev)
{
	struct lep_eth_priv *priv;
	struct net_device *ndev;

	ndev = alloc_etherdev(sizeof (struct lep_eth_priv));
	if (!ndev)
		return -ENOMEM;

	SET_NETDEV_DEV(ndev, &pdev->dev);
	platform_set_drvdata(pdev, ndev);

	priv = netdev_priv(ndev);
	spin_lock_init(&priv->lock);
	
	/* we use this timer to simulate incoming packets */
	hrtimer_init(&priv->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	priv->timer.function = lep_timer_callback;

	ndev->netdev_ops = &lep_eth_netdev_ops;
	ndev->watchdog_timeo = msecs_to_jiffies(5000);

	return register_netdev(ndev);
}

static int lep_eth_drv_remove(struct platform_device *pdev)
{
	struct net_device *ndev = platform_get_drvdata(pdev);

	unregister_netdev(ndev);
	free_netdev(ndev);

	return 0;
}

static struct platform_driver lep_eth_driver = {
	.probe		= lep_eth_drv_probe,
	.remove		= lep_eth_drv_remove,
	.driver		= {
		.name	= CARDNAME,
	},
};

static struct platform_device *lepeth_pdev;

static int __init lep_eth_init(void)
{	
        int ret;

        lepeth_pdev = platform_device_alloc(CARDNAME, -1);
        if (!lepeth_pdev)
                return -ENOMEM;

        ret = platform_device_add(lepeth_pdev);
        if (ret) {
                platform_device_put(lepeth_pdev);
                return ret;
        }   

	return platform_driver_register(&lep_eth_driver);
	}

static void __exit lep_eth_cleanup(void)
{
        platform_device_unregister(lepeth_pdev);
	platform_driver_unregister(&lep_eth_driver);
}

module_init(lep_eth_init);
module_exit(lep_eth_cleanup);

MODULE_AUTHOR("Barry Song");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" CARDNAME);
