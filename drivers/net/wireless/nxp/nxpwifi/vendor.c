// SPDX-License-Identifier: GPL-2.0-only
/*
 * NXP Wireless LAN device driver: VENDOR
 *
 * Copyright 2011-2024 NXP
 */

#include <net/mac80211.h>
#include <net/netlink.h>
#include "vendor.h"
#include "main.h"

static int nxpwifi_vendor_cmd_sleeppd(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      const void *data,
				      int data_len);

static int nxpwifi_vendor_cmd_hscfg(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				     const void *data,
				     int data_len);

static int nxpwifi_vendor_cmd_hs_offload(struct wiphy *wiphy,
					 struct wireless_dev *wdev,
					 const void *data,
					 int data_len);

static int nxpwifi_vendor_cmd_hscfg(struct wiphy *wiphy,
				    struct wireless_dev *wdev,
				     const void *data,
				     int data_len)
{
	struct nxpwifi_adapter *adapter =
			(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));

	struct nxpwifi_private *priv =
			nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
	struct nxpwifi_ds_hs_cfg hscfg;
	int ret = 0;
	const u32 *ptr = data + 1;
	struct sk_buff *resp;

	if (data_len == 0)
		return -EINVAL;

	memset(&hscfg, 0, sizeof(struct nxpwifi_ds_hs_cfg));

	if (*(u8 *)data == HOST_ACT_GEN_GET) {
		nxpwifi_set_hs_params(priv, HOST_ACT_GEN_GET,
				      NXPWIFI_SYNC_CMD, &hscfg);
		resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(hscfg));

		if (!resp)
			return -ENOMEM;

		if (nla_put(resp, NXPWIFI_HSCFG,
			    sizeof(hscfg) - sizeof(hscfg.is_invoke_hostcmd),
			    &hscfg.conditions)) {
			kfree_skb(resp);
			return -ENOBUFS;
		}
		ret = cfg80211_vendor_cmd_reply(resp);
	} else if (*(u8 *)data == HOST_ACT_GEN_SET) {
		if (data_len == 1 || data_len > 13) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "Wrong argument numbers\n");
			return -EINVAL;
		}

		if (data_len >= 2)
			hscfg.conditions = le32_to_cpu(get_unaligned(ptr));
		if (data_len >= 6)
			hscfg.gpio = le32_to_cpu(get_unaligned(ptr + 1));
		if (data_len >= 10)
			hscfg.gap = le32_to_cpu(get_unaligned(ptr + 2));

		hscfg.is_invoke_hostcmd = false;

		if (hscfg.conditions == HS_CFG_CANCEL) {
			ret = nxpwifi_cancel_hs(priv, NXPWIFI_ASYNC_CMD);
		} else {
			ret = nxpwifi_set_hs_params(priv, HOST_ACT_GEN_SET,
						    NXPWIFI_SYNC_CMD, &hscfg);
			if (!ret) {
				if (!nxpwifi_enable_hs(priv->adapter))
					ret = -EFAULT;
				clear_bit(NXPWIFI_IS_HS_ENABLING, &adapter->work_flags);
			}
		}
	} else {
		nxpwifi_dbg(priv->adapter, ERROR,
			    "Invlaid action\n");
		ret = -EINVAL;
	}

	return ret;
}

static int nxpwifi_vendor_cmd_sleeppd(struct wiphy *wiphy,
				      struct wireless_dev *wdev,
				      const void *data,
				      int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv =
		nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
	u16 sleep_period;
	int ret = 0;
	struct sk_buff *resp;
	const u8 *ptr = data;

	if (ptr[0] == HOST_ACT_GEN_GET) {
		ret = nxpwifi_set_sleep_pd(priv, HOST_ACT_GEN_GET,
					   NXPWIFI_SYNC_CMD, &sleep_period);
		resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(u16));

		if (!resp)
			ret = -ENOMEM;

		if (nla_put(resp, NXPWIFI_SLEEPPD,
			    sizeof(sleep_period), &sleep_period)) {
			kfree_skb(resp);
			ret = -ENOBUFS;
		}
		ret = cfg80211_vendor_cmd_reply(resp);
	} else if (ptr[0] == HOST_ACT_GEN_SET) {
		adapter->sleep_period.period = (ptr[2] << 8) | ptr[1];
		ret = nxpwifi_set_sleep_pd(priv, HOST_ACT_GEN_SET,
					   NXPWIFI_SYNC_CMD, &adapter->sleep_period.period);
	} else {
		nxpwifi_dbg(priv->adapter, ERROR,
			    "Invlaid action\n");
		ret = -EINVAL;
	}

	return ret;
}

static int nxpwifi_vendor_cmd_clocksync(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv =
		nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
	struct nxpwifi_ds_gpio_tsf_latch *clocksync_cfg;
	int ret = 0;
	struct sk_buff *resp;
	struct nxpwifi_ds_tsf_info *tsf_info;

	if (data_len == 0)
		return -EINVAL;

	if (*(u8 *)data == HOST_ACT_GEN_GET) {
		tsf_info = kzalloc(sizeof(*tsf_info), GFP_KERNEL);

		nxpwifi_set_clock_sync(priv, HOST_ACT_GEN_GET, NXPWIFI_SYNC_CMD,
				       (void *)tsf_info);

		resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(*tsf_info));

		if (!resp)
			return -ENOMEM;

		if (nla_put(resp, NXPWIFI_TSF_REPORT,
			    sizeof(*tsf_info),
			    tsf_info)) {
			kfree_skb(resp);
			return -ENOBUFS;
		}
		ret = cfg80211_vendor_cmd_reply(resp);
		kfree(tsf_info);
	} else if (*(u8 *)data == HOST_ACT_GEN_SET) {
		const u16 *ptr = data + 5;

		clocksync_cfg = kzalloc(sizeof(*clocksync_cfg), GFP_KERNEL);

		if (data_len != 6) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "Wrong argument numbers: %d\n", data_len);
			return -EINVAL;
		}
		clocksync_cfg->mode = *((u8 *)data + 1);
		clocksync_cfg->role = *((u8 *)data + 2);
		clocksync_cfg->pin = *((u8 *)data + 3);
		clocksync_cfg->level = *((u8 *)data + 4);
		clocksync_cfg->width = le16_to_cpu(get_unaligned(ptr));
		nxpwifi_dbg(priv->adapter, INFO,
				    "clocksync: mode %d role: %d pin: %d level: %d wodth: %d\n", clocksync_cfg->mode, clocksync_cfg->role, clocksync_cfg->pin, clocksync_cfg->level, clocksync_cfg->width );


		nxpwifi_set_clock_sync(priv, HOST_ACT_GEN_SET, NXPWIFI_SYNC_CMD,
				       (void *)clocksync_cfg);
		kfree(clocksync_cfg);
	} else {
		nxpwifi_dbg(priv->adapter, ERROR,
			    "Invlaid action\n");
	}

	return 0;
}

static int nxpwifi_vendor_cmd_hs_offload(struct wiphy *wiphy,
					 struct wireless_dev *wdev,
					 const void *data,
					 int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv =
		nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
	int ret = 0;
	struct sk_buff *resp;
	u8 hs_offload_cfg = 0;

	if (data_len == 0)
		return -EINVAL;

	if (*(u8 *)data == HOST_ACT_GEN_GET) {
		if (priv->auto_arp)
			hs_offload_cfg = HS_OFFLOAD_ARP;

		if (priv->auto_ping)
			hs_offload_cfg |= HS_OFFLOAD_PING;

		resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(hs_offload_cfg));

		if (!resp)
			return -ENOMEM;

		if (nla_put(resp, NXPWIFI_HS_OFFLOAD,
			    sizeof(hs_offload_cfg),
			    &hs_offload_cfg)) {
			kfree_skb(resp);
			return -ENOBUFS;
		}
		ret = cfg80211_vendor_cmd_reply(resp);

	} else if (*(u8 *)data == HOST_ACT_GEN_SET) {
		if (data_len != 2) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "Wrong argument numbers: %d\n", data_len);
			return -EINVAL;
		}

		if (*((u8 *)data + 1) & HS_OFFLOAD_ARP)
			priv->auto_arp = 1;
		else
			priv->auto_arp = 0;

		if (*((u8 *)data + 1) & HS_OFFLOAD_PING)
			priv->auto_ping = 1;
		else
			priv->auto_ping = 0;

		if (*((u8 *)data + 1) & HS_WAKEON_MDNS)
			priv->wake_on_mdns = 1;
		else
			priv->wake_on_mdns = 0;

	} else {
		nxpwifi_dbg(priv->adapter, ERROR,
			    "Invlaid action\n");
	}

	return 0;
}

static const struct wiphy_vendor_command nxpwifi_vendor_commands[] = {
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_HSCFG,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_cmd_hscfg,
		.policy = VENDOR_CMD_RAW_DATA,
	},
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_SLEEPPD,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_cmd_sleeppd,
		.policy = VENDOR_CMD_RAW_DATA,
	},
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_CLOCKSYNC,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_cmd_clocksync,
		.policy = VENDOR_CMD_RAW_DATA,
	},
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_HSOFFLD,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_cmd_hs_offload,
		.policy = VENDOR_CMD_RAW_DATA,
	},
};

void nxpwifi_set_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands = nxpwifi_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(nxpwifi_vendor_commands);
}
