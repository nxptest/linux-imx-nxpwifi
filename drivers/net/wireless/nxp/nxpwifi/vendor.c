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
};

void nxpwifi_set_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands = nxpwifi_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(nxpwifi_vendor_commands);
}
