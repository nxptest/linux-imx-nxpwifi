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

#if 0
static const
struct 
. nxpwifi_vendor_attr_policy[NUM_WLCORE_VENDOR_ATTR] = {
	[WLCORE_VENDOR_ATTR_FREQ]		= { .type = NLA_U32 },
	[WLCORE_VENDOR_ATTR_GROUP_ID]		= { .type = NLA_U32 },
};
#endif

static const struct
nla_policy nxpwifi_vendor_attr_policy[NXPWIFI_ATTR_CSI_MAX + 1] = {
	[NXPWIFI_ATTR_ANTENNA_MODE] = { .type = NLA_U16 },
	[NXPWIFI_ATTR_SAD_EVAL_TIME] = { .type = NLA_U16 },
};

static const struct
nla_policy nxpwifi_edmac_policy[NXPWIFI_EDMAC_MAX + 1] = {
	[NXPWIFI_EDMAC_CTRL_2G] = { .type = NLA_U16 },
	[NXPWIFI_EDMAC_OFFSET_2G] = { .type = NLA_S16 },
	[NXPWIFI_EDMAC_CTRL_5G] = { .type = NLA_U16 },
	[NXPWIFI_EDMAC_OFFSET_5G] = { .type = NLA_S16 },
	[NXPWIFI_EDMAC_TXQ_LOCK] = { .type = NLA_U32 },
};

static const struct
nla_policy nxpwifi_vht_policy[NXPWIFI_VHT_MAX + 1] = {
	[NXPWIFI_VHT_BAND] = { .type = NLA_U32 },
	[NXPWIFI_VHT_TXRX] = { .type = NLA_U32 },
	[NXPWIFI_VHT_BW] = { .type = NLA_U32 },
	[NXPWIFI_VHT_CAP] = { .type = NLA_U32 },
	[NXPWIFI_VHT_TXMCS] = { .type = NLA_U32 },
	[NXPWIFI_VHT_RXMCS] = { .type = NLA_U32 }
};

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

static int nxpwifi_vendor_edmac_cfg(struct wiphy *wiphy,
				    struct wireless_dev *wdev, const void *data,
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

static int nxpwifi_vendor_cmd_ind_reset(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data,
					int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv =
		nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
	struct nxpwifi_ds_independent_reset_cfg *ir_cfg;
	int ret = 0;
	struct sk_buff *resp;

	if (data_len == 0)
		return -EINVAL;

	ir_cfg = kzalloc(sizeof(*ir_cfg), GFP_KERNEL);

	if (*(u8 *)data == HOST_ACT_GEN_GET) {
		nxpwifi_set_ind_rst(priv, HOST_ACT_GEN_GET, NXPWIFI_SYNC_CMD,
				    ir_cfg);
		resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(*ir_cfg));

		if (!resp)
			return -ENOMEM;

		if (nla_put(resp, NXPWIFI_INDRST_CFG,
			    sizeof(*ir_cfg),
			    ir_cfg)) {
			kfree_skb(resp);
			return -ENOBUFS;
		}
		ret = cfg80211_vendor_cmd_reply(resp);

	} else if (*(u8 *)data == HOST_ACT_GEN_SET) {
		if (data_len != 3) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "Wrong argument numbers: %d\n", data_len);
			return -EINVAL;
		}
		ir_cfg->ir_mode = *((u8 *)data + 1);
		ir_cfg->gpio_pin = *((u8 *)data + 2);
		nxpwifi_set_ind_rst(priv, HOST_ACT_GEN_SET, NXPWIFI_SYNC_CMD,
				    ir_cfg);
	} else {
		nxpwifi_dbg(priv->adapter, ERROR,
			    "Invlaid action\n");
	}

	kfree(ir_cfg);

	return 0;
}

static int nxpwifi_vendor_set_csi(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv =
		nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
	struct nlattr *tb_vendor[NXPWIFI_ATTR_CSI_MAX + 1];
	int ret = 0;
	struct nxpwifi_ds_csi_cfg *csi_cfg;
	const u8 *ptr = data;

	nxpwifi_dbg(priv->adapter, ERROR, "%s dump data %x %x %x %x %x %x %d\n", __FUNCTION__, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], data_len);

	if (data_len == 0)
		return -EINVAL;

	csi_cfg = kzalloc(sizeof(*csi_cfg), GFP_KERNEL);

	if (csi_cfg == NULL) {
		nxpwifi_dbg(priv->adapter, ERROR, "Could not allocate buffer for set CSI command!\n");
		ret = -ENOMEM;
		goto done;
	}

	nla_parse(tb_vendor, NXPWIFI_ATTR_CSI_MAX, (struct nlattr *)data, data_len,
			  NULL,
			  NULL);

	if (!tb_vendor[NXPWIFI_ATTR_CSI_CONFIG]) {
		nxpwifi_dbg(priv->adapter, ERROR, "Could not find CSI CFG attr!\n");
		ret = -EFAULT;
		goto done;
	}

	memcpy(csi_cfg,
				(struct nxpwifi_ds_csi_cfg *)nla_data(
					tb_vendor[NXPWIFI_ATTR_CSI_CONFIG]),
				sizeof(*csi_cfg));

	nxpwifi_dbg(priv->adapter, ERROR, "CSI configuration: csi_enable %d head_id %x tail_id %x csi_filter_cnt %d chip_id %x\n", csi_cfg->csi_enable,
	csi_cfg->head_id, csi_cfg->tail_id, csi_cfg->csi_filter_cnt, csi_cfg->chip_id);

	priv->csi_enable = csi_cfg->csi_enable;

	if (priv->csi_enable == 1) {
#if 0
		if (tb_vendor[ATTR_CSI_DUMP_FORMAT])
			priv->csi_dump_format =
				nla_get_u8(tb_vendor[ATTR_CSI_DUMP_FORMAT]);
#endif
		ret = nxpwifi_set_csi_cfg(priv, HOST_ACT_CSI_ENABLE,
			NXPWIFI_SYNC_CMD,
			csi_cfg);

	} else if (priv->csi_enable == 0) {		
		if (!tb_vendor[NXPWIFI_ATTR_MAC_ADDR]) {
			ret = -EFAULT;
			goto done;
		}
		memset(csi_cfg, 0, sizeof(*csi_cfg));
		memcpy(csi_cfg->csi_filter[0].mac_addr,
			   (u8 *)nla_data(tb_vendor[NXPWIFI_ATTR_MAC_ADDR]),
			   ETH_ALEN);
		ret = nxpwifi_set_csi_cfg(priv, HOST_ACT_CSI_DISABLE,
			NXPWIFI_SYNC_CMD,
			csi_cfg);

	}

done:
#if 0
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
#endif
	return ret;
}

static int nxpwifi_vendor_channel_switch(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv =
		nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_UAP);
	struct nlattr *tb_vendor[NXPWIFI_ATTR_CSI_MAX + 1];
	struct nxpwifi_ds_chan_switch *chsw_cfg;
	int ret = 0;

	if (priv->bss_type != NXPWIFI_BSS_TYPE_UAP) {
		nxpwifi_dbg(priv->adapter, ERROR, "Please do channel switch on the AP interface.\n");
		return -EINVAL;
	}

	if (data_len == 0)
		return -EINVAL;

	chsw_cfg = kzalloc(sizeof(*chsw_cfg), GFP_KERNEL);

	if (chsw_cfg == NULL) {
		return -ENOMEM;
	}

	nla_parse(tb_vendor, NXPWIFI_ATTR_CSI_MAX, (struct nlattr *)data, data_len,
			  NULL,
			  NULL);

	if (!tb_vendor[NXPWIFI_ATTR_CHSWITCH]) {
		nxpwifi_dbg(priv->adapter, ERROR, "Could not find channel switch attr!\n");
		ret = -EFAULT;
		goto done;
	}

	memcpy(chsw_cfg,
				(struct nxpwifi_ds_chan_switch *)nla_data(
					tb_vendor[NXPWIFI_ATTR_CHSWITCH]),
				sizeof(*chsw_cfg));

	nxpwifi_dbg(priv->adapter, ERROR, "%s channel switch cfg mode %d chan_switch_mode %d new_oper_class %d new_channel_num %d chan_switch_count %d number of packets %d\n", __FUNCTION__, chsw_cfg->mode, chsw_cfg->chan_switch_mode, chsw_cfg->new_oper_class, chsw_cfg->new_channel_num, chsw_cfg->chan_switch_count, chsw_cfg->bw_retry.num_pkts);

	if(!chsw_cfg->bw_retry.num_pkts)
		chsw_cfg->bw_retry.num_pkts = NXPWIFI_DEF_NUM_PKTS;
    else if (!chsw_cfg->mode)
		chsw_cfg->bw_retry.num_pkts = min_t(u8, chsw_cfg->bw_retry.num_pkts, NXPWIFI_MAX_NUM_PKTS);

	ret = nxpwifi_set_channel_switch(priv, HOST_ACT_GEN_SET, NXPWIFI_SYNC_CMD,
				       chsw_cfg);
done:
	kfree(chsw_cfg);

	return ret;

}

static int nxpwifi_vendor_antenna_cfg(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv =
		nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
	struct nlattr *tb_vendor[NXPWIFI_ATTR_CSI_MAX + 1];
	struct nxpwifi_ds_ant_cfg *ant_cfg;
	int ret = 0;
	struct sk_buff *resp;

	//if (data_len == 0)
	//	return -EINVAL;

	ant_cfg = kzalloc(sizeof(*ant_cfg), GFP_KERNEL);

	if (ant_cfg == NULL) {
		return -ENOMEM;
	}

	nla_parse(tb_vendor, NXPWIFI_ATTR_CSI_MAX, (struct nlattr *)data, data_len,
			  NULL,
			  NULL);

	if (!tb_vendor[NXPWIFI_ATTR_ANTENNA_MODE]) {
		nxpwifi_dbg(priv->adapter, ERROR, "Could not find antenna config attr! It is get command\n");
		ret = nxpwifi_set_antenna(priv, HOST_ACT_GEN_GET, NXPWIFI_SYNC_CMD,
				    	   ant_cfg);
		resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(ant_cfg->antenna_mode));

		if (!resp)
			return -ENOMEM;

		if (nla_put_u16(resp, NXPWIFI_ATTR_ANTENNA_MODE,
			    ant_cfg->antenna_mode)) {
			nxpwifi_dbg(priv->adapter, ERROR, "put ant mode error\n");
			kfree_skb(resp);
			return -ENOBUFS;
		}
		ret = cfg80211_vendor_cmd_reply(resp);

	} else {
		ant_cfg->tx_ant = 0;
		ant_cfg->rx_ant = 0;

		ant_cfg->antenna_mode = nla_get_u16(
			tb_vendor[NXPWIFI_ATTR_ANTENNA_MODE]);

		if (tb_vendor[NXPWIFI_ATTR_SAD_EVAL_TIME]) {
			ant_cfg->evaluate_time = nla_get_u16(
				tb_vendor[NXPWIFI_ATTR_SAD_EVAL_TIME]);
		} else {
			ant_cfg->evaluate_time = 0;
		}
		nxpwifi_dbg(priv->adapter, ERROR, "%s tx_ant %d rx_ant %d antenna_mode %x evaluate_time %d\n", __FUNCTION__, ant_cfg->tx_ant, ant_cfg->rx_ant, ant_cfg->antenna_mode, ant_cfg->evaluate_time);

		ret = nxpwifi_set_antenna(priv, HOST_ACT_GEN_SET, NXPWIFI_SYNC_CMD,
				    	   ant_cfg);
	}
done:
	kfree(ant_cfg);

	return ret;

}

static int nxpwifi_vendor_edmac_cfg(struct wiphy *wiphy,
				    struct wireless_dev *wdev, const void *data,
				    int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv =
		nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
	struct nlattr *tb_vendor[NXPWIFI_EDMAC_MAX + 1];
	struct nxpwifi_ds_ed_mac_cfg *edmac_cfg;
	int ret = 0;
	struct sk_buff *resp;

	edmac_cfg = kzalloc(sizeof(*edmac_cfg), GFP_KERNEL);

	if (!edmac_cfg)
		return -ENOMEM;

	nla_parse(tb_vendor, NXPWIFI_EDMAC_MAX, (struct nlattr *)data, data_len,
		  nxpwifi_edmac_policy, NULL);

	if (!tb_vendor[NXPWIFI_EDMAC_CTRL_2G]) {
		nxpwifi_dbg(priv->adapter, INFO,
			    "Could not find EDMAC attr! It's a GET command. Get EDMAC CFG from FW.\n");
		ret = nxpwifi_set_edmac(priv, HOST_ACT_GEN_GET,
					NXPWIFI_SYNC_CMD, edmac_cfg);
		resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 32);

		if (!resp)
			return -ENOMEM;

		if (nla_put_u16(resp, NXPWIFI_EDMAC_CTRL_2G,
				edmac_cfg->ed_ctrl_2g)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put EDMAC_CTRL_2G attribute error\n");
			kfree_skb(resp);
			return -ENOBUFS;
		}

		if (nla_put_u16(resp, NXPWIFI_EDMAC_OFFSET_2G,
				edmac_cfg->ed_offset_2g)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put EDMAC_OFFSET_2G attribute error\n");
			kfree_skb(resp);
			return -ENOBUFS;
		}

		if (nla_put_u16(resp, NXPWIFI_EDMAC_CTRL_5G,
				edmac_cfg->ed_ctrl_5g)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put EDMAC_CTRL_5G attribute error\n");
			kfree_skb(resp);
			return -ENOBUFS;
		}

		if (nla_put_u16(resp, NXPWIFI_EDMAC_OFFSET_5G,
				edmac_cfg->ed_offset_5g)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put EDMAC_OFFSET_5G attribute error\n");
			kfree_skb(resp);
			return -ENOBUFS;
		}

		if (nla_put_u32(resp, NXPWIFI_EDMAC_TXQ_LOCK,
				edmac_cfg->ed_bitmap_txq_lock)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put EDMAC_TXQ_LOCK attribute error\n");
			kfree_skb(resp);
			return -ENOBUFS;
		}

		ret = cfg80211_vendor_cmd_reply(resp);

	} else {
		edmac_cfg->ed_ctrl_2g =
			*(u16 *)nla_data(tb_vendor[NXPWIFI_EDMAC_CTRL_2G]);
		edmac_cfg->ed_offset_2g =
			*(s16 *)nla_data(tb_vendor[NXPWIFI_EDMAC_OFFSET_2G]);

		edmac_cfg->ed_ctrl_5g =
			*(u16 *)nla_data(tb_vendor[NXPWIFI_EDMAC_CTRL_5G]);
		edmac_cfg->ed_offset_5g =
			*(s16 *)nla_data(tb_vendor[NXPWIFI_EDMAC_OFFSET_5G]);

		edmac_cfg->ed_bitmap_txq_lock =
			*(u32 *)nla_data(tb_vendor[NXPWIFI_EDMAC_TXQ_LOCK]);
		ret = nxpwifi_set_edmac(priv, HOST_ACT_GEN_SET,
					NXPWIFI_SYNC_CMD, edmac_cfg);
	}

	kfree(edmac_cfg);

	return ret;
}

static int nxpwifi_vendor_vht_cfg(struct wiphy *wiphy,
				  struct wireless_dev *wdev, const void *data,
				  int data_len)
{
	struct nxpwifi_adapter *adapter =
		(struct nxpwifi_adapter *)(*(unsigned long *)wiphy_priv(wiphy));
	struct nxpwifi_private *priv = NULL;
	struct nlattr *tb_vendor[NXPWIFI_VHT_MAX + 1];
	struct nxpwifi_11ac_vht_cfg *vht_cfg;
	int ret = 0;
	struct sk_buff *resp;
	u32 txrx, bw;

	vht_cfg = kzalloc(sizeof(*vht_cfg), GFP_KERNEL);

	if (!vht_cfg)
		return -ENOMEM;

	nla_parse(tb_vendor, NXPWIFI_VHT_MAX, (struct nlattr *)data, data_len,
		  nxpwifi_vht_policy, NULL);

	if (!tb_vendor[NXPWIFI_VHT_BAND]) {
		nxpwifi_dbg(priv->adapter, ERROR,
			    "Could not find NXPWIFI_VHT_BAND attr!\n");
		ret = -EINVAL;
		goto done;
	}

	vht_cfg->band_config = 0x3 &
			       *(u8 *)nla_data(tb_vendor[NXPWIFI_VHT_BAND]);

	if (!tb_vendor[NXPWIFI_VHT_TXRX]) {
		nxpwifi_dbg(priv->adapter, ERROR,
			    "Could not find NXPWIFI_VHT_TXRX attr!\n");
		ret = -EINVAL;
		goto done;
	}

	vht_cfg->misc_config |= 0x3 &
				*(u8 *)nla_data(tb_vendor[NXPWIFI_VHT_TXRX]);

	if (vht_cfg->misc_config == 0) {
		ret = -EINVAL;
		goto done;
	} else if ((vht_cfg->misc_config == 1) || (vht_cfg->misc_config == 2)) {
		priv = nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_STA);
		nxpwifi_dbg(priv->adapter, ERROR, "sta mode\n");
	} else {
		priv = nxpwifi_get_priv(adapter, NXPWIFI_BSS_ROLE_UAP);
	}

	if (!tb_vendor[NXPWIFI_VHT_BW]) {
		nxpwifi_dbg(priv->adapter, INFO,
			    "Could not find NXPWIFI_VHT_BW attr! It's a get command.\n");

		ret = nxpwifi_set_vht(priv, HOST_ACT_GEN_GET, NXPWIFI_SYNC_CMD,
				      vht_cfg);
		resp = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, 32);

		if (!resp) {
			ret = -ENOMEM;
			goto done;
		}

		if (nla_put_u32(resp, NXPWIFI_VHT_BAND, vht_cfg->band_config)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put NXPWIFI_VHT_BAND attribute error\n");
			kfree_skb(resp);
			ret = -ENOBUFS;
			goto done;
		}
		txrx = vht_cfg->misc_config & 0x3;

		if (nla_put_u32(resp, NXPWIFI_VHT_TXRX, txrx)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put NXPWIFI_VHT_TXRX attribute error\n");
			kfree_skb(resp);
			ret = -ENOBUFS;
			goto done;
		}

		bw = (vht_cfg->misc_config & 0x4) << 2;

		if (nla_put_u32(resp, NXPWIFI_VHT_BW, bw)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put NXPWIFI_VHT_BW attribute error\n");
			kfree_skb(resp);
			ret = -ENOBUFS;
			goto done;
		}

		if (nla_put_u32(resp, NXPWIFI_VHT_CAP, vht_cfg->cap_info)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put NXPWIFI_VHT_CAP attribute error\n");
			kfree_skb(resp);
			ret = -ENOBUFS;
			goto done;
		}

		if (nla_put_u32(resp, NXPWIFI_VHT_TXMCS, vht_cfg->mcs_tx_set)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put NXPWIFI_VHT_TXMCS attribute error\n");
			kfree_skb(resp);
			ret = -ENOBUFS;
			goto done;
		}
		if (nla_put_u32(resp, NXPWIFI_VHT_RXMCS, vht_cfg->mcs_rx_set)) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "put NXPWIFI_VHT_RXMCS attribute error\n");
			kfree_skb(resp);
			ret = -ENOBUFS;
			goto done;
		}
		ret = cfg80211_vendor_cmd_reply(resp);
	} else {
		vht_cfg->misc_config |=
			0x4 & (*(u8 *)nla_data(tb_vendor[NXPWIFI_VHT_BW]) << 2);

		if (!tb_vendor[NXPWIFI_VHT_CAP]) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "Could not find NXPWIFI_VHT_CAP attr!\n");
			ret = -EINVAL;
			goto done;
		}

		memcpy(&vht_cfg->cap_info, nla_data(tb_vendor[NXPWIFI_VHT_CAP]),
		       sizeof(u32));

		if (tb_vendor[NXPWIFI_VHT_TXMCS])
			memcpy(&vht_cfg->mcs_tx_set,
			       nla_data(tb_vendor[NXPWIFI_VHT_TXMCS]),
			       sizeof(u32));

		if (tb_vendor[NXPWIFI_VHT_RXMCS])
			memcpy(&vht_cfg->mcs_rx_set,
			       nla_data(tb_vendor[NXPWIFI_VHT_RXMCS]),
			       sizeof(u32));

		ret = nxpwifi_set_vht(priv, HOST_ACT_GEN_SET, NXPWIFI_SYNC_CMD,
				      vht_cfg);
	}
done:
	kfree(vht_cfg);

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
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_INDRST,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_cmd_ind_reset,
		.policy = VENDOR_CMD_RAW_DATA,
	},
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_SETCSI,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_set_csi,
		.policy = VENDOR_CMD_RAW_DATA,
	},
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_CHSWITCH,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_channel_switch,
		.policy = VENDOR_CMD_RAW_DATA,
	},
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_ANTCFG,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_antenna_cfg,
		.policy = VENDOR_CMD_RAW_DATA,
	},
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_EDMAC_CFG,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_edmac_cfg,
		.policy = nxpwifi_edmac_policy,
		.maxattr = NXPWIFI_EDMAC_MAX - 1,
	},
	{
		.info = {
			.vendor_id = NXP_OUI,
			.subcmd = NXPWIFI_VENDOR_CMD_VHT_CFG,
		},
		.flags = WIPHY_VENDOR_CMD_NEED_RUNNING,
		.doit = nxpwifi_vendor_vht_cfg,
		.policy = nxpwifi_vht_policy,
		.maxattr = NXPWIFI_VHT_MAX - 1,
	}
};

void nxpwifi_set_vendor_commands(struct wiphy *wiphy)
{
	wiphy->vendor_commands = nxpwifi_vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(nxpwifi_vendor_commands);
}
