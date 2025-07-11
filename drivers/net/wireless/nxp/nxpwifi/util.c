// SPDX-License-Identifier: GPL-2.0-only
/*
 * NXP Wireless LAN device driver: utility functions
 *
 * Copyright 2011-2024 NXP
 */

#include "cfg.h"
#include "util.h"
#include "fw.h"
#include "main.h"
#include "cmdevt.h"
#include "wmm.h"
#include "11n.h"

static struct nxpwifi_debug_data items[] = {
	{"debug_mask", item_size(debug_mask),
	 item_addr(debug_mask), 1},
	{"int_counter", item_size(int_counter),
	 item_addr(int_counter), 1},
	{"wmm_ac_vo", item_size(packets_out[WMM_AC_VO]),
	 item_addr(packets_out[WMM_AC_VO]), 1},
	{"wmm_ac_vi", item_size(packets_out[WMM_AC_VI]),
	 item_addr(packets_out[WMM_AC_VI]), 1},
	{"wmm_ac_be", item_size(packets_out[WMM_AC_BE]),
	 item_addr(packets_out[WMM_AC_BE]), 1},
	{"wmm_ac_bk", item_size(packets_out[WMM_AC_BK]),
	 item_addr(packets_out[WMM_AC_BK]), 1},
	{"tx_buf_size", item_size(tx_buf_size),
	 item_addr(tx_buf_size), 1},
	{"curr_tx_buf_size", item_size(curr_tx_buf_size),
	 item_addr(curr_tx_buf_size), 1},
	{"ps_mode", item_size(ps_mode),
	 item_addr(ps_mode), 1},
	{"ps_state", item_size(ps_state),
	 item_addr(ps_state), 1},
	{"is_deep_sleep", item_size(is_deep_sleep),
	 item_addr(is_deep_sleep), 1},
	{"wakeup_dev_req", item_size(pm_wakeup_card_req),
	 item_addr(pm_wakeup_card_req), 1},
	{"wakeup_tries", item_size(pm_wakeup_fw_try),
	 item_addr(pm_wakeup_fw_try), 1},
	{"hs_configured", item_size(is_hs_configured),
	 item_addr(is_hs_configured), 1},
	{"hs_activated", item_size(hs_activated),
	 item_addr(hs_activated), 1},
	{"num_tx_timeout", item_size(num_tx_timeout),
	 item_addr(num_tx_timeout), 1},
	{"is_cmd_timedout", item_size(is_cmd_timedout),
	 item_addr(is_cmd_timedout), 1},
	{"timeout_cmd_id", item_size(timeout_cmd_id),
	 item_addr(timeout_cmd_id), 1},
	{"timeout_cmd_act", item_size(timeout_cmd_act),
	 item_addr(timeout_cmd_act), 1},
	{"last_cmd_id", item_size(last_cmd_id),
	 item_addr(last_cmd_id), DBG_CMD_NUM},
	{"last_cmd_act", item_size(last_cmd_act),
	 item_addr(last_cmd_act), DBG_CMD_NUM},
	{"last_cmd_index", item_size(last_cmd_index),
	 item_addr(last_cmd_index), 1},
	{"last_cmd_resp_id", item_size(last_cmd_resp_id),
	 item_addr(last_cmd_resp_id), DBG_CMD_NUM},
	{"last_cmd_resp_index", item_size(last_cmd_resp_index),
	 item_addr(last_cmd_resp_index), 1},
	{"last_event", item_size(last_event),
	 item_addr(last_event), DBG_CMD_NUM},
	{"last_event_index", item_size(last_event_index),
	 item_addr(last_event_index), 1},
	{"last_mp_wr_bitmap", item_size(last_mp_wr_bitmap),
	 item_addr(last_mp_wr_bitmap), NXPWIFI_DBG_SDIO_MP_NUM},
	{"last_mp_wr_ports", item_size(last_mp_wr_ports),
	 item_addr(last_mp_wr_ports), NXPWIFI_DBG_SDIO_MP_NUM},
	{"last_mp_wr_len", item_size(last_mp_wr_len),
	 item_addr(last_mp_wr_len), NXPWIFI_DBG_SDIO_MP_NUM},
	{"last_mp_curr_wr_port", item_size(last_mp_curr_wr_port),
	 item_addr(last_mp_curr_wr_port), NXPWIFI_DBG_SDIO_MP_NUM},
	{"last_sdio_mp_index", item_size(last_sdio_mp_index),
	 item_addr(last_sdio_mp_index), 1},
	{"num_cmd_h2c_fail", item_size(num_cmd_host_to_card_failure),
	 item_addr(num_cmd_host_to_card_failure), 1},
	{"num_cmd_sleep_cfm_fail",
	 item_size(num_cmd_sleep_cfm_host_to_card_failure),
	 item_addr(num_cmd_sleep_cfm_host_to_card_failure), 1},
	{"num_tx_h2c_fail", item_size(num_tx_host_to_card_failure),
	 item_addr(num_tx_host_to_card_failure), 1},
	{"num_evt_deauth", item_size(num_event_deauth),
	 item_addr(num_event_deauth), 1},
	{"num_evt_disassoc", item_size(num_event_disassoc),
	 item_addr(num_event_disassoc), 1},
	{"num_evt_link_lost", item_size(num_event_link_lost),
	 item_addr(num_event_link_lost), 1},
	{"num_cmd_deauth", item_size(num_cmd_deauth),
	 item_addr(num_cmd_deauth), 1},
	{"num_cmd_assoc_ok", item_size(num_cmd_assoc_success),
	 item_addr(num_cmd_assoc_success), 1},
	{"num_cmd_assoc_fail", item_size(num_cmd_assoc_failure),
	 item_addr(num_cmd_assoc_failure), 1},
	{"cmd_sent", item_size(cmd_sent),
	 item_addr(cmd_sent), 1},
	{"data_sent", item_size(data_sent),
	 item_addr(data_sent), 1},
	{"cmd_resp_received", item_size(cmd_resp_received),
	 item_addr(cmd_resp_received), 1},
	{"event_received", item_size(event_received),
	 item_addr(event_received), 1},

	/* variables defined in struct nxpwifi_adapter */
	{"cmd_pending", adapter_item_size(cmd_pending),
	 adapter_item_addr(cmd_pending), 1},
	{"tx_pending", adapter_item_size(tx_pending),
	 adapter_item_addr(tx_pending), 1},
};

static int num_of_items = ARRAY_SIZE(items);

/* Firmware initialization complete callback handler.
 *
 * This function wakes up the function waiting on the init
 * wait queue for the firmware initialization to complete.
 */
void nxpwifi_init_fw_complete(struct nxpwifi_adapter *adapter)
{
	adapter->init_wait_q_woken = true;
	wake_up_interruptible(&adapter->init_wait_q);
}

/* This function sends init/shutdown command
 * to firmware.
 */
int nxpwifi_init_shutdown_fw(struct nxpwifi_private *priv,
			     u32 func_init_shutdown)
{
	u16 cmd;

	if (func_init_shutdown == NXPWIFI_FUNC_INIT) {
		cmd = HOST_CMD_FUNC_INIT;
	} else if (func_init_shutdown == NXPWIFI_FUNC_SHUTDOWN) {
		cmd = HOST_CMD_FUNC_SHUTDOWN;
	} else {
		nxpwifi_dbg(priv->adapter, ERROR,
			    "unsupported parameter\n");
		return -EINVAL;
	}

	return nxpwifi_send_cmd(priv, cmd, HOST_ACT_GEN_SET, 0, NULL, true);
}
EXPORT_SYMBOL_GPL(nxpwifi_init_shutdown_fw);

/* IOCTL request handler to set/get debug information.
 *
 * This function collates/sets the information from/to different driver
 * structures.
 */
int nxpwifi_get_debug_info(struct nxpwifi_private *priv,
			   struct nxpwifi_debug_info *info)
{
	struct nxpwifi_adapter *adapter = priv->adapter;

	if (info) {
		info->debug_mask = adapter->debug_mask;
		memcpy(info->packets_out,
		       priv->wmm.packets_out,
		       sizeof(priv->wmm.packets_out));
		info->curr_tx_buf_size = (u32)adapter->curr_tx_buf_size;
		info->tx_buf_size = (u32)adapter->tx_buf_size;
		info->rx_tbl_num = nxpwifi_get_rx_reorder_tbl(priv,
							      info->rx_tbl);
		info->tx_tbl_num = nxpwifi_get_tx_ba_stream_tbl(priv,
								info->tx_tbl);
		info->ps_mode = adapter->ps_mode;
		info->ps_state = adapter->ps_state;
		info->is_deep_sleep = adapter->is_deep_sleep;
		info->pm_wakeup_card_req = adapter->pm_wakeup_card_req;
		info->pm_wakeup_fw_try = adapter->pm_wakeup_fw_try;
		info->is_hs_configured = test_bit(NXPWIFI_IS_HS_CONFIGURED,
						  &adapter->work_flags);
		info->hs_activated = adapter->hs_activated;
		info->is_cmd_timedout = test_bit(NXPWIFI_IS_CMD_TIMEDOUT,
						 &adapter->work_flags);
		info->num_cmd_host_to_card_failure =
			adapter->dbg.num_cmd_host_to_card_failure;
		info->num_cmd_sleep_cfm_host_to_card_failure =
			adapter->dbg.num_cmd_sleep_cfm_host_to_card_failure;
		info->num_tx_host_to_card_failure =
			adapter->dbg.num_tx_host_to_card_failure;
		info->num_event_deauth = adapter->dbg.num_event_deauth;
		info->num_event_disassoc = adapter->dbg.num_event_disassoc;
		info->num_event_link_lost = adapter->dbg.num_event_link_lost;
		info->num_cmd_deauth = adapter->dbg.num_cmd_deauth;
		info->num_cmd_assoc_success =
			adapter->dbg.num_cmd_assoc_success;
		info->num_cmd_assoc_failure =
			adapter->dbg.num_cmd_assoc_failure;
		info->num_tx_timeout = adapter->dbg.num_tx_timeout;
		info->timeout_cmd_id = adapter->dbg.timeout_cmd_id;
		info->timeout_cmd_act = adapter->dbg.timeout_cmd_act;
		memcpy(info->last_cmd_id, adapter->dbg.last_cmd_id,
		       sizeof(adapter->dbg.last_cmd_id));
		memcpy(info->last_cmd_act, adapter->dbg.last_cmd_act,
		       sizeof(adapter->dbg.last_cmd_act));
		info->last_cmd_index = adapter->dbg.last_cmd_index;
		memcpy(info->last_cmd_resp_id, adapter->dbg.last_cmd_resp_id,
		       sizeof(adapter->dbg.last_cmd_resp_id));
		info->last_cmd_resp_index = adapter->dbg.last_cmd_resp_index;
		memcpy(info->last_event, adapter->dbg.last_event,
		       sizeof(adapter->dbg.last_event));
		info->last_event_index = adapter->dbg.last_event_index;
		memcpy(info->last_mp_wr_bitmap, adapter->dbg.last_mp_wr_bitmap,
		       sizeof(adapter->dbg.last_mp_wr_bitmap));
		memcpy(info->last_mp_wr_ports, adapter->dbg.last_mp_wr_ports,
		       sizeof(adapter->dbg.last_mp_wr_ports));
		memcpy(info->last_mp_curr_wr_port,
		       adapter->dbg.last_mp_curr_wr_port,
		       sizeof(adapter->dbg.last_mp_curr_wr_port));
		memcpy(info->last_mp_wr_len, adapter->dbg.last_mp_wr_len,
		       sizeof(adapter->dbg.last_mp_wr_len));
		info->last_sdio_mp_index = adapter->dbg.last_sdio_mp_index;
		info->data_sent = adapter->data_sent;
		info->cmd_sent = adapter->cmd_sent;
		info->cmd_resp_received = adapter->cmd_resp_received;
	}

	return 0;
}

int nxpwifi_debug_info_to_buffer(struct nxpwifi_private *priv, char *buf,
				 struct nxpwifi_debug_info *info)
{
	char *p = buf;
	struct nxpwifi_debug_data *d = &items[0];
	size_t size, addr;
	long val;
	int i, j;

	if (!info)
		return 0;

	for (i = 0; i < num_of_items; i++) {
		p += sprintf(p, "%s=", d[i].name);

		size = d[i].size / d[i].num;

		if (i < (num_of_items - 3))
			addr = d[i].addr + (size_t)info;
		else /* The last 3 items are struct nxpwifi_adapter variables */
			addr = d[i].addr + (size_t)priv->adapter;

		for (j = 0; j < d[i].num; j++) {
			switch (size) {
			case 1:
				val = *((u8 *)addr);
				break;
			case 2:
				val = get_unaligned((u16 *)addr);
				break;
			case 4:
				val = get_unaligned((u32 *)addr);
				break;
			case 8:
				val = get_unaligned((long long *)addr);
				break;
			default:
				val = -1;
				break;
			}

			p += sprintf(p, "%#lx ", val);
			addr += size;
		}

		p += sprintf(p, "\n");
	}

	if (info->tx_tbl_num) {
		p += sprintf(p, "Tx BA stream table:\n");
		for (i = 0; i < info->tx_tbl_num; i++)
			p += sprintf(p, "tid = %d, ra = %pM\n",
				     info->tx_tbl[i].tid, info->tx_tbl[i].ra);
	}

	if (info->rx_tbl_num) {
		p += sprintf(p, "Rx reorder table:\n");
		for (i = 0; i < info->rx_tbl_num; i++) {
			p += sprintf(p, "tid = %d, ta = %pM, ",
				     info->rx_tbl[i].tid,
				     info->rx_tbl[i].ta);
			p += sprintf(p, "start_win = %d, ",
				     info->rx_tbl[i].start_win);
			p += sprintf(p, "win_size = %d, buffer: ",
				     info->rx_tbl[i].win_size);

			for (j = 0; j < info->rx_tbl[i].win_size; j++)
				p += sprintf(p, "%c ",
					     info->rx_tbl[i].buffer[j] ?
					     '1' : '0');

			p += sprintf(p, "\n");
		}
	}

	return p - buf;
}

bool nxpwifi_is_channel_setting_allowable(struct nxpwifi_private *priv,
					  struct ieee80211_channel *check_chan)
{
	struct nxpwifi_adapter *adapter = priv->adapter;
	int i;
	struct nxpwifi_private *tmp_priv;
	u8 bss_role = GET_BSS_ROLE(priv);
	struct ieee80211_channel *set_chan;

	for (i = 0; i < adapter->priv_num; i++) {
		tmp_priv = adapter->priv[i];
		if (tmp_priv == priv)
			continue;

		set_chan = NULL;
		if (bss_role == NXPWIFI_BSS_ROLE_STA) {
			if (GET_BSS_ROLE(tmp_priv) == NXPWIFI_BSS_ROLE_UAP &&
			    netif_carrier_ok(tmp_priv->netdev) &&
			    cfg80211_chandef_valid(&tmp_priv->bss_chandef))
				set_chan = tmp_priv->bss_chandef.chan;
		} else if (bss_role == NXPWIFI_BSS_ROLE_UAP) {
			struct nxpwifi_current_bss_params *bss_params =
				&tmp_priv->curr_bss_params;
			int channel = bss_params->bss_descriptor.channel;
			enum nl80211_band band =
				nxpwifi_band_to_radio_type(bss_params->band);
			int freq =
				ieee80211_channel_to_frequency(channel, band);

			if (GET_BSS_ROLE(tmp_priv) == NXPWIFI_BSS_ROLE_STA &&
			    tmp_priv->media_connected)
				set_chan = ieee80211_get_channel(adapter->wiphy, freq);
		}

		if (set_chan && !ieee80211_channel_equal(check_chan, set_chan)) {
			nxpwifi_dbg(adapter, ERROR,
				    "AP/STA must run on the same channel\n");
			return false;
		}
	}

	return true;
}

void nxpwifi_convert_chan_to_band_cfg(struct nxpwifi_private *priv,
				      u8 *band_cfg,
				      struct cfg80211_chan_def *chan_def)
{
	u8 chan_band = 0, chan_width = 0, chan2_offset = 0;

	switch (chan_def->chan->band) {
	case NL80211_BAND_2GHZ:
		chan_band = BAND_2GHZ;
		break;
	case NL80211_BAND_5GHZ:
		chan_band = BAND_5GHZ;
		break;
	default:
		break;
	}

	switch (chan_def->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
	case NL80211_CHAN_WIDTH_20:
		chan_width = CHAN_BW_20MHZ;
		break;
	case NL80211_CHAN_WIDTH_40:
		chan_width = CHAN_BW_40MHZ;
		if (chan_def->center_freq1 > chan_def->chan->center_freq)
			chan2_offset = IEEE80211_HT_PARAM_CHA_SEC_ABOVE;
		else
			chan2_offset = IEEE80211_HT_PARAM_CHA_SEC_BELOW;
		break;
	case NL80211_CHAN_WIDTH_80:
		chan2_offset =
			nxpwifi_get_sec_chan_offset(chan_def->chan->hw_value);
		chan_width = CHAN_BW_80MHZ;
		break;
	case NL80211_CHAN_WIDTH_80P80:
	case NL80211_CHAN_WIDTH_160:
	default:
		nxpwifi_dbg(priv->adapter,
			    WARN, "Unknown channel width: %d\n",
			    chan_def->width);
		break;
	}

	*band_cfg = ((chan2_offset << BAND_CFG_CHAN2_SHIFT_BIT) &
		     BAND_CFG_CHAN2_OFFSET_MASK) |
		    ((chan_width << BAND_CFG_CHAN_WIDTH_SHIFT_BIT) &
		     BAND_CFG_CHAN_WIDTH_MASK) |
		    ((chan_band << BAND_CFG_CHAN_BAND_SHIFT_BIT) &
		     BAND_CFG_CHAN_BAND_MASK);
}

static int
nxpwifi_parse_mgmt_packet(struct nxpwifi_private *priv, u8 *payload, u16 len,
			  struct rxpd *rx_pd)
{
	u16 stype;
	u8 category;
	struct ieee80211_hdr *ieee_hdr = (void *)payload;

	stype = (le16_to_cpu(ieee_hdr->frame_control) & IEEE80211_FCTL_STYPE);

	switch (stype) {
	case IEEE80211_STYPE_ACTION:
		category = *(payload + sizeof(struct ieee80211_hdr));
		switch (category) {
		case WLAN_CATEGORY_BACK:
			/*we dont indicate BACK action frames to cfg80211*/
			nxpwifi_dbg(priv->adapter, INFO,
				    "drop BACK action frames");
			return -EINVAL;
		default:
			nxpwifi_dbg(priv->adapter, INFO,
				    "unknown public action frame category %d\n",
				    category);
		}
		break;
	default:
		nxpwifi_dbg(priv->adapter, INFO,
			    "unknown mgmt frame subtype %#x\n", stype);
		return 0;
	}

	return 0;
}

/* This function sends deauth packet to the kernel. */
void nxpwifi_host_mlme_disconnect(struct nxpwifi_private *priv,
				  u16 reason_code, u8 *sa)
{
	u8 frame_buf[100];
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)frame_buf;

	memset(frame_buf, 0, sizeof(frame_buf));
	mgmt->frame_control = cpu_to_le16(IEEE80211_STYPE_DEAUTH);
	mgmt->duration = 0;
	mgmt->seq_ctrl = 0;
	mgmt->u.deauth.reason_code = cpu_to_le16(reason_code);

	if (GET_BSS_ROLE(priv) == NXPWIFI_BSS_ROLE_STA) {
		eth_broadcast_addr(mgmt->da);
		memcpy(mgmt->sa,
		       priv->curr_bss_params.bss_descriptor.mac_address,
		       ETH_ALEN);
		memcpy(mgmt->bssid, priv->cfg_bssid, ETH_ALEN);
		priv->auth_flag = 0;
		priv->auth_alg = WLAN_AUTH_NONE;
	} else {
		memcpy(mgmt->da, priv->curr_addr, ETH_ALEN);
		memcpy(mgmt->sa, sa, ETH_ALEN);
		memcpy(mgmt->bssid, priv->curr_addr, ETH_ALEN);
	}

	if (GET_BSS_ROLE(priv) != NXPWIFI_BSS_ROLE_UAP) {
		mutex_lock(&priv->wdev.mtx);
		cfg80211_rx_mlme_mgmt(priv->netdev, frame_buf, 26);
		mutex_unlock(&priv->wdev.mtx);
	} else {
		cfg80211_rx_mgmt(&priv->wdev,
				 priv->bss_chandef.chan->center_freq,
				 0, frame_buf, 26, 0);
	}
}

/* This function processes the received management packet and send it
 * to the kernel.
 */
int
nxpwifi_process_mgmt_packet(struct nxpwifi_private *priv,
			    struct sk_buff *skb)
{
	struct nxpwifi_adapter *adapter = priv->adapter;
	struct rxpd *rx_pd;
	u16 pkt_len;
	struct ieee80211_hdr *ieee_hdr;
	int ret;

	if (!skb)
		return -ENOMEM;

	if (!priv->mgmt_frame_mask ||
	    priv->wdev.iftype == NL80211_IFTYPE_UNSPECIFIED) {
		nxpwifi_dbg(adapter, ERROR,
			    "do not receive mgmt frames on uninitialized intf");
		return -EINVAL;
	}

	rx_pd = (struct rxpd *)skb->data;
	pkt_len = le16_to_cpu(rx_pd->rx_pkt_length);
	if (pkt_len < sizeof(struct ieee80211_hdr) + sizeof(pkt_len)) {
		nxpwifi_dbg(adapter, ERROR, "invalid rx_pkt_length");
		return -EINVAL;
	}

	skb_pull(skb, le16_to_cpu(rx_pd->rx_pkt_offset));
	skb_pull(skb, sizeof(pkt_len));
	pkt_len -= sizeof(pkt_len);

	ieee_hdr = (void *)skb->data;
	if (ieee80211_is_mgmt(ieee_hdr->frame_control)) {
		ret = nxpwifi_parse_mgmt_packet(priv, (u8 *)ieee_hdr,
						pkt_len, rx_pd);
		if (ret)
			return ret;
	}
	/* Remove address4 */
	memmove(skb->data + sizeof(struct ieee80211_hdr_3addr),
		skb->data + sizeof(struct ieee80211_hdr),
		pkt_len - sizeof(struct ieee80211_hdr));

	pkt_len -= ETH_ALEN;
	rx_pd->rx_pkt_length = cpu_to_le16(pkt_len);

	if (priv->host_mlme_reg &&
	    (GET_BSS_ROLE(priv) != NXPWIFI_BSS_ROLE_UAP) &&
	    (ieee80211_is_auth(ieee_hdr->frame_control) ||
	     ieee80211_is_deauth(ieee_hdr->frame_control) ||
	     ieee80211_is_disassoc(ieee_hdr->frame_control))) {
		struct nxpwifi_rxinfo *rx_info;

		if (ieee80211_is_auth(ieee_hdr->frame_control)) {
			if (priv->auth_flag & HOST_MLME_AUTH_PENDING) {
				if (priv->auth_alg != WLAN_AUTH_SAE) {
					priv->auth_flag &=
						~HOST_MLME_AUTH_PENDING;
					priv->auth_flag |=
						HOST_MLME_AUTH_DONE;
				}
			} else {
				return 0;
			}

			nxpwifi_dbg(adapter, MSG,
				    "auth: receive authentication from %pM\n",
				    ieee_hdr->addr3);
		} else {
			if (!priv->wdev.connected)
				return 0;

			if (ieee80211_is_deauth(ieee_hdr->frame_control)) {
				nxpwifi_dbg(adapter, MSG,
					    "auth: receive deauth from %pM\n",
					    ieee_hdr->addr3);
				priv->auth_flag = 0;
				priv->auth_alg = WLAN_AUTH_NONE;
			} else {
				nxpwifi_dbg(adapter, MSG,
					    "assoc: receive disassoc from %pM\n",
					    ieee_hdr->addr3);
			}
		}

		rx_info = NXPWIFI_SKB_RXCB(skb);
		rx_info->pkt_len = pkt_len;
		skb_queue_tail(&adapter->rx_mlme_q, skb);
		nxpwifi_queue_work(adapter, &adapter->host_mlme_work);
		return -EINPROGRESS;
	}

	if (GET_BSS_ROLE(priv) == NXPWIFI_BSS_ROLE_UAP) {
		if (ieee80211_is_auth(ieee_hdr->frame_control))
			nxpwifi_dbg(adapter, MSG,
				    "auth: receive auth from %pM\n",
				    ieee_hdr->addr2);
		if (ieee80211_is_deauth(ieee_hdr->frame_control))
			nxpwifi_dbg(adapter, MSG,
				    "auth: receive deauth from %pM\n",
				    ieee_hdr->addr2);
		if (ieee80211_is_disassoc(ieee_hdr->frame_control))
			nxpwifi_dbg(adapter, MSG,
				    "assoc: receive disassoc from %pM\n",
				    ieee_hdr->addr2);
		if (ieee80211_is_assoc_req(ieee_hdr->frame_control))
			nxpwifi_dbg(adapter, MSG,
				    "assoc: receive assoc req from %pM\n",
				    ieee_hdr->addr2);
		if (ieee80211_is_reassoc_req(ieee_hdr->frame_control))
			nxpwifi_dbg(adapter, MSG,
				    "assoc: receive reassoc req from %pM\n",
				    ieee_hdr->addr2);
	}

	cfg80211_rx_mgmt(&priv->wdev, priv->roc_cfg.chan.center_freq,
			 CAL_RSSI(rx_pd->snr, rx_pd->nf), skb->data, pkt_len,
			 0);

	return 0;
}

/* This function processes the received packet before sending it to the
 * kernel.
 *
 * It extracts the SKB from the received buffer and sends it to kernel.
 * In case the received buffer does not contain the data in SKB format,
 * the function creates a blank SKB, fills it with the data from the
 * received buffer and then sends this new SKB to the kernel.
 */
int nxpwifi_recv_packet(struct nxpwifi_private *priv, struct sk_buff *skb)
{
	struct nxpwifi_sta_node *src_node;
	struct ethhdr *p_ethhdr;

	if (!skb)
		return -ENOMEM;

	priv->stats.rx_bytes += skb->len;
	priv->stats.rx_packets++;

	if (GET_BSS_ROLE(priv) == NXPWIFI_BSS_ROLE_UAP) {
		p_ethhdr = (void *)skb->data;
		src_node = nxpwifi_get_sta_entry(priv, p_ethhdr->h_source);
		if (src_node) {
			src_node->stats.last_rx = jiffies;
			src_node->stats.rx_bytes += skb->len;
			src_node->stats.rx_packets++;
		}
	}

	skb->dev = priv->netdev;
	skb->protocol = eth_type_trans(skb, priv->netdev);
	skb->ip_summed = CHECKSUM_NONE;

	netif_rx(skb);
	return 0;
}

/* IOCTL completion callback handler.
 *
 * This function is called when a pending IOCTL is completed.
 *
 * If work queue support is enabled, the function wakes up the
 * corresponding waiting function. Otherwise, it processes the
 * IOCTL response and frees the response buffer.
 */
int nxpwifi_complete_cmd(struct nxpwifi_adapter *adapter,
			 struct cmd_ctrl_node *cmd_node)
{
	WARN_ON(!cmd_node->wait_q_enabled);
	nxpwifi_dbg(adapter, CMD, "cmd completed: status=%d\n",
		    adapter->cmd_wait_q.status);

	*cmd_node->condition = true;
	wake_up_interruptible(&adapter->cmd_wait_q.wait);

	return 0;
}

/* This function will return the pointer to station entry in station list
 * table which matches specified mac address.
 * This function should be called after acquiring RA list spinlock.
 * NULL is returned if station entry is not found in associated STA list.
 */
struct nxpwifi_sta_node *
nxpwifi_get_sta_entry(struct nxpwifi_private *priv, const u8 *mac)
{
	struct nxpwifi_sta_node *node;

	if (!mac)
		return NULL;

	list_for_each_entry(node, &priv->sta_list, list) {
		if (!memcmp(node->mac_addr, mac, ETH_ALEN))
			return node;
	}

	return NULL;
}

/* This function will add a sta_node entry to associated station list
 * table with the given mac address.
 * If entry exist already, existing entry is returned.
 * If received mac address is NULL, NULL is returned.
 */
struct nxpwifi_sta_node *
nxpwifi_add_sta_entry(struct nxpwifi_private *priv, const u8 *mac)
{
	struct nxpwifi_sta_node *node;

	if (!mac)
		return NULL;

	spin_lock_bh(&priv->sta_list_spinlock);
	node = nxpwifi_get_sta_entry(priv, mac);
	if (node)
		goto done;

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (!node)
		goto done;

	memcpy(node->mac_addr, mac, ETH_ALEN);
	list_add_tail(&node->list, &priv->sta_list);

done:
	spin_unlock_bh(&priv->sta_list_spinlock);
	return node;
}

/* This function will search for HT IE in association request IEs
 * and set station HT parameters accordingly.
 */
void
nxpwifi_set_sta_ht_cap(struct nxpwifi_private *priv, const u8 *ies,
		       int ies_len, struct nxpwifi_sta_node *node)
{
	struct element *ht_cap_ie;
	const struct ieee80211_ht_cap *ht_cap;

	if (!ies)
		return;

	ht_cap_ie = (void *)cfg80211_find_ie(WLAN_EID_HT_CAPABILITY, ies,
					     ies_len);
	if (ht_cap_ie) {
		ht_cap = (void *)(ht_cap_ie + 1);
		node->is_11n_enabled = 1;
		node->max_amsdu = le16_to_cpu(ht_cap->cap_info) &
				  IEEE80211_HT_CAP_MAX_AMSDU ?
				  NXPWIFI_TX_DATA_BUF_SIZE_8K :
				  NXPWIFI_TX_DATA_BUF_SIZE_4K;
	} else {
		node->is_11n_enabled = 0;
	}
}

/* This function will delete a station entry from station list */
void nxpwifi_del_sta_entry(struct nxpwifi_private *priv, const u8 *mac)
{
	struct nxpwifi_sta_node *node;

	spin_lock_bh(&priv->sta_list_spinlock);

	node = nxpwifi_get_sta_entry(priv, mac);
	if (node) {
		list_del(&node->list);
		kfree(node);
	}

	spin_unlock_bh(&priv->sta_list_spinlock);
}

/* This function will delete all stations from associated station list. */
void nxpwifi_del_all_sta_list(struct nxpwifi_private *priv)
{
	struct nxpwifi_sta_node *node, *tmp;

	spin_lock_bh(&priv->sta_list_spinlock);

	list_for_each_entry_safe(node, tmp, &priv->sta_list, list) {
		list_del(&node->list);
		kfree(node);
	}

	INIT_LIST_HEAD(&priv->sta_list);
	spin_unlock_bh(&priv->sta_list_spinlock);
}

/* This function adds histogram data to histogram array*/
void nxpwifi_hist_data_add(struct nxpwifi_private *priv,
			   u8 rx_rate, s8 snr, s8 nflr)
{
	struct nxpwifi_histogram_data *phist_data = priv->hist_data;

	if (atomic_read(&phist_data->num_samples) > NXPWIFI_HIST_MAX_SAMPLES)
		nxpwifi_hist_data_reset(priv);
	nxpwifi_hist_data_set(priv, rx_rate, snr, nflr);
}

/* function to add histogram record */
void nxpwifi_hist_data_set(struct nxpwifi_private *priv, u8 rx_rate, s8 snr,
			   s8 nflr)
{
	struct nxpwifi_histogram_data *phist_data = priv->hist_data;
	s8 nf   = -nflr;
	s8 rssi = snr - nflr;

	atomic_inc(&phist_data->num_samples);
	atomic_inc(&phist_data->rx_rate[rx_rate]);
	atomic_inc(&phist_data->snr[snr + 128]);
	atomic_inc(&phist_data->noise_flr[nf + 128]);
	atomic_inc(&phist_data->sig_str[rssi + 128]);
}

/* function to reset histogram data during init/reset */
void nxpwifi_hist_data_reset(struct nxpwifi_private *priv)
{
	int ix;
	struct nxpwifi_histogram_data *phist_data = priv->hist_data;

	atomic_set(&phist_data->num_samples, 0);
	for (ix = 0; ix < NXPWIFI_MAX_AC_RX_RATES; ix++)
		atomic_set(&phist_data->rx_rate[ix], 0);
	for (ix = 0; ix < NXPWIFI_MAX_SNR; ix++)
		atomic_set(&phist_data->snr[ix], 0);
	for (ix = 0; ix < NXPWIFI_MAX_NOISE_FLR; ix++)
		atomic_set(&phist_data->noise_flr[ix], 0);
	for (ix = 0; ix < NXPWIFI_MAX_SIG_STRENGTH; ix++)
		atomic_set(&phist_data->sig_str[ix], 0);
}

void *nxpwifi_alloc_dma_align_buf(int rx_len, gfp_t flags)
{
	struct sk_buff *skb;
	int buf_len, pad;

	buf_len = rx_len + NXPWIFI_RX_HEADROOM + NXPWIFI_DMA_ALIGN_SZ;

	skb = __dev_alloc_skb(buf_len, flags);

	if (!skb)
		return NULL;

	skb_reserve(skb, NXPWIFI_RX_HEADROOM);

	pad = NXPWIFI_ALIGN_ADDR(skb->data, NXPWIFI_DMA_ALIGN_SZ) -
	      (long)skb->data;

	skb_reserve(skb, pad);

	return skb;
}
EXPORT_SYMBOL_GPL(nxpwifi_alloc_dma_align_buf);

void nxpwifi_fw_dump_event(struct nxpwifi_private *priv)
{
	nxpwifi_send_cmd(priv, HOST_CMD_FW_DUMP_EVENT, HOST_ACT_GEN_SET,
			 0, NULL, true);
}
EXPORT_SYMBOL_GPL(nxpwifi_fw_dump_event);

int nxpwifi_append_data_tlv(u16 id, u8 *data, int len, u8 *pos, u8 *cmd_end)
{
	struct nxpwifi_ie_types_data *tlv;
	u16 header_len = sizeof(struct nxpwifi_ie_types_header);

	tlv = (struct nxpwifi_ie_types_data *)pos;
	tlv->header.len = cpu_to_le16(len);

	if (id == WLAN_EID_EXT_HE_CAPABILITY) {
		if ((pos + header_len + len + 1) > cmd_end)
			return 0;

		tlv->header.type = cpu_to_le16(WLAN_EID_EXTENSION);
		tlv->data[0] = WLAN_EID_EXT_HE_CAPABILITY;
		memcpy(tlv->data + 1, data, len);
	} else {
		if ((pos + header_len + len) > cmd_end)
			return 0;

		tlv->header.type = cpu_to_le16(id);
		memcpy(tlv->data, data, len);
	}

	return (header_len + len);
}

static int nxpwifi_get_vdll_image(struct nxpwifi_adapter *adapter, u32 vdll_len)
{
	struct vdll_dnld_ctrl *ctrl = &adapter->vdll_ctrl;
	bool req_fw = false;
	u32 offset;

	if (ctrl->vdll_mem) {
		nxpwifi_dbg(adapter, EVENT,
			    "VDLL mem is not empty: %p old_len=%d new_len=%d\n",
			    ctrl->vdll_mem, ctrl->vdll_len, vdll_len);
		vfree(ctrl->vdll_mem);
		ctrl->vdll_mem = NULL;
		ctrl->vdll_len = 0;
	}

	ctrl->vdll_mem = vmalloc(vdll_len);
	if (!ctrl->vdll_mem)
		return -ENOMEM;

	if (!adapter->firmware) {
		req_fw = true;
		if (request_firmware(&adapter->firmware, adapter->fw_name,
				     adapter->dev))
			return -ENOENT;
	}

	if (adapter->firmware) {
		if (vdll_len < adapter->firmware->size) {
			offset = adapter->firmware->size - vdll_len;
			memcpy(ctrl->vdll_mem, adapter->firmware->data + offset,
			       vdll_len);
		} else {
			nxpwifi_dbg(adapter, ERROR,
				    "Invalid VDLL length = %d, fw_len=%d\n",
				    vdll_len, (int)adapter->firmware->size);
			return -EINVAL;
		}
		if (req_fw) {
			release_firmware(adapter->firmware);
			adapter->firmware = NULL;
		}
	}

	ctrl->vdll_len = vdll_len;
	nxpwifi_dbg(adapter, MSG, "VDLL image: len=%d\n", ctrl->vdll_len);

	return 0;
}

int nxpwifi_download_vdll_block(struct nxpwifi_adapter *adapter,
				u8 *block, u16 block_len)
{
	struct vdll_dnld_ctrl *ctrl = &adapter->vdll_ctrl;
	struct host_cmd_ds_command *host_cmd;
	u16 msg_len = block_len + S_DS_GEN;
	int ret = 0;

	skb_trim(ctrl->skb, 0);
	skb_put_zero(ctrl->skb, msg_len);

	host_cmd = (struct host_cmd_ds_command *)(ctrl->skb->data);

	host_cmd->command = cpu_to_le16(HOST_CMD_VDLL);
	host_cmd->seq_num = cpu_to_le16(0xFF00);
	host_cmd->size = cpu_to_le16(msg_len);
	memcpy(ctrl->skb->data + S_DS_GEN, block, block_len);

	skb_push(ctrl->skb, adapter->intf_hdr_len);
	ret = adapter->if_ops.host_to_card(adapter, NXPWIFI_TYPE_VDLL,
					   ctrl->skb, NULL);
	skb_pull(ctrl->skb, adapter->intf_hdr_len);

	if (ret)
		nxpwifi_dbg(adapter, ERROR,
			    "Fail to download VDLL: block: %p, len: %d\n",
			    block, block_len);

	return ret;
}

int nxpwifi_process_vdll_event(struct nxpwifi_private *priv,
			       struct sk_buff *skb)
{
	struct nxpwifi_adapter *adapter = priv->adapter;
	struct vdll_ind_event *vdll_evt =
		(struct vdll_ind_event *)(skb->data + sizeof(u32));
	u16 type = le16_to_cpu(vdll_evt->type);
	u16 vdll_id = le16_to_cpu(vdll_evt->vdll_id);
	u32 offset = le32_to_cpu(vdll_evt->offset);
	u16 block_len = le16_to_cpu(vdll_evt->block_len);
	struct vdll_dnld_ctrl *ctrl = &adapter->vdll_ctrl;
	int ret = 0;

	switch (type) {
	case VDLL_IND_TYPE_REQ:
		nxpwifi_dbg(adapter, EVENT,
			    "VDLL IND (REG): ID: %d, offset: %#x, len: %d\n",
			    vdll_id, offset, block_len);
		if (offset <= ctrl->vdll_len) {
			block_len =
				min((u32)block_len, ctrl->vdll_len - offset);
			if (!adapter->cmd_sent) {
				ret = nxpwifi_download_vdll_block(adapter,
								  ctrl->vdll_mem
								  + offset,
								  block_len);
				if (ret)
					nxpwifi_dbg(adapter, ERROR,
						    "Download VDLL failed\n");
			} else {
				nxpwifi_dbg(adapter, EVENT,
					    "Delay download VDLL block\n");
				ctrl->pending_block_len = block_len;
				ctrl->pending_block = ctrl->vdll_mem + offset;
			}
		} else {
			nxpwifi_dbg(adapter, ERROR,
				    "Err Req: offset=%#x, len=%d, vdll_len=%d\n",
				    offset, block_len, ctrl->vdll_len);
			ret = -EINVAL;
		}
		break;
	case VDLL_IND_TYPE_OFFSET:
		nxpwifi_dbg(adapter, EVENT,
			    "VDLL IND (OFFSET): offset: %#x\n", offset);
		ret = nxpwifi_get_vdll_image(adapter, offset);
		break;
	case VDLL_IND_TYPE_ERR_SIG:
	case VDLL_IND_TYPE_ERR_ID:
	case VDLL_IND_TYPE_SEC_ERR_ID:
		nxpwifi_dbg(adapter, ERROR, "VDLL IND: error: %d\n", type);
		break;
	case VDLL_IND_TYPE_INTF_RESET:
		nxpwifi_dbg(adapter, EVENT, "VDLL IND: interface reset\n");
		break;
	default:
		nxpwifi_dbg(adapter, ERROR, "VDLL IND: unknown type: %d", type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

u64 nxpwifi_roc_cookie(struct nxpwifi_adapter *adapter)
{
	adapter->roc_cookie_counter++;

	/* wow, you wrapped 64 bits ... more likely a bug */
	if (WARN_ON(adapter->roc_cookie_counter == 0))
		adapter->roc_cookie_counter++;

	return adapter->roc_cookie_counter;
}

static bool nxpwifi_can_queue_work(struct nxpwifi_adapter *adapter)
{
	if (test_bit(NXPWIFI_SURPRISE_REMOVED, &adapter->work_flags) ||
	    test_bit(NXPWIFI_IS_CMD_TIMEDOUT, &adapter->work_flags) ||
	    test_bit(NXPWIFI_IS_SUSPENDED, &adapter->work_flags)) {
		nxpwifi_dbg(adapter, WARN,
			    "queueing nxpwifi work while going to suspend\n");
		return false;
	}

	return true;
}

void nxpwifi_queue_work(struct nxpwifi_adapter *adapter,
			struct work_struct *work)
{
	if (!nxpwifi_can_queue_work(adapter))
		return;

	queue_work(adapter->workqueue, work);
}
EXPORT_SYMBOL(nxpwifi_queue_work);

void nxpwifi_queue_delayed_work(struct nxpwifi_adapter *adapter,
				struct delayed_work *dwork,
				unsigned long delay)
{
	if (!nxpwifi_can_queue_work(adapter))
		return;

	queue_delayed_work(adapter->workqueue, dwork, delay);
}
EXPORT_SYMBOL(nxpwifi_queue_delayed_work);
