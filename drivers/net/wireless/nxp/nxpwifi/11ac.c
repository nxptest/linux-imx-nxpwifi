// SPDX-License-Identifier: GPL-2.0-only
/*
 * NXP Wireless LAN device driver: 802.11ac
 *
 * Copyright 2011-2024 NXP
 */

#include "cfg.h"
#include "fw.h"
#include "main.h"
#include "11ac.h"

/* Tables of the MCS map to the highest data rate (in Mbps) supported
 * for long GI.
 */
static const u16 max_rate_lgi_80MHZ[8][3] = {
	{0x124, 0x15F, 0x186},	/* NSS = 1 */
	{0x249, 0x2BE, 0x30C},  /* NSS = 2 */
	{0x36D, 0x41D, 0x492},  /* NSS = 3 */
	{0x492, 0x57C, 0x618},  /* NSS = 4 */
	{0x5B6, 0x6DB, 0x79E},  /* NSS = 5 */
	{0x6DB, 0x83A, 0x0},    /* NSS = 6 */
	{0x7FF, 0x999, 0xAAA},  /* NSS = 7 */
	{0x924, 0xAF8, 0xC30}   /* NSS = 8 */
};

static const u16 max_rate_lgi_160MHZ[8][3] = {
	{0x249, 0x2BE, 0x30C},   /* NSS = 1 */
	{0x492, 0x57C, 0x618},   /* NSS = 2 */
	{0x6DB, 0x83A, 0x0},     /* NSS = 3 */
	{0x924, 0xAF8, 0xC30},   /* NSS = 4 */
	{0xB6D, 0xDB6, 0xF3C},   /* NSS = 5 */
	{0xDB6, 0x1074, 0x1248}, /* NSS = 6 */
	{0xFFF, 0x1332, 0x1554}, /* NSS = 7 */
	{0x1248, 0x15F0, 0x1860} /* NSS = 8 */
};

/* This function converts the 2-bit MCS map to the highest long GI
 * VHT data rate.
 */
static u16
nxpwifi_convert_mcsmap_to_maxrate(struct nxpwifi_private *priv,
				  u16 bands, u16 mcs_map)
{
	u8 i, nss, mcs;
	u16 max_rate = 0;
	u32 usr_vht_cap_info = 0;
	struct nxpwifi_adapter *adapter = priv->adapter;

	if (bands & BAND_AAC)
		usr_vht_cap_info = adapter->usr_dot_11ac_dev_cap_a;
	else
		usr_vht_cap_info = adapter->usr_dot_11ac_dev_cap_bg;

	/* find the max NSS supported */
	nss = 1;
	for (i = 1; i <= 8; i++) {
		mcs = GET_VHTNSSMCS(mcs_map, i);
		if (mcs < IEEE80211_VHT_MCS_NOT_SUPPORTED)
			nss = i;
	}
	mcs = GET_VHTNSSMCS(mcs_map, nss);

	/* if mcs is 3, nss must be 1 (NSS = 1). Default mcs to MCS 0~9 */
	if (mcs == IEEE80211_VHT_MCS_NOT_SUPPORTED)
		mcs = IEEE80211_VHT_MCS_SUPPORT_0_9;

	if (GET_VHTCAP_CHWDSET(usr_vht_cap_info)) {
		/* support 160 MHz */
		max_rate = max_rate_lgi_160MHZ[nss - 1][mcs];
		if (!max_rate)
			/* MCS9 is not supported in NSS6 */
			max_rate = max_rate_lgi_160MHZ[nss - 1][mcs - 1];
	} else {
		max_rate = max_rate_lgi_80MHZ[nss - 1][mcs];
		if (!max_rate)
			/* MCS9 is not supported in NSS3 */
			max_rate = max_rate_lgi_80MHZ[nss - 1][mcs - 1];
	}

	return max_rate;
}

static void
nxpwifi_fill_vht_cap_info(struct nxpwifi_private *priv,
			  struct ieee80211_vht_cap *vht_cap, u16 bands)
{
	struct nxpwifi_adapter *adapter = priv->adapter;

	if (bands & BAND_A)
		vht_cap->vht_cap_info =
			cpu_to_le32(adapter->usr_dot_11ac_dev_cap_a);
	else
		vht_cap->vht_cap_info =
			cpu_to_le32(adapter->usr_dot_11ac_dev_cap_bg);
}

static void
nxpwifi_fill_vht_cap_tlv(struct nxpwifi_private *priv,
			 struct ieee80211_vht_cap *vht_cap, u16 bands)
{
	struct nxpwifi_adapter *adapter = priv->adapter;
	u16 mcs_map_user, mcs_map_resp, mcs_map_result;
	u16 mcs_user, mcs_resp, nss, tmp;

	/* Fill VHT cap info */
	nxpwifi_fill_vht_cap_info(priv, vht_cap, bands);

	/* rx MCS Set: find the minimum of the user rx mcs and ap rx mcs */
	mcs_map_user = GET_DEVRXMCSMAP(adapter->usr_dot_11ac_mcs_support);
	mcs_map_resp = le16_to_cpu(vht_cap->supp_mcs.rx_mcs_map);
	mcs_map_result = 0;

	for (nss = 1; nss <= 8; nss++) {
		mcs_user = GET_VHTNSSMCS(mcs_map_user, nss);
		mcs_resp = GET_VHTNSSMCS(mcs_map_resp, nss);

		if (mcs_user == IEEE80211_VHT_MCS_NOT_SUPPORTED ||
		    mcs_resp == IEEE80211_VHT_MCS_NOT_SUPPORTED)
			SET_VHTNSSMCS(mcs_map_result, nss,
				      IEEE80211_VHT_MCS_NOT_SUPPORTED);
		else
			SET_VHTNSSMCS(mcs_map_result, nss,
				      min(mcs_user, mcs_resp));
	}

	vht_cap->supp_mcs.rx_mcs_map = cpu_to_le16(mcs_map_result);

	tmp = nxpwifi_convert_mcsmap_to_maxrate(priv, bands, mcs_map_result);
	vht_cap->supp_mcs.rx_highest = cpu_to_le16(tmp);

	/* tx MCS Set: find the minimum of the user tx mcs and ap tx mcs */
	mcs_map_user = GET_DEVTXMCSMAP(adapter->usr_dot_11ac_mcs_support);
	mcs_map_resp = le16_to_cpu(vht_cap->supp_mcs.tx_mcs_map);
	mcs_map_result = 0;

	for (nss = 1; nss <= 8; nss++) {
		mcs_user = GET_VHTNSSMCS(mcs_map_user, nss);
		mcs_resp = GET_VHTNSSMCS(mcs_map_resp, nss);
		if (mcs_user == IEEE80211_VHT_MCS_NOT_SUPPORTED ||
		    mcs_resp == IEEE80211_VHT_MCS_NOT_SUPPORTED)
			SET_VHTNSSMCS(mcs_map_result, nss,
				      IEEE80211_VHT_MCS_NOT_SUPPORTED);
		else
			SET_VHTNSSMCS(mcs_map_result, nss,
				      min(mcs_user, mcs_resp));
	}

	vht_cap->supp_mcs.tx_mcs_map = cpu_to_le16(mcs_map_result);

	tmp = nxpwifi_convert_mcsmap_to_maxrate(priv, bands, mcs_map_result);
	vht_cap->supp_mcs.tx_highest = cpu_to_le16(tmp);
}

int nxpwifi_cmd_append_11ac_tlv(struct nxpwifi_private *priv,
				struct nxpwifi_bssdescriptor *bss_desc,
				u8 **buffer)
{
	struct nxpwifi_ie_types_vhtcap *vht_cap;
	struct nxpwifi_ie_types_oper_mode_ntf *oper_ntf;
	struct ieee_types_oper_mode_ntf *ieee_oper_ntf;
	struct nxpwifi_ie_types_vht_oper *vht_op;
	struct nxpwifi_adapter *adapter = priv->adapter;
	u8 supp_chwd_set;
	u32 usr_vht_cap_info;
	int ret_len = 0;

	if (bss_desc->bss_band & BAND_A)
		usr_vht_cap_info = adapter->usr_dot_11ac_dev_cap_a;
	else
		usr_vht_cap_info = adapter->usr_dot_11ac_dev_cap_bg;

	/* VHT Capabilities IE */
	if (bss_desc->bcn_vht_cap) {
		vht_cap = (struct nxpwifi_ie_types_vhtcap *)*buffer;
		memset(vht_cap, 0, sizeof(*vht_cap));
		vht_cap->header.type = cpu_to_le16(WLAN_EID_VHT_CAPABILITY);
		vht_cap->header.len  =
			cpu_to_le16(sizeof(struct ieee80211_vht_cap));
		memcpy((u8 *)vht_cap + sizeof(struct nxpwifi_ie_types_header),
		       (u8 *)bss_desc->bcn_vht_cap,
		       le16_to_cpu(vht_cap->header.len));

		nxpwifi_fill_vht_cap_tlv(priv, &vht_cap->vht_cap,
					 bss_desc->bss_band);
		*buffer += sizeof(*vht_cap);
		ret_len += sizeof(*vht_cap);
	}

	/* VHT Operation IE */
	if (bss_desc->bcn_vht_oper) {
		if (priv->bss_mode == NL80211_IFTYPE_STATION) {
			vht_op = (struct nxpwifi_ie_types_vht_oper *)*buffer;
			memset(vht_op, 0, sizeof(*vht_op));
			vht_op->header.type =
				cpu_to_le16(WLAN_EID_VHT_OPERATION);
			vht_op->header.len  = cpu_to_le16(sizeof(*vht_op) -
				sizeof(struct nxpwifi_ie_types_header));
			memcpy((u8 *)vht_op +
				sizeof(struct nxpwifi_ie_types_header),
			       (u8 *)bss_desc->bcn_vht_oper,
			       le16_to_cpu(vht_op->header.len));

			/* negotiate the channel width and central freq
			 * and keep the central freq as the peer suggests
			 */
			supp_chwd_set = GET_VHTCAP_CHWDSET(usr_vht_cap_info);

			switch (supp_chwd_set) {
			case 0:
				vht_op->chan_width =
				     min_t(u8, IEEE80211_VHT_CHANWIDTH_80MHZ,
					   bss_desc->bcn_vht_oper->chan_width);
				break;
			case 1:
				vht_op->chan_width =
				     min_t(u8, IEEE80211_VHT_CHANWIDTH_160MHZ,
					   bss_desc->bcn_vht_oper->chan_width);
				break;
			case 2:
				vht_op->chan_width =
				     min_t(u8, IEEE80211_VHT_CHANWIDTH_80P80MHZ,
					   bss_desc->bcn_vht_oper->chan_width);
				break;
			default:
				vht_op->chan_width =
				     IEEE80211_VHT_CHANWIDTH_USE_HT;
				break;
			}

			*buffer += sizeof(*vht_op);
			ret_len += sizeof(*vht_op);
		}
	}

	/* Operating Mode Notification IE */
	if (bss_desc->oper_mode) {
		ieee_oper_ntf = bss_desc->oper_mode;
		oper_ntf = (void *)*buffer;
		memset(oper_ntf, 0, sizeof(*oper_ntf));
		oper_ntf->header.type = cpu_to_le16(WLAN_EID_OPMODE_NOTIF);
		oper_ntf->header.len = cpu_to_le16(sizeof(u8));
		oper_ntf->oper_mode = ieee_oper_ntf->oper_mode;
		*buffer += sizeof(*oper_ntf);
		ret_len += sizeof(*oper_ntf);
	}

	return ret_len;
}

int nxpwifi_cmd_11ac_cfg(struct nxpwifi_private *priv,
			 struct host_cmd_ds_command *cmd, u16 cmd_action,
			 struct nxpwifi_11ac_vht_cfg *cfg)
{
	struct host_cmd_11ac_vht_cfg *vhtcfg = &cmd->params.vht_cfg;

	cmd->command = cpu_to_le16(HOST_CMD_11AC_CFG);
	cmd->size = cpu_to_le16(sizeof(struct host_cmd_11ac_vht_cfg) +
				S_DS_GEN);
	vhtcfg->action = cpu_to_le16(cmd_action);
	vhtcfg->band_config = cfg->band_config;
	vhtcfg->misc_config = cfg->misc_config;
	vhtcfg->cap_info = cpu_to_le32(cfg->cap_info);
	vhtcfg->mcs_tx_set = cpu_to_le32(cfg->mcs_tx_set);
	vhtcfg->mcs_rx_set = cpu_to_le32(cfg->mcs_rx_set);

	return 0;
}

/* This function initializes the BlockACK setup information for given
 * nxpwifi_private structure for 11ac enabled networks.
 */
void nxpwifi_set_11ac_ba_params(struct nxpwifi_private *priv)
{
	priv->add_ba_param.timeout = NXPWIFI_DEFAULT_BLOCK_ACK_TIMEOUT;

	if (GET_BSS_ROLE(priv) == NXPWIFI_BSS_ROLE_UAP) {
		priv->add_ba_param.tx_win_size =
			NXPWIFI_11AC_UAP_AMPDU_DEF_TXWINSIZE;
		priv->add_ba_param.rx_win_size =
			NXPWIFI_11AC_UAP_AMPDU_DEF_RXWINSIZE;
	} else {
		priv->add_ba_param.tx_win_size =
			NXPWIFI_11AC_STA_AMPDU_DEF_TXWINSIZE;
		priv->add_ba_param.rx_win_size =
			NXPWIFI_11AC_STA_AMPDU_DEF_RXWINSIZE;
	}
}
