// SPDX-License-Identifier: GPL-2.0-only
/*
 * NXP Wireless LAN device driver: 802.11ax
 *
 * Copyright 2011-2024 NXP
 */

#include "decl.h"
#include "cfg.h"
#include "fw.h"
#include "main.h"
#include "11ax.h"

void nxpwifi_update_11ax_cap(struct nxpwifi_adapter *adapter,
			     struct hw_spec_extension *hw_he_cap)
{
	struct nxpwifi_private *priv;
	struct nxpwifi_ie_types_he_cap *he_cap = NULL;
	struct nxpwifi_ie_types_he_cap *user_he_cap = NULL;
	u8 header_len = sizeof(struct nxpwifi_ie_types_header);
	u16 data_len = le16_to_cpu(hw_he_cap->header.len);
	bool he_cap_2g = false;
	int i;

	if ((data_len + header_len) > sizeof(adapter->hw_he_cap)) {
		nxpwifi_dbg(adapter, ERROR,
			    "hw_he_cap too big, len=%d\n",
			    data_len);
		return;
	}

	he_cap = (struct nxpwifi_ie_types_he_cap *)hw_he_cap;

	if (he_cap->he_phy_cap[0] &
	    (AX_2G_40MHZ_SUPPORT | AX_2G_20MHZ_SUPPORT)) {
		adapter->hw_2g_he_cap_len = data_len + header_len;
		memcpy(adapter->hw_2g_he_cap, (u8 *)hw_he_cap,
		       adapter->hw_2g_he_cap_len);
		adapter->fw_bands |= BAND_GAX;
		he_cap_2g = true;
		nxpwifi_dbg_dump(adapter, CMD_D, "2.4G HE capability IE ",
				 adapter->hw_2g_he_cap,
				 adapter->hw_2g_he_cap_len);
	} else {
		adapter->hw_he_cap_len = data_len + header_len;
		memcpy(adapter->hw_he_cap, (u8 *)hw_he_cap,
		       adapter->hw_he_cap_len);
		adapter->fw_bands |= BAND_AAX;
		nxpwifi_dbg_dump(adapter, CMD_D, "5G HE capability IE ",
				 adapter->hw_he_cap,
				 adapter->hw_he_cap_len);
	}

	for (i = 0; i < adapter->priv_num; i++) {
		priv = adapter->priv[i];

		if (he_cap_2g) {
			priv->user_2g_he_cap_len = adapter->hw_2g_he_cap_len;
			memcpy(priv->user_2g_he_cap, adapter->hw_2g_he_cap,
			       sizeof(adapter->hw_2g_he_cap));
			user_he_cap = (struct nxpwifi_ie_types_he_cap *)
				priv->user_2g_he_cap;
		} else {
			priv->user_he_cap_len = adapter->hw_he_cap_len;
			memcpy(priv->user_he_cap, adapter->hw_he_cap,
			       sizeof(adapter->hw_he_cap));
			user_he_cap = (struct nxpwifi_ie_types_he_cap *)
				priv->user_he_cap;
		}

		if (GET_BSS_ROLE(priv) == NXPWIFI_BSS_ROLE_STA)
			user_he_cap->he_mac_cap[0] &=
				HE_MAC_CAP_TWT_RESP_SUPPORT;
		else
			user_he_cap->he_mac_cap[0] &=
				HE_MAC_CAP_TWT_REQ_SUPPORT;
	}

	adapter->is_hw_11ax_capable = true;
}

bool nxpwifi_11ax_bandconfig_allowed(struct nxpwifi_private *priv,
				     struct nxpwifi_bssdescriptor *bss_desc)
{
	u16 bss_band = bss_desc->bss_band;

	if (bss_desc->disable_11n)
		return false;

	if (bss_band & BAND_G)
		return (priv->config_bands & BAND_GAX);
	else if (bss_band & BAND_A)
		return (priv->config_bands & BAND_AAX);

	return false;
}

int nxpwifi_cmd_append_11ax_tlv(struct nxpwifi_private *priv,
				struct nxpwifi_bssdescriptor *bss_desc,
				u8 **buffer)
{
	struct nxpwifi_adapter *adapter = priv->adapter;
	struct nxpwifi_ie_types_he_cap *he_cap = NULL;
	struct nxpwifi_ie_types_he_cap *hw_he_cap = NULL;
	int ret_len;
	u16 rx_nss, tx_nss;
	u8 nss;
	u16 cfg_value;
	u16 hw_value;

	if (!bss_desc->bcn_he_cap)
		return -EOPNOTSUPP;

	he_cap = (struct nxpwifi_ie_types_he_cap *)*buffer;
	if (bss_desc->bss_band & BAND_A) {
		memcpy(*buffer, priv->user_he_cap, priv->user_he_cap_len);
		*buffer += priv->user_he_cap_len;
		ret_len = priv->user_he_cap_len;
		hw_he_cap = (struct nxpwifi_ie_types_he_cap *)
			adapter->hw_he_cap;
	} else {
		memcpy(*buffer, priv->user_2g_he_cap, priv->user_2g_he_cap_len);
		*buffer += priv->user_2g_he_cap_len;
		ret_len = priv->user_2g_he_cap_len;
		hw_he_cap = (struct nxpwifi_ie_types_he_cap *)
			adapter->hw_2g_he_cap;
	}

	if (bss_desc->bss_band & BAND_A) {
		rx_nss = GET_RXMCSSUPP(adapter->user_htstream >> 8);
		tx_nss = GET_TXMCSSUPP(adapter->user_htstream >> 8) & 0x0f;
	} else {
		rx_nss = GET_RXMCSSUPP(adapter->user_htstream);
		tx_nss = GET_TXMCSSUPP(adapter->user_htstream) & 0x0f;
	}

	for (nss = 1; nss <= 8; nss++) {
		cfg_value = nxpwifi_get_he_nss_mcs(he_cap->rx_mcs_80, nss);
		hw_value = nxpwifi_get_he_nss_mcs(hw_he_cap->rx_mcs_80, nss);
		if (rx_nss != 0 && nss > rx_nss)
			cfg_value = NO_NSS_SUPPORT;
		if (hw_value == NO_NSS_SUPPORT ||
		    cfg_value == NO_NSS_SUPPORT)
			nxpwifi_set_he_nss_mcs(&he_cap->rx_mcs_80, nss,
					       NO_NSS_SUPPORT);
		else
			nxpwifi_set_he_nss_mcs(&he_cap->rx_mcs_80, nss,
					       min(cfg_value, hw_value));
	}

	for (nss = 1; nss <= 8; nss++) {
		cfg_value = nxpwifi_get_he_nss_mcs(he_cap->tx_mcs_80, nss);
		hw_value = nxpwifi_get_he_nss_mcs(hw_he_cap->tx_mcs_80, nss);
		if (tx_nss != 0 && nss > tx_nss)
			cfg_value = NO_NSS_SUPPORT;
		if (hw_value == NO_NSS_SUPPORT ||
		    cfg_value == NO_NSS_SUPPORT)
			nxpwifi_set_he_nss_mcs(&he_cap->tx_mcs_80, nss,
					       NO_NSS_SUPPORT);
		else
			nxpwifi_set_he_nss_mcs(&he_cap->tx_mcs_80, nss,
					       min(cfg_value, hw_value));
	}

	return ret_len;
}

int nxpwifi_cmd_11ax_cfg(struct nxpwifi_private *priv,
			 struct host_cmd_ds_command *cmd, u16 cmd_action,
			 struct nxpwifi_11ax_he_cfg *ax_cfg)
{
	struct host_cmd_11ax_cfg *he_cfg = &cmd->params.ax_cfg;
	u16 cmd_size;
	struct nxpwifi_ie_types_header *header;

	cmd->command = cpu_to_le16(HOST_CMD_11AX_CFG);
	cmd_size = sizeof(struct host_cmd_11ax_cfg) + S_DS_GEN;

	he_cfg->action = cpu_to_le16(cmd_action);
	he_cfg->band_config = ax_cfg->band;

	if (ax_cfg->he_cap_cfg.len &&
	    ax_cfg->he_cap_cfg.ext_id == WLAN_EID_EXT_HE_CAPABILITY) {
		header = (struct nxpwifi_ie_types_header *)he_cfg->tlv;
		header->type = cpu_to_le16(ax_cfg->he_cap_cfg.id);
		header->len = cpu_to_le16(ax_cfg->he_cap_cfg.len);
		memcpy(he_cfg->tlv + sizeof(*header),
		       &ax_cfg->he_cap_cfg.ext_id,
		       ax_cfg->he_cap_cfg.len);
		cmd_size += (sizeof(*header) + ax_cfg->he_cap_cfg.len);
	}

	cmd->size = cpu_to_le16(cmd_size);

	return 0;
}

int nxpwifi_ret_11ax_cfg(struct nxpwifi_private *priv,
			 struct host_cmd_ds_command *resp,
			 struct nxpwifi_11ax_he_cfg *ax_cfg)
{
	struct host_cmd_11ax_cfg *he_cfg = &resp->params.ax_cfg;
	struct nxpwifi_ie_types_header *header;
	u16 left_len, tlv_type, tlv_len;
	u8 ext_id;
	struct nxpwifi_11ax_he_cap_cfg *he_cap = &ax_cfg->he_cap_cfg;

	left_len = resp->size - sizeof(*he_cfg) - S_DS_GEN;
	header = (struct nxpwifi_ie_types_header *)he_cfg->tlv;

	while (left_len > sizeof(*header)) {
		tlv_type = le16_to_cpu(header->type);
		tlv_len = le16_to_cpu(header->len);

		if (tlv_type == TLV_TYPE_EXTENSION_ID) {
			ext_id = *((u8 *)header + sizeof(*header) + 1);
			if (ext_id == WLAN_EID_EXT_HE_CAPABILITY) {
				he_cap->id = tlv_type;
				he_cap->len = tlv_len;
				memcpy((u8 *)&he_cap->ext_id,
				       (u8 *)header + sizeof(*header) + 1,
				       tlv_len);
				if (he_cfg->band_config & BIT(1)) {
					memcpy(priv->user_he_cap,
					       (u8 *)header,
					       sizeof(*header) + tlv_len);
					priv->user_he_cap_len =
						sizeof(*header) + tlv_len;
				} else {
					memcpy(priv->user_2g_he_cap,
					       (u8 *)header,
					       sizeof(*header) + tlv_len);
					priv->user_2g_he_cap_len =
						sizeof(*header) + tlv_len;
				}
			}
		}

		left_len -= (sizeof(*header) + tlv_len);
		header = (struct nxpwifi_ie_types_header *)((u8 *)header +
							    sizeof(*header) +
							    tlv_len);
	}

	return 0;
}

int nxpwifi_cmd_11ax_cmd(struct nxpwifi_private *priv,
			 struct host_cmd_ds_command *cmd, u16 cmd_action,
			 struct nxpwifi_11ax_cmd_cfg *ax_cmd)
{
	struct nxpwifi_adapter *adapter = priv->adapter;
	struct host_cmd_11ax_cmd *he_cmd = &cmd->params.ax_cmd;
	u16 cmd_size;

	cmd->command = cpu_to_le16(HOST_CMD_11AX_CMD);
	cmd_size = sizeof(struct host_cmd_11ax_cmd) + S_DS_GEN;

	he_cmd->action = cpu_to_le16(cmd_action);
	he_cmd->sub_id = cpu_to_le16(ax_cmd->sub_id);

	switch (ax_cmd->sub_command) {
	case NXPWIFI_11AXCMD_SR_SUBID:
		struct nxpwifi_11ax_sr_cmd *sr_cmd =
			(struct nxpwifi_11ax_sr_cmd *)&ax_cmd->param;
		struct nxpwifi_ie_types_data *tlv;

		tlv = (struct nxpwifi_ie_types_data *)he_cmd->val;
		tlv->header.type = cpu_to_le16(sr_cmd->type);
		tlv->header.len = cpu_to_le16(sr_cmd->len);
		memcpy(tlv->data, sr_cmd->param.obss_pd_offset.offset,
		       sr_cmd->len);
		cmd_size += (sizeof(tlv->header) + sr_cmd->len);
		break;
	case NXPWIFI_11AXCMD_BEAM_SUBID:
		struct nxpwifi_11ax_beam_cmd *beam_cmd =
			(struct nxpwifi_11ax_beam_cmd *)&ax_cmd->param;

		he_cmd->val[0] = beam_cmd->value;
		cmd_size += sizeof(*beam_cmd);
		break;
	case NXPWIFI_11AXCMD_HTC_SUBID:
		struct nxpwifi_11ax_htc_cmd *htc_cmd =
			(struct nxpwifi_11ax_htc_cmd *)&ax_cmd->param;

		he_cmd->val[0] = htc_cmd->value;
		cmd_size += sizeof(*htc_cmd);
		break;
	case NXPWIFI_11AXCMD_TXOMI_SUBID:
		struct nxpwifi_11ax_txomi_cmd *txmoi_cmd =
			(struct nxpwifi_11ax_txomi_cmd *)&ax_cmd->param;

		memcpy(he_cmd->val, &txmoi_cmd->omi, sizeof(*txmoi_cmd));
		cmd_size += sizeof(*txmoi_cmd);
		break;
	case NXPWIFI_11AXCMD_OBSS_TOLTIME_SUBID:
		struct nxpwifi_11ax_toltime_cmd *toltime_cmd =
			(struct nxpwifi_11ax_toltime_cmd *)&ax_cmd->param;

		memcpy(he_cmd->val, &toltime_cmd->tol_time,
		       sizeof(toltime_cmd->tol_time));
		cmd_size += sizeof(*toltime_cmd);
		break;
	case NXPWIFI_11AXCMD_TXOPRTS_SUBID:
		struct nxpwifi_11ax_txop_cmd *txop_cmd =
			(struct nxpwifi_11ax_txop_cmd *)&ax_cmd->param;

		memcpy(he_cmd->val, &txop_cmd->rts_thres,
		       sizeof(txop_cmd->rts_thres));
		cmd_size += sizeof(*txop_cmd);
		break;
	case NXPWIFI_11AXCMD_SET_BSRP_SUBID:
		struct nxpwifi_11ax_set_bsrp_cmd *set_bsrp_cmd =
			(struct nxpwifi_11ax_set_bsrp_cmd *)&ax_cmd->param;

		he_cmd->val[0] = set_bsrp_cmd->value;
		cmd_size += sizeof(*set_bsrp_cmd);
		break;
	case NXPWIFI_11AXCMD_LLDE_SUBID:
		struct nxpwifi_11ax_llde_cmd *llde_cmd =
			(struct nxpwifi_11ax_llde_cmd *)&ax_cmd->param;

		memcpy(he_cmd->val, &llde_cmd->llde, sizeof(*llde_cmd));
		cmd_size += sizeof(*llde_cmd);
		break;
	default:
		nxpwifi_dbg(adapter, ERROR,
			    "%s: Unknown sub command: %d\n",
			    __func__, ax_cmd->sub_command);
		return -EINVAL;
	}

	cmd->size = cpu_to_le16(cmd_size);

	return 0;
}

int nxpwifi_ret_11ax_cmd(struct nxpwifi_private *priv,
			 struct host_cmd_ds_command *resp,
			 struct nxpwifi_11ax_cmd_cfg *ax_cmd)
{
	struct nxpwifi_adapter *adapter = priv->adapter;
	struct host_cmd_11ax_cmd *he_cmd = &resp->params.ax_cmd;

	ax_cmd->sub_id = le16_to_cpu(he_cmd->sub_id);

	switch (ax_cmd->sub_command) {
	case NXPWIFI_11AXCMD_SR_SUBID:
		struct nxpwifi_ie_types_data *tlv;

		tlv = (struct nxpwifi_ie_types_data *)he_cmd->val;
		memcpy(ax_cmd->param.sr_cfg.param.obss_pd_offset.offset,
		       tlv->data,
		       ax_cmd->param.sr_cfg.len);
		break;
	case NXPWIFI_11AXCMD_BEAM_SUBID:
		ax_cmd->param.beam_cfg.value = *he_cmd->val;
		break;
	case NXPWIFI_11AXCMD_HTC_SUBID:
		ax_cmd->param.htc_cfg.value = *he_cmd->val;
		break;
	case NXPWIFI_11AXCMD_TXOMI_SUBID:
		memcpy(&ax_cmd->param.txomi_cfg.omi,
		       he_cmd->val, sizeof(ax_cmd->param.txomi_cfg));
		break;
	case NXPWIFI_11AXCMD_OBSS_TOLTIME_SUBID:
		memcpy(&ax_cmd->param.toltime_cfg.tol_time,
		       he_cmd->val, sizeof(ax_cmd->param.toltime_cfg));
		break;
	case NXPWIFI_11AXCMD_TXOPRTS_SUBID:
		memcpy(&ax_cmd->param.txop_cfg.rts_thres,
		       he_cmd->val, sizeof(ax_cmd->param.txop_cfg));
		break;
	case NXPWIFI_11AXCMD_SET_BSRP_SUBID:
		ax_cmd->param.setbsrp_cfg.value = *he_cmd->val;
		break;
	case NXPWIFI_11AXCMD_LLDE_SUBID:
		memcpy(&ax_cmd->param.llde_cfg.llde,
		       he_cmd->val, sizeof(ax_cmd->param.llde_cfg));
		break;
	default:
		nxpwifi_dbg(adapter, ERROR,
			    "%s: Unknown sub command: %d\n",
			    __func__, ax_cmd->sub_command);
		return -EINVAL;
	}

	return 0;
}
