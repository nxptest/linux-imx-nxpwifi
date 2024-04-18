/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * NXP Wireless LAN device driver: 802.11n
 *
 * Copyright 2011-2024 NXP
 */

#ifndef _NXPWIFI_11N_H_
#define _NXPWIFI_11N_H_

#include "11n_aggr.h"
#include "11n_rxreorder.h"
#include "wmm.h"

int nxpwifi_ret_11n_delba(struct nxpwifi_private *priv,
			  struct host_cmd_ds_command *resp);
int nxpwifi_ret_11n_addba_req(struct nxpwifi_private *priv,
			      struct host_cmd_ds_command *resp);
int nxpwifi_cmd_11n_cfg(struct nxpwifi_private *priv,
			struct host_cmd_ds_command *cmd, u16 cmd_action,
			struct nxpwifi_ds_11n_tx_cfg *txcfg);
int nxpwifi_cmd_append_11n_tlv(struct nxpwifi_private *priv,
			       struct nxpwifi_bssdescriptor *bss_desc,
			       u8 **buffer);
int nxpwifi_fill_cap_info(struct nxpwifi_private *priv, u8 radio_type,
			  struct ieee80211_ht_cap *ht_cap);
int nxpwifi_set_get_11n_htcap_cfg(struct nxpwifi_private *priv,
				  u16 action, int *htcap_cfg);
void nxpwifi_11n_delete_tx_ba_stream_tbl_entry(struct nxpwifi_private *priv,
					       struct nxpwifi_tx_ba_stream_tbl
					       *tx_tbl);
void nxpwifi_11n_delete_all_tx_ba_stream_tbl(struct nxpwifi_private *priv);
struct nxpwifi_tx_ba_stream_tbl *nxpwifi_get_ba_tbl(struct nxpwifi_private
						    *priv, int tid, u8 *ra);
void nxpwifi_create_ba_tbl(struct nxpwifi_private *priv, u8 *ra, int tid,
			   enum nxpwifi_ba_status ba_status);
int nxpwifi_send_addba(struct nxpwifi_private *priv, int tid, u8 *peer_mac);
int nxpwifi_send_delba(struct nxpwifi_private *priv, int tid, u8 *peer_mac,
		       int initiator);
void nxpwifi_11n_delete_ba_stream(struct nxpwifi_private *priv, u8 *del_ba);
int nxpwifi_get_rx_reorder_tbl(struct nxpwifi_private *priv,
			       struct nxpwifi_ds_rx_reorder_tbl *buf);
int nxpwifi_get_tx_ba_stream_tbl(struct nxpwifi_private *priv,
				 struct nxpwifi_ds_tx_ba_stream_tbl *buf);
int nxpwifi_cmd_recfg_tx_buf(struct nxpwifi_private *priv,
			     struct host_cmd_ds_command *cmd,
			     int cmd_action, u16 *buf_size);
int nxpwifi_cmd_amsdu_aggr_ctrl(struct host_cmd_ds_command *cmd,
				int cmd_action,
				struct nxpwifi_ds_11n_amsdu_aggr_ctrl *aa_ctrl);
void nxpwifi_del_tx_ba_stream_tbl_by_ra(struct nxpwifi_private *priv, u8 *ra);
u8 nxpwifi_get_sec_chan_offset(int chan);

static inline u8
nxpwifi_is_station_ampdu_allowed(struct nxpwifi_private *priv,
				 struct nxpwifi_ra_list_tbl *ptr, int tid)
{
	struct nxpwifi_sta_node *node = nxpwifi_get_sta_entry(priv, ptr->ra);

	if (unlikely(!node))
		return false;

	return (node->ampdu_sta[tid] != BA_STREAM_NOT_ALLOWED) ? true : false;
}

/* This function checks whether AMPDU is allowed or not for a particular TID. */
static inline u8
nxpwifi_is_ampdu_allowed(struct nxpwifi_private *priv,
			 struct nxpwifi_ra_list_tbl *ptr, int tid)
{
	u8 ret;

	if (is_broadcast_ether_addr(ptr->ra))
		return false;

	if (GET_BSS_ROLE(priv) == NXPWIFI_BSS_ROLE_UAP)
		ret = nxpwifi_is_station_ampdu_allowed(priv, ptr, tid);
	else
		ret = (priv->aggr_prio_tbl[tid].ampdu_ap !=
		       BA_STREAM_NOT_ALLOWED) ? true : false;

	return ret;
}

/* This function checks whether AMSDU is allowed or not for a particular TID.
 */
static inline u8
nxpwifi_is_amsdu_allowed(struct nxpwifi_private *priv, int tid)
{
	return (((priv->aggr_prio_tbl[tid].amsdu != BA_STREAM_NOT_ALLOWED) &&
		 (priv->is_data_rate_auto || !(priv->bitmap_rates[2] & 0x03)))
		? true : false);
}

/* This function checks whether a space is available for new BA stream or not.
 */
static inline u8
nxpwifi_space_avail_for_new_ba_stream(struct nxpwifi_adapter *adapter)
{
	struct nxpwifi_private *priv;
	u8 i;
	size_t ba_stream_num = 0, ba_stream_max;

	ba_stream_max = NXPWIFI_MAX_TX_BASTREAM_SUPPORTED;

	for (i = 0; i < adapter->priv_num; i++) {
		priv = adapter->priv[i];
		if (priv)
			ba_stream_num +=
				list_count_nodes(&priv->tx_ba_stream_tbl_ptr);
	}

	if (adapter->fw_api_ver == NXPWIFI_FW_V15) {
		ba_stream_max =
			       GETSUPP_TXBASTREAMS(adapter->hw_dot_11n_dev_cap);
		if (!ba_stream_max)
			ba_stream_max = NXPWIFI_MAX_TX_BASTREAM_SUPPORTED;
	}

	return ((ba_stream_num < ba_stream_max) ? true : false);
}

/* This function finds the correct Tx BA stream to delete.
 *
 * Upon successfully locating, both the TID and the RA are returned.
 */
static inline u8
nxpwifi_find_stream_to_delete(struct nxpwifi_private *priv, int ptr_tid,
			      int *ptid, u8 *ra)
{
	int tid;
	u8 ret = false;
	struct nxpwifi_tx_ba_stream_tbl *tx_tbl;

	tid = priv->aggr_prio_tbl[ptr_tid].ampdu_user;

	spin_lock_bh(&priv->tx_ba_stream_tbl_lock);
	list_for_each_entry(tx_tbl, &priv->tx_ba_stream_tbl_ptr, list) {
		if (tid > priv->aggr_prio_tbl[tx_tbl->tid].ampdu_user) {
			tid = priv->aggr_prio_tbl[tx_tbl->tid].ampdu_user;
			*ptid = tx_tbl->tid;
			memcpy(ra, tx_tbl->ra, ETH_ALEN);
			ret = true;
		}
	}
	spin_unlock_bh(&priv->tx_ba_stream_tbl_lock);

	return ret;
}

/* This function checks whether associated station is 11n enabled
 */
static inline int nxpwifi_is_sta_11n_enabled(struct nxpwifi_private *priv,
					     struct nxpwifi_sta_node *node)
{
	if (!node || (priv->bss_role == NXPWIFI_BSS_ROLE_UAP &&
		      !priv->ap_11n_enabled))
		return 0;

	return node->is_11n_enabled;
}

#endif /* !_NXPWIFI_11N_H_ */
