// SPDX-License-Identifier: GPL-2.0-only
/*
 * NXP Wireless LAN device driver: 802.11n RX Re-ordering
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
#include "11n_rxreorder.h"

/* This function will dispatch amsdu packet and forward it to kernel/upper
 * layer.
 */
static int nxpwifi_11n_dispatch_amsdu_pkt(struct nxpwifi_private *priv,
					  struct sk_buff *skb)
{
	struct rxpd *local_rx_pd = (struct rxpd *)(skb->data);
	int ret;

	if (le16_to_cpu(local_rx_pd->rx_pkt_type) == PKT_TYPE_AMSDU) {
		struct sk_buff_head list;
		struct sk_buff *rx_skb;

		__skb_queue_head_init(&list);

		skb_pull(skb, le16_to_cpu(local_rx_pd->rx_pkt_offset));
		skb_trim(skb, le16_to_cpu(local_rx_pd->rx_pkt_length));

		ieee80211_amsdu_to_8023s(skb, &list, priv->curr_addr,
					 priv->wdev.iftype, 0, NULL, NULL, false);

		while (!skb_queue_empty(&list)) {
			rx_skb = __skb_dequeue(&list);

			if (priv->bss_role == NXPWIFI_BSS_ROLE_UAP)
				ret = nxpwifi_uap_recv_packet(priv, rx_skb);
			else
				ret = nxpwifi_recv_packet(priv, rx_skb);
			if (ret)
				nxpwifi_dbg(priv->adapter, ERROR,
					    "Rx of A-MSDU failed");
		}
		return 0;
	}

	return -EINVAL;
}

/* This function will process the rx packet and forward it to kernel/upper
 * layer.
 */
static int nxpwifi_11n_dispatch_pkt(struct nxpwifi_private *priv,
				    struct sk_buff *payload)
{
	int ret;

	if (!payload) {
		nxpwifi_dbg(priv->adapter, INFO, "info: fw drop data\n");
		return 0;
	}

	ret = nxpwifi_11n_dispatch_amsdu_pkt(priv, payload);
	if (!ret)
		return 0;

	if (priv->bss_role == NXPWIFI_BSS_ROLE_UAP)
		return nxpwifi_handle_uap_rx_forward(priv, payload);

	return nxpwifi_process_rx_packet(priv, payload);
}

/* This function dispatches all packets in the Rx reorder table until the
 * start window.
 *
 * There could be holes in the buffer, which are skipped by the function.
 * Since the buffer is linear, the function uses rotation to simulate
 * circular buffer.
 */
static void
nxpwifi_11n_dispatch_pkt_until_start_win(struct nxpwifi_private *priv,
					 struct nxpwifi_rx_reorder_tbl *tbl,
					 int start_win)
{
	struct sk_buff_head list;
	struct sk_buff *skb;
	int pkt_to_send, i;

	__skb_queue_head_init(&list);
	spin_lock_bh(&priv->rx_reorder_tbl_lock);

	pkt_to_send = (start_win > tbl->start_win) ?
		      min((start_win - tbl->start_win), tbl->win_size) :
		      tbl->win_size;

	for (i = 0; i < pkt_to_send; ++i) {
		if (tbl->rx_reorder_ptr[i]) {
			skb = tbl->rx_reorder_ptr[i];
			__skb_queue_tail(&list, skb);
			tbl->rx_reorder_ptr[i] = NULL;
		}
	}

	/* We don't have a circular buffer, hence use rotation to simulate
	 * circular buffer
	 */
	for (i = 0; i < tbl->win_size - pkt_to_send; ++i) {
		tbl->rx_reorder_ptr[i] = tbl->rx_reorder_ptr[pkt_to_send + i];
		tbl->rx_reorder_ptr[pkt_to_send + i] = NULL;
	}

	tbl->start_win = start_win;
	spin_unlock_bh(&priv->rx_reorder_tbl_lock);

	while ((skb = __skb_dequeue(&list)))
		nxpwifi_11n_dispatch_pkt(priv, skb);
}

/* This function dispatches all packets in the Rx reorder table until
 * a hole is found.
 *
 * The start window is adjusted automatically when a hole is located.
 * Since the buffer is linear, the function uses rotation to simulate
 * circular buffer.
 */
static void
nxpwifi_11n_scan_and_dispatch(struct nxpwifi_private *priv,
			      struct nxpwifi_rx_reorder_tbl *tbl)
{
	struct sk_buff_head list;
	struct sk_buff *skb;
	int i, j, xchg;

	__skb_queue_head_init(&list);
	spin_lock_bh(&priv->rx_reorder_tbl_lock);

	for (i = 0; i < tbl->win_size; ++i) {
		if (!tbl->rx_reorder_ptr[i])
			break;
		skb = tbl->rx_reorder_ptr[i];
		__skb_queue_tail(&list, skb);
		tbl->rx_reorder_ptr[i] = NULL;
	}

	/* We don't have a circular buffer, hence use rotation to simulate
	 * circular buffer
	 */
	if (i > 0) {
		xchg = tbl->win_size - i;
		for (j = 0; j < xchg; ++j) {
			tbl->rx_reorder_ptr[j] = tbl->rx_reorder_ptr[i + j];
			tbl->rx_reorder_ptr[i + j] = NULL;
		}
	}
	tbl->start_win = (tbl->start_win + i) & (MAX_TID_VALUE - 1);

	spin_unlock_bh(&priv->rx_reorder_tbl_lock);

	while ((skb = __skb_dequeue(&list)))
		nxpwifi_11n_dispatch_pkt(priv, skb);
}

/* This function deletes the Rx reorder table and frees the memory.
 *
 * The function stops the associated timer and dispatches all the
 * pending packets in the Rx reorder table before deletion.
 */
static void
nxpwifi_del_rx_reorder_entry(struct nxpwifi_private *priv,
			     struct nxpwifi_rx_reorder_tbl *tbl)
{
	struct nxpwifi_adapter *adapter = priv->adapter;
	int start_win;

	if (!tbl)
		return;

	tasklet_disable(&adapter->rx_task);

	start_win = (tbl->start_win + tbl->win_size) & (MAX_TID_VALUE - 1);
	nxpwifi_11n_dispatch_pkt_until_start_win(priv, tbl, start_win);

	del_timer_sync(&tbl->timer_context.timer);
	tbl->timer_context.timer_is_set = false;

	spin_lock_bh(&priv->rx_reorder_tbl_lock);
	list_del(&tbl->list);
	spin_unlock_bh(&priv->rx_reorder_tbl_lock);

	kfree(tbl->rx_reorder_ptr);
	kfree(tbl);

	tasklet_enable(&adapter->rx_task);
}

/* This function returns the pointer to an entry in Rx reordering
 * table which matches the given TA/TID pair.
 */
struct nxpwifi_rx_reorder_tbl *
nxpwifi_11n_get_rx_reorder_tbl(struct nxpwifi_private *priv, int tid, u8 *ta)
{
	struct nxpwifi_rx_reorder_tbl *tbl;

	spin_lock_bh(&priv->rx_reorder_tbl_lock);
	list_for_each_entry(tbl, &priv->rx_reorder_tbl_ptr, list) {
		if (!memcmp(tbl->ta, ta, ETH_ALEN) && tbl->tid == tid) {
			spin_unlock_bh(&priv->rx_reorder_tbl_lock);
			return tbl;
		}
	}
	spin_unlock_bh(&priv->rx_reorder_tbl_lock);

	return NULL;
}

/* This function retrieves the pointer to an entry in Rx reordering
 * table which matches the given TA and deletes it.
 */
void nxpwifi_11n_del_rx_reorder_tbl_by_ta(struct nxpwifi_private *priv, u8 *ta)
{
	struct nxpwifi_rx_reorder_tbl *tbl, *tmp;

	if (!ta)
		return;

	spin_lock_bh(&priv->rx_reorder_tbl_lock);
	list_for_each_entry_safe(tbl, tmp, &priv->rx_reorder_tbl_ptr, list) {
		if (!memcmp(tbl->ta, ta, ETH_ALEN)) {
			spin_unlock_bh(&priv->rx_reorder_tbl_lock);
			nxpwifi_del_rx_reorder_entry(priv, tbl);
			spin_lock_bh(&priv->rx_reorder_tbl_lock);
		}
	}
	spin_unlock_bh(&priv->rx_reorder_tbl_lock);
}

/* This function finds the last sequence number used in the packets
 * buffered in Rx reordering table.
 */
static int
nxpwifi_11n_find_last_seq_num(struct reorder_tmr_cnxt *ctx)
{
	struct nxpwifi_rx_reorder_tbl *rx_reorder_tbl_ptr = ctx->ptr;
	struct nxpwifi_private *priv = ctx->priv;
	int i;

	spin_lock_bh(&priv->rx_reorder_tbl_lock);
	for (i = rx_reorder_tbl_ptr->win_size - 1; i >= 0; --i) {
		if (rx_reorder_tbl_ptr->rx_reorder_ptr[i]) {
			spin_unlock_bh(&priv->rx_reorder_tbl_lock);
			return i;
		}
	}
	spin_unlock_bh(&priv->rx_reorder_tbl_lock);

	return -EINVAL;
}

/* This function flushes all the packets in Rx reordering table.
 *
 * The function checks if any packets are currently buffered in the
 * table or not. In case there are packets available, it dispatches
 * them and then dumps the Rx reordering table.
 */
static void
nxpwifi_flush_data(struct timer_list *t)
{
	struct reorder_tmr_cnxt *ctx =
		from_timer(ctx, t, timer);
	int start_win, seq_num;

	ctx->timer_is_set = false;
	seq_num = nxpwifi_11n_find_last_seq_num(ctx);

	if (seq_num < 0)
		return;

	nxpwifi_dbg(ctx->priv->adapter, INFO, "info: flush data %d\n", seq_num);
	start_win = (ctx->ptr->start_win + seq_num + 1) & (MAX_TID_VALUE - 1);
	nxpwifi_11n_dispatch_pkt_until_start_win(ctx->priv, ctx->ptr,
						 start_win);
}

/* This function creates an entry in Rx reordering table for the
 * given TA/TID.
 *
 * The function also initializes the entry with sequence number, window
 * size as well as initializes the timer.
 *
 * If the received TA/TID pair is already present, all the packets are
 * dispatched and the window size is moved until the SSN.
 */
static void
nxpwifi_11n_create_rx_reorder_tbl(struct nxpwifi_private *priv, u8 *ta,
				  int tid, int win_size, int seq_num)
{
	int i;
	struct nxpwifi_rx_reorder_tbl *tbl, *new_node;
	u16 last_seq = 0;
	struct nxpwifi_sta_node *node;

	/* If we get a TID, ta pair which is already present dispatch all
	 * the packets and move the window size until the ssn
	 */
	tbl = nxpwifi_11n_get_rx_reorder_tbl(priv, tid, ta);
	if (tbl) {
		nxpwifi_11n_dispatch_pkt_until_start_win(priv, tbl, seq_num);
		return;
	}
	/* if !tbl then create one */
	new_node = kzalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
		return;

	INIT_LIST_HEAD(&new_node->list);
	new_node->tid = tid;
	memcpy(new_node->ta, ta, ETH_ALEN);
	new_node->start_win = seq_num;
	new_node->init_win = seq_num;
	new_node->flags = 0;

	spin_lock_bh(&priv->sta_list_spinlock);
	if (nxpwifi_queuing_ra_based(priv)) {
		if (priv->bss_role == NXPWIFI_BSS_ROLE_UAP) {
			node = nxpwifi_get_sta_entry(priv, ta);
			if (node)
				last_seq = node->rx_seq[tid];
		}
	} else {
		node = nxpwifi_get_sta_entry(priv, ta);
		if (node)
			last_seq = node->rx_seq[tid];
		else
			last_seq = priv->rx_seq[tid];
	}
	spin_unlock_bh(&priv->sta_list_spinlock);

	nxpwifi_dbg(priv->adapter, INFO,
		    "info: last_seq=%d start_win=%d\n",
		    last_seq, new_node->start_win);

	if (last_seq != NXPWIFI_DEF_11N_RX_SEQ_NUM &&
	    last_seq >= new_node->start_win) {
		new_node->start_win = last_seq + 1;
		new_node->flags |= RXREOR_INIT_WINDOW_SHIFT;
	}

	new_node->win_size = win_size;

	new_node->rx_reorder_ptr = kcalloc(win_size, sizeof(void *),
					   GFP_KERNEL);
	if (!new_node->rx_reorder_ptr) {
		kfree(new_node);
		nxpwifi_dbg(priv->adapter, ERROR,
			    "%s: failed to alloc reorder_ptr\n", __func__);
		return;
	}

	new_node->timer_context.ptr = new_node;
	new_node->timer_context.priv = priv;
	new_node->timer_context.timer_is_set = false;

	timer_setup(&new_node->timer_context.timer, nxpwifi_flush_data, 0);

	for (i = 0; i < win_size; ++i)
		new_node->rx_reorder_ptr[i] = NULL;

	spin_lock_bh(&priv->rx_reorder_tbl_lock);
	list_add_tail(&new_node->list, &priv->rx_reorder_tbl_ptr);
	spin_unlock_bh(&priv->rx_reorder_tbl_lock);
}

static void
nxpwifi_11n_rxreorder_timer_restart(struct nxpwifi_rx_reorder_tbl *tbl)
{
	u32 min_flush_time;

	if (tbl->win_size >= NXPWIFI_BA_WIN_SIZE_32)
		min_flush_time = MIN_FLUSH_TIMER_15_MS;
	else
		min_flush_time = MIN_FLUSH_TIMER_MS;

	mod_timer(&tbl->timer_context.timer,
		  jiffies + msecs_to_jiffies(min_flush_time * tbl->win_size));

	tbl->timer_context.timer_is_set = true;
}

/* This function prepares command for adding a BA request.
 *
 * Preparation includes -
 *      - Setting command ID and proper size
 *      - Setting add BA request buffer
 *      - Ensuring correct endian-ness
 */
int nxpwifi_cmd_11n_addba_req(struct host_cmd_ds_command *cmd, void *data_buf)
{
	struct host_cmd_ds_11n_addba_req *add_ba_req = &cmd->params.add_ba_req;

	cmd->command = cpu_to_le16(HOST_CMD_11N_ADDBA_REQ);
	cmd->size = cpu_to_le16(sizeof(*add_ba_req) + S_DS_GEN);
	memcpy(add_ba_req, data_buf, sizeof(*add_ba_req));

	return 0;
}

/* This function prepares command for adding a BA response.
 *
 * Preparation includes -
 *      - Setting command ID and proper size
 *      - Setting add BA response buffer
 *      - Ensuring correct endian-ness
 */
int nxpwifi_cmd_11n_addba_rsp_gen(struct nxpwifi_private *priv,
				  struct host_cmd_ds_command *cmd,
				  struct host_cmd_ds_11n_addba_req
				  *cmd_addba_req)
{
	struct host_cmd_ds_11n_addba_rsp *add_ba_rsp = &cmd->params.add_ba_rsp;
	u32 rx_win_size = priv->add_ba_param.rx_win_size;
	u8 tid;
	int win_size;
	u16 block_ack_param_set;

	cmd->command = cpu_to_le16(HOST_CMD_11N_ADDBA_RSP);
	cmd->size = cpu_to_le16(sizeof(*add_ba_rsp) + S_DS_GEN);

	memcpy(add_ba_rsp->peer_mac_addr, cmd_addba_req->peer_mac_addr,
	       ETH_ALEN);
	add_ba_rsp->dialog_token = cmd_addba_req->dialog_token;
	add_ba_rsp->block_ack_tmo = cmd_addba_req->block_ack_tmo;
	add_ba_rsp->ssn = cmd_addba_req->ssn;

	block_ack_param_set = le16_to_cpu(cmd_addba_req->block_ack_param_set);
	tid = (block_ack_param_set & IEEE80211_ADDBA_PARAM_TID_MASK)
		>> BLOCKACKPARAM_TID_POS;
	add_ba_rsp->status_code = cpu_to_le16(ADDBA_RSP_STATUS_ACCEPT);
	block_ack_param_set &= ~IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK;

	/* If we don't support AMSDU inside AMPDU, reset the bit */
	if (!priv->add_ba_param.rx_amsdu ||
	    priv->aggr_prio_tbl[tid].amsdu == BA_STREAM_NOT_ALLOWED)
		block_ack_param_set &= ~BLOCKACKPARAM_AMSDU_SUPP_MASK;
	block_ack_param_set |= rx_win_size << BLOCKACKPARAM_WINSIZE_POS;
	add_ba_rsp->block_ack_param_set = cpu_to_le16(block_ack_param_set);
	win_size = (le16_to_cpu(add_ba_rsp->block_ack_param_set)
		    & IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK)
		   >> BLOCKACKPARAM_WINSIZE_POS;
	cmd_addba_req->block_ack_param_set = cpu_to_le16(block_ack_param_set);

	nxpwifi_11n_create_rx_reorder_tbl(priv, cmd_addba_req->peer_mac_addr,
					  tid, win_size,
					  le16_to_cpu(cmd_addba_req->ssn));
	return 0;
}

/* This function prepares command for deleting a BA request.
 *
 * Preparation includes -
 *      - Setting command ID and proper size
 *      - Setting del BA request buffer
 *      - Ensuring correct endian-ness
 */
int nxpwifi_cmd_11n_delba(struct host_cmd_ds_command *cmd, void *data_buf)
{
	struct host_cmd_ds_11n_delba *del_ba = &cmd->params.del_ba;

	cmd->command = cpu_to_le16(HOST_CMD_11N_DELBA);
	cmd->size = cpu_to_le16(sizeof(*del_ba) + S_DS_GEN);
	memcpy(del_ba, data_buf, sizeof(*del_ba));

	return 0;
}

/* This function identifies if Rx reordering is needed for a received packet.
 *
 * In case reordering is required, the function will do the reordering
 * before sending it to kernel.
 *
 * The Rx reorder table is checked first with the received TID/TA pair. If
 * not found, the received packet is dispatched immediately. But if found,
 * the packet is reordered and all the packets in the updated Rx reordering
 * table is dispatched until a hole is found.
 *
 * For sequence number less than the starting window, the packet is dropped.
 */
int nxpwifi_11n_rx_reorder_pkt(struct nxpwifi_private *priv,
			       u16 seq_num, u16 tid,
			       u8 *ta, u8 pkt_type, void *payload)
{
	struct nxpwifi_rx_reorder_tbl *tbl;
	int prev_start_win, start_win, end_win, win_size;
	u16 pkt_index;
	bool init_window_shift = false;
	int ret = 0;

	tbl = nxpwifi_11n_get_rx_reorder_tbl(priv, tid, ta);
	if (!tbl) {
		if (pkt_type != PKT_TYPE_BAR)
			nxpwifi_11n_dispatch_pkt(priv, payload);
		return ret;
	}

	if (pkt_type == PKT_TYPE_AMSDU && !tbl->amsdu) {
		nxpwifi_11n_dispatch_pkt(priv, payload);
		return ret;
	}

	start_win = tbl->start_win;
	prev_start_win = start_win;
	win_size = tbl->win_size;
	end_win = ((start_win + win_size) - 1) & (MAX_TID_VALUE - 1);
	if (tbl->flags & RXREOR_INIT_WINDOW_SHIFT) {
		init_window_shift = true;
		tbl->flags &= ~RXREOR_INIT_WINDOW_SHIFT;
	}

	if (tbl->flags & RXREOR_FORCE_NO_DROP) {
		nxpwifi_dbg(priv->adapter, INFO,
			    "RXREOR_FORCE_NO_DROP when HS is activated\n");
		tbl->flags &= ~RXREOR_FORCE_NO_DROP;
	} else if (init_window_shift && seq_num < start_win &&
		   seq_num >= tbl->init_win) {
		nxpwifi_dbg(priv->adapter, INFO,
			    "Sender TID sequence number reset %d->%d for SSN %d\n",
			    start_win, seq_num, tbl->init_win);
		start_win = seq_num;
		tbl->start_win = start_win;
		end_win = ((start_win + win_size) - 1) & (MAX_TID_VALUE - 1);
	} else {
		/* If seq_num is less then starting win then ignore and drop
		 * the packet
		 */
		if ((start_win + TWOPOW11) > (MAX_TID_VALUE - 1)) {
			if (seq_num >= ((start_win + TWOPOW11) &
					(MAX_TID_VALUE - 1)) &&
			    seq_num < start_win) {
				ret = -EINVAL;
				goto done;
			}
		} else if ((seq_num < start_win) ||
			   (seq_num >= (start_win + TWOPOW11))) {
			ret = -EINVAL;
			goto done;
		}
	}

	/* If this packet is a BAR we adjust seq_num as
	 * WinStart = seq_num
	 */
	if (pkt_type == PKT_TYPE_BAR)
		seq_num = ((seq_num + win_size) - 1) & (MAX_TID_VALUE - 1);

	if ((end_win < start_win &&
	     seq_num < start_win && seq_num > end_win) ||
	    (end_win > start_win && (seq_num > end_win ||
				     seq_num < start_win))) {
		end_win = seq_num;
		if (((end_win - win_size) + 1) >= 0)
			start_win = (end_win - win_size) + 1;
		else
			start_win = (MAX_TID_VALUE - (win_size - end_win)) + 1;
		nxpwifi_11n_dispatch_pkt_until_start_win(priv, tbl, start_win);
	}

	if (pkt_type != PKT_TYPE_BAR) {
		if (seq_num >= start_win)
			pkt_index = seq_num - start_win;
		else
			pkt_index = (seq_num + MAX_TID_VALUE) - start_win;

		if (tbl->rx_reorder_ptr[pkt_index]) {
			ret = -EINVAL;
			goto done;
		}

		tbl->rx_reorder_ptr[pkt_index] = payload;
	}

	/* Dispatch all packets sequentially from start_win until a
	 * hole is found and adjust the start_win appropriately
	 */
	nxpwifi_11n_scan_and_dispatch(priv, tbl);

done:
	if (!tbl->timer_context.timer_is_set ||
	    prev_start_win != tbl->start_win)
		nxpwifi_11n_rxreorder_timer_restart(tbl);
	return ret;
}

/* This function deletes an entry for a given TID/TA pair.
 *
 * The TID/TA are taken from del BA event body.
 */
void
nxpwifi_del_ba_tbl(struct nxpwifi_private *priv, int tid, u8 *peer_mac,
		   u8 type, int initiator)
{
	struct nxpwifi_rx_reorder_tbl *tbl;
	struct nxpwifi_tx_ba_stream_tbl *ptx_tbl;
	struct nxpwifi_ra_list_tbl *ra_list;
	u8 cleanup_rx_reorder_tbl;
	int tid_down;

	if (type == TYPE_DELBA_RECEIVE)
		cleanup_rx_reorder_tbl = (initiator) ? true : false;
	else
		cleanup_rx_reorder_tbl = (initiator) ? false : true;

	nxpwifi_dbg(priv->adapter, EVENT, "event: DELBA: %pM tid=%d initiator=%d\n",
		    peer_mac, tid, initiator);

	if (cleanup_rx_reorder_tbl) {
		tbl = nxpwifi_11n_get_rx_reorder_tbl(priv, tid, peer_mac);
		if (!tbl) {
			nxpwifi_dbg(priv->adapter, EVENT,
				    "event: TID, TA not found in table\n");
			return;
		}
		nxpwifi_del_rx_reorder_entry(priv, tbl);
	} else {
		ptx_tbl = nxpwifi_get_ba_tbl(priv, tid, peer_mac);
		if (!ptx_tbl) {
			nxpwifi_dbg(priv->adapter, EVENT,
				    "event: TID, RA not found in table\n");
			return;
		}

		tid_down = nxpwifi_wmm_downgrade_tid(priv, tid);
		ra_list = nxpwifi_wmm_get_ralist_node(priv, tid_down, peer_mac);
		if (ra_list) {
			ra_list->amsdu_in_ampdu = false;
			ra_list->ba_status = BA_SETUP_NONE;
		}
		spin_lock_bh(&priv->tx_ba_stream_tbl_lock);
		nxpwifi_11n_delete_tx_ba_stream_tbl_entry(priv, ptx_tbl);
		spin_unlock_bh(&priv->tx_ba_stream_tbl_lock);
	}
}

/* This function handles the command response of an add BA response.
 *
 * Handling includes changing the header fields into CPU format and
 * creating the stream, provided the add BA is accepted.
 */
int nxpwifi_ret_11n_addba_resp(struct nxpwifi_private *priv,
			       struct host_cmd_ds_command *resp)
{
	struct host_cmd_ds_11n_addba_rsp *add_ba_rsp = &resp->params.add_ba_rsp;
	int tid, win_size;
	struct nxpwifi_rx_reorder_tbl *tbl;
	u16 block_ack_param_set;

	block_ack_param_set = le16_to_cpu(add_ba_rsp->block_ack_param_set);

	tid = (block_ack_param_set & IEEE80211_ADDBA_PARAM_TID_MASK)
		>> BLOCKACKPARAM_TID_POS;
	/* Check if we had rejected the ADDBA, if yes then do not create
	 * the stream
	 */
	if (le16_to_cpu(add_ba_rsp->status_code) != BA_RESULT_SUCCESS) {
		nxpwifi_dbg(priv->adapter, ERROR, "ADDBA RSP: failed %pM tid=%d)\n",
			    add_ba_rsp->peer_mac_addr, tid);

		tbl = nxpwifi_11n_get_rx_reorder_tbl(priv, tid,
						     add_ba_rsp->peer_mac_addr);
		if (tbl)
			nxpwifi_del_rx_reorder_entry(priv, tbl);

		return 0;
	}

	win_size = (block_ack_param_set & IEEE80211_ADDBA_PARAM_BUF_SIZE_MASK)
		    >> BLOCKACKPARAM_WINSIZE_POS;

	tbl = nxpwifi_11n_get_rx_reorder_tbl(priv, tid,
					     add_ba_rsp->peer_mac_addr);
	if (tbl) {
		if ((block_ack_param_set & BLOCKACKPARAM_AMSDU_SUPP_MASK) &&
		    priv->add_ba_param.rx_amsdu &&
		    priv->aggr_prio_tbl[tid].amsdu != BA_STREAM_NOT_ALLOWED)
			tbl->amsdu = true;
		else
			tbl->amsdu = false;
	}

	nxpwifi_dbg(priv->adapter, CMD,
		    "cmd: ADDBA RSP: %pM tid=%d ssn=%d win_size=%d\n",
		    add_ba_rsp->peer_mac_addr, tid, add_ba_rsp->ssn, win_size);

	return 0;
}

/* This function handles BA stream timeout event by preparing and sending
 * a command to the firmware.
 */
void nxpwifi_11n_ba_stream_timeout(struct nxpwifi_private *priv,
				   struct host_cmd_ds_11n_batimeout *event)
{
	struct host_cmd_ds_11n_delba delba;

	memset(&delba, 0, sizeof(struct host_cmd_ds_11n_delba));
	memcpy(delba.peer_mac_addr, event->peer_mac_addr, ETH_ALEN);

	delba.del_ba_param_set |=
		cpu_to_le16((u16)event->tid << DELBA_TID_POS);
	delba.del_ba_param_set |=
		cpu_to_le16((u16)event->origninator << DELBA_INITIATOR_POS);
	delba.reason_code = cpu_to_le16(WLAN_REASON_QSTA_TIMEOUT);
	nxpwifi_send_cmd(priv, HOST_CMD_11N_DELBA, 0, 0, &delba, false);
}

/* This function cleans up the Rx reorder table by deleting all the entries
 * and re-initializing.
 */
void nxpwifi_11n_cleanup_reorder_tbl(struct nxpwifi_private *priv)
{
	struct nxpwifi_rx_reorder_tbl *del_tbl_ptr, *tmp_node;

	spin_lock_bh(&priv->rx_reorder_tbl_lock);
	list_for_each_entry_safe(del_tbl_ptr, tmp_node,
				 &priv->rx_reorder_tbl_ptr, list) {
		spin_unlock_bh(&priv->rx_reorder_tbl_lock);
		nxpwifi_del_rx_reorder_entry(priv, del_tbl_ptr);
		spin_lock_bh(&priv->rx_reorder_tbl_lock);
	}
	INIT_LIST_HEAD(&priv->rx_reorder_tbl_ptr);
	spin_unlock_bh(&priv->rx_reorder_tbl_lock);

	nxpwifi_reset_11n_rx_seq_num(priv);
}

/* This function updates all rx_reorder_tbl's flags.
 */
void nxpwifi_update_rxreor_flags(struct nxpwifi_adapter *adapter, u8 flags)
{
	struct nxpwifi_private *priv;
	struct nxpwifi_rx_reorder_tbl *tbl;
	int i;

	for (i = 0; i < adapter->priv_num; i++) {
		priv = adapter->priv[i];
		if (!priv)
			continue;

		spin_lock_bh(&priv->rx_reorder_tbl_lock);
		list_for_each_entry(tbl, &priv->rx_reorder_tbl_ptr, list)
			tbl->flags = flags;
		spin_unlock_bh(&priv->rx_reorder_tbl_lock);
	}
}

/* This function update all the rx_win_size based on coex flag
 */
static void nxpwifi_update_ampdu_rxwinsize(struct nxpwifi_adapter *adapter,
					   bool coex_flag)
{
	u8 i;
	u32 rx_win_size;
	struct nxpwifi_private *priv;

	dev_dbg(adapter->dev, "Update rxwinsize %d\n", coex_flag);

	for (i = 0; i < adapter->priv_num; i++) {
		if (!adapter->priv[i])
			continue;
		priv = adapter->priv[i];
		rx_win_size = priv->add_ba_param.rx_win_size;
		if (coex_flag) {
			if (priv->bss_type == NXPWIFI_BSS_TYPE_STA)
				priv->add_ba_param.rx_win_size =
					NXPWIFI_STA_COEX_AMPDU_DEF_RXWINSIZE;
			if (priv->bss_type == NXPWIFI_BSS_TYPE_UAP)
				priv->add_ba_param.rx_win_size =
					NXPWIFI_UAP_COEX_AMPDU_DEF_RXWINSIZE;
		} else {
			if (priv->bss_type == NXPWIFI_BSS_TYPE_STA)
				priv->add_ba_param.rx_win_size =
					NXPWIFI_STA_AMPDU_DEF_RXWINSIZE;
			if (priv->bss_type == NXPWIFI_BSS_TYPE_UAP)
				priv->add_ba_param.rx_win_size =
					NXPWIFI_UAP_AMPDU_DEF_RXWINSIZE;
		}

		if (adapter->coex_win_size && adapter->coex_rx_win_size)
			priv->add_ba_param.rx_win_size =
				adapter->coex_rx_win_size;

		if (rx_win_size != priv->add_ba_param.rx_win_size) {
			if (!priv->media_connected)
				continue;
			for (i = 0; i < MAX_NUM_TID; i++)
				nxpwifi_11n_delba(priv, i);
		}
	}
}

/* This function check coex for RX BA
 */
void nxpwifi_coex_ampdu_rxwinsize(struct nxpwifi_adapter *adapter)
{
	u8 i;
	struct nxpwifi_private *priv;
	u8 count = 0;

	for (i = 0; i < adapter->priv_num; i++) {
		if (adapter->priv[i]) {
			priv = adapter->priv[i];
			if (GET_BSS_ROLE(priv) == NXPWIFI_BSS_ROLE_STA) {
				if (priv->media_connected)
					count++;
			}
			if (GET_BSS_ROLE(priv) == NXPWIFI_BSS_ROLE_UAP) {
				if (priv->bss_started)
					count++;
			}
		}
		if (count >= NXPWIFI_BSS_COEX_COUNT)
			break;
	}
	if (count >= NXPWIFI_BSS_COEX_COUNT)
		nxpwifi_update_ampdu_rxwinsize(adapter, true);
	else
		nxpwifi_update_ampdu_rxwinsize(adapter, false);
}

/* This function handles rxba_sync event
 */
void nxpwifi_11n_rxba_sync_event(struct nxpwifi_private *priv,
				 u8 *event_buf, u16 len)
{
	struct nxpwifi_ie_types_rxba_sync *tlv_rxba = (void *)event_buf;
	u16 tlv_type, tlv_len;
	struct nxpwifi_rx_reorder_tbl *rx_reor_tbl_ptr;
	u8 i, j;
	u16 seq_num, tlv_seq_num, tlv_bitmap_len;
	int tlv_buf_left = len;
	int ret;
	u8 *tmp;

	nxpwifi_dbg_dump(priv->adapter, EVT_D, "RXBA_SYNC event:",
			 event_buf, len);
	while (tlv_buf_left > sizeof(*tlv_rxba)) {
		tlv_type = le16_to_cpu(tlv_rxba->header.type);
		tlv_len  = le16_to_cpu(tlv_rxba->header.len);
		if (size_add(sizeof(tlv_rxba->header), tlv_len) > tlv_buf_left) {
			nxpwifi_dbg(priv->adapter, WARN,
				    "TLV size (%zu) overflows event_buf buf_left=%d\n",
				    size_add(sizeof(tlv_rxba->header), tlv_len),
				    tlv_buf_left);
			return;
		}

		if (tlv_type != TLV_TYPE_RXBA_SYNC) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "Wrong TLV id=0x%x\n", tlv_type);
			return;
		}

		tlv_seq_num = le16_to_cpu(tlv_rxba->seq_num);
		tlv_bitmap_len = le16_to_cpu(tlv_rxba->bitmap_len);
		if (size_add(sizeof(*tlv_rxba), tlv_bitmap_len) > tlv_buf_left) {
			nxpwifi_dbg(priv->adapter, WARN,
				    "TLV size (%zu) overflows event_buf buf_left=%d\n",
				    size_add(sizeof(*tlv_rxba), tlv_bitmap_len),
				    tlv_buf_left);
			return;
		}

		nxpwifi_dbg(priv->adapter, INFO,
			    "%pM tid=%d seq_num=%d bitmap_len=%d\n",
			    tlv_rxba->mac, tlv_rxba->tid, tlv_seq_num,
			    tlv_bitmap_len);

		rx_reor_tbl_ptr =
			nxpwifi_11n_get_rx_reorder_tbl(priv, tlv_rxba->tid,
						       tlv_rxba->mac);
		if (!rx_reor_tbl_ptr) {
			nxpwifi_dbg(priv->adapter, ERROR,
				    "Can not find rx_reorder_tbl!");
			return;
		}

		for (i = 0; i < tlv_bitmap_len; i++) {
			for (j = 0 ; j < 8; j++) {
				if (tlv_rxba->bitmap[i] & (1 << j)) {
					seq_num = (MAX_TID_VALUE - 1) &
						(tlv_seq_num + i * 8 + j);

					nxpwifi_dbg(priv->adapter, ERROR,
						    "drop packet,seq=%d\n",
						    seq_num);

					ret = nxpwifi_11n_rx_reorder_pkt
					(priv, seq_num, tlv_rxba->tid,
					 tlv_rxba->mac, 0, NULL);

					if (ret)
						nxpwifi_dbg(priv->adapter,
							    ERROR,
							    "Fail to drop packet");
				}
			}
		}

		tlv_buf_left -= (sizeof(tlv_rxba->header) + tlv_len);
		tmp = (u8 *)tlv_rxba + sizeof(tlv_rxba->header) + tlv_len;
		tlv_rxba = (struct nxpwifi_ie_types_rxba_sync *)tmp;
	}
}
