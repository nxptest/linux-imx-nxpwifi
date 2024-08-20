/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * NXP Wireless LAN device driver: VENDOR
 *
 * Copyright 2011-2024 NXP
 */

#ifndef __NXPWIFI_VENDOR_H__
#define __NXPWIFI_VENDOR_H__

#define NXP_OUI	0x006037

enum nxpwifi_vendor_commands {
	NXPWIFI_VENDOR_CMD_HSCFG,
	NXPWIFI_VENDOR_CMD_SLEEPPD,
	NXPWIFI_VENDOR_CMD_CLOCKSYNC,
	NXPWIFI_VENDOR_CMD_HSOFFLD
};

enum nxpwifi_nl_attrs {
	NXPWIFI_HSCFG,
	NXPWIFI_SLEEPPD,
	NXPWIFI_TSF_REPORT,
	NXPWIFI_HS_OFFLOAD
};

#define HS_OFFLOAD_ARP 0x1
#define HS_OFFLOAD_PING 0x2
#define HS_WAKEON_MDNS 0x4

void nxpwifi_set_vendor_commands(struct wiphy *wiphy);

#endif /* __NXPWIFI_VENDOR_H__ */
