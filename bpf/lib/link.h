/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/* Enum for the attached interface link type. This is used to
 * determine how to handle certain operations based on the link type.
 *
 * Important: keep in sync with pkg/datapath/link/link.go
 */
enum {
    LINK_TYPE_GENERIC = 0,
    LINK_TYPE_DEVICE,
    LINK_TYPE_DUMMY,
    LINK_TYPE_IFB,
    LINK_TYPE_BRIDGE,
    LINK_TYPE_VLAN,
    LINK_TYPE_MACVLAN,
    LINK_TYPE_MACVTAP,
    LINK_TYPE_TUNTAP,
    LINK_TYPE_NETKIT,
    LINK_TYPE_VETH,
    LINK_TYPE_WIREGUARD,
    LINK_TYPE_VXLAN,
    LINK_TYPE_IPVLAN,
    LINK_TYPE_IPVTAP,
    LINK_TYPE_BOND,
    LINK_TYPE_GENEVE,
    LINK_TYPE_GRETAP4,
    LINK_TYPE_GRETAP6,
    LINK_TYPE_IPTUN,
    LINK_TYPE_IP6TNL,
    LINK_TYPE_SITTUN,
    LINK_TYPE_VTI4,
    LINK_TYPE_VTI6,
    LINK_TYPE_GRETUN4,
    LINK_TYPE_GRETUN6,
    LINK_TYPE_VRF,
    LINK_TYPE_GTP,
    LINK_TYPE_XFRMI,
    LINK_TYPE_CAN,
    LINK_TYPE_IPOIB,
    LINK_TYPE_BARE_UDP,
};
