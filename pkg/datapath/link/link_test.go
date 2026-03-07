// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package link

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) {
	testutils.PrivilegedTest(tb)
}

func TestPrivilegedDeleteByName(t *testing.T) {
	setup(t)

	testCases := []struct {
		name   string
		create bool
	}{
		{"foo", true},
		{"bar", false},
	}
	var err error

	for _, tc := range testCases {
		if tc.create {
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: tc.name,
				},
			})
			require.NoError(t, err)
		}

		require.NoError(t, DeleteByName(tc.name))
	}
}

func TestPrivilegedRename(t *testing.T) {
	setup(t)

	testCases := []struct {
		curName     string
		newName     string
		create      bool
		expectError bool
	}{
		{
			"abc",
			"xyz",
			true,
			false,
		},
		{
			"fizz",
			"buzz",
			false,
			true,
		},
	}
	var err error

	for _, tc := range testCases {
		if tc.create {
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: tc.curName,
				},
			})
			require.NoError(t, err)
		}

		err = Rename(tc.curName, tc.newName)
		if tc.expectError {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}

		DeleteByName(tc.newName)
	}
}

func TestLinkType(t *testing.T) {
	fooLinkAttrs := netlink.LinkAttrs{Name: "foo"}

	for _, tc := range []struct {
		link     netlink.Link
		expected uint8
	}{
		{&netlink.GenericLink{LinkAttrs: fooLinkAttrs, LinkType: "foo"}, LinkTypeGeneric},
		{&netlink.Device{LinkAttrs: fooLinkAttrs}, LinkTypeDevice},
		{&netlink.Dummy{LinkAttrs: fooLinkAttrs}, LinkTypeDummy},
		{&netlink.Ifb{LinkAttrs: fooLinkAttrs}, LinkTypeIfb},
		{&netlink.Bridge{LinkAttrs: fooLinkAttrs}, LinkTypeBridge},
		{&netlink.Vlan{LinkAttrs: fooLinkAttrs}, LinkTypeVlan},
		{&netlink.Macvlan{LinkAttrs: fooLinkAttrs}, LinkTypeMacvlan},
		{&netlink.Macvtap{Macvlan: netlink.Macvlan{LinkAttrs: fooLinkAttrs}}, LinkTypeMacvtap},
		{&netlink.Tuntap{LinkAttrs: fooLinkAttrs}, LinkTypeTuntap},
		{&netlink.Netkit{LinkAttrs: fooLinkAttrs}, LinkTypeNetkit},
		{&netlink.Veth{LinkAttrs: fooLinkAttrs}, LinkTypeVeth},
		{&netlink.Wireguard{LinkAttrs: fooLinkAttrs}, LinkTypeWireguard},
		{&netlink.Vxlan{LinkAttrs: fooLinkAttrs}, LinkTypeVxlan},
		{&netlink.IPVlan{LinkAttrs: fooLinkAttrs}, LinkTypeIPVlan},
		{&netlink.IPVtap{IPVlan: netlink.IPVlan{LinkAttrs: fooLinkAttrs}}, LinkTypeIPVtap},
		{&netlink.Bond{LinkAttrs: fooLinkAttrs}, LinkTypeBond},
		{&netlink.Geneve{LinkAttrs: fooLinkAttrs}, LinkTypeGeneve},
		{&netlink.Gretap{LinkAttrs: fooLinkAttrs, Local: net.IPv4zero}, LinkTypeGretap4},
		{&netlink.Gretap{LinkAttrs: fooLinkAttrs, Local: net.IPv6zero}, LinkTypeGretap6},
		{&netlink.Iptun{LinkAttrs: fooLinkAttrs}, LinkTypeIPTun},
		{&netlink.Ip6tnl{LinkAttrs: fooLinkAttrs}, LinkTypeIP6Tnl},
		{&netlink.Sittun{LinkAttrs: fooLinkAttrs}, LinkTypeSitTun},
		{&netlink.Vti{LinkAttrs: fooLinkAttrs, Local: net.IPv4zero}, LinkTypeVti4},
		{&netlink.Vti{LinkAttrs: fooLinkAttrs, Local: net.IPv6zero}, LinkTypeVti6},
		{&netlink.Gretun{LinkAttrs: fooLinkAttrs, Local: net.IPv4zero}, LinkTypeGretun4},
		{&netlink.Gretun{LinkAttrs: fooLinkAttrs, Local: net.IPv6zero}, LinkTypeGretun6},
		{&netlink.Vrf{LinkAttrs: fooLinkAttrs}, LinkTypeVrf},
		{&netlink.GTP{LinkAttrs: fooLinkAttrs}, LinkTypeGTP},
		{&netlink.Xfrmi{LinkAttrs: fooLinkAttrs}, LinkTypeXfrmi},
		{&netlink.Can{LinkAttrs: fooLinkAttrs}, LinkTypeCan},
		{&netlink.IPoIB{LinkAttrs: fooLinkAttrs}, LinkTypeIPoIB},
		{&netlink.BareUDP{LinkAttrs: fooLinkAttrs}, LinkTypeBareUDP},
	} {
		require.Equal(t, tc.expected, LinkToTypeEnum(tc.link))
	}

}
