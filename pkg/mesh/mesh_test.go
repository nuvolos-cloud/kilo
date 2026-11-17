// Copyright 2019 the Kilo authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package mesh

import (
	"net"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/squat/kilo/pkg/wireguard"
)

func mustKey() wgtypes.Key {
	if k, err := wgtypes.GeneratePrivateKey(); err != nil {
		panic(err.Error())
	} else {
		return k
	}
}

var key = mustKey()

func TestReady(t *testing.T) {
	internalIP := oneAddressCIDR(net.ParseIP("1.1.1.1"))
	externalIP := oneAddressCIDR(net.ParseIP("2.2.2.2"))
	for _, tc := range []struct {
		name  string
		node  *Node
		ready bool
	}{
		{
			name:  "nil",
			node:  nil,
			ready: false,
		},
		{
			name:  "empty fields",
			node:  &Node{},
			ready: false,
		},
		{
			name: "empty endpoint",
			node: &Node{
				InternalIP: internalIP,
				Key:        key,
				Subnet:     &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
			},
			ready: false,
		},
		{
			name: "empty endpoint IP",
			node: &Node{
				Endpoint:   wireguard.NewEndpoint(nil, DefaultKiloPort),
				InternalIP: internalIP,
				Key:        wgtypes.Key{},
				Subnet:     &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
			},
			ready: false,
		},
		{
			name: "empty endpoint port",
			node: &Node{
				Endpoint:   wireguard.NewEndpoint(externalIP.IP, 0),
				InternalIP: internalIP,
				Key:        wgtypes.Key{},
				Subnet:     &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
			},
			ready: false,
		},
		{
			name: "empty internal IP",
			node: &Node{
				Endpoint: wireguard.NewEndpoint(externalIP.IP, DefaultKiloPort),
				Key:      wgtypes.Key{},
				Subnet:   &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
			},
			ready: false,
		},
		{
			name: "empty key",
			node: &Node{
				Endpoint:   wireguard.NewEndpoint(externalIP.IP, DefaultKiloPort),
				InternalIP: internalIP,
				Subnet:     &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
			},
			ready: false,
		},
		{
			name: "empty subnet",
			node: &Node{
				Endpoint:   wireguard.NewEndpoint(externalIP.IP, DefaultKiloPort),
				InternalIP: internalIP,
				Key:        wgtypes.Key{},
			},
			ready: false,
		},
		{
			name: "valid",
			node: &Node{
				Endpoint:   wireguard.NewEndpoint(externalIP.IP, DefaultKiloPort),
				InternalIP: internalIP,
				Key:        key,
				LastSeen:   time.Now().Unix(),
				Subnet:     &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
			},
			ready: true,
		},
	} {
		ready := tc.node.Ready()
		if ready != tc.ready {
			t.Errorf("test case %q: expected %t, got %t", tc.name, tc.ready, ready)
		}
	}
}

func TestRemoteNodesAreEqualDiscoveredEndpoints(t *testing.T) {
	now := time.Now().Unix()
	bmKey := mustKey()
	az1Key := mustKey()
	az2Key := mustKey()
	peerKey := mustKey()

	mkNode := func(name, loc string, k wgtypes.Key, pka time.Duration, de map[string]*net.UDPAddr) *Node {
		return &Node{
			Name:                name,
			Location:            loc,
			Key:                 k,
			Endpoint:            wireguard.NewEndpoint(net.ParseIP("10.0.0.1"), DefaultKiloPort),
			InternalIP:          oneAddressCIDR(net.ParseIP("10.1.0.1")),
			Subnet:              &net.IPNet{IP: net.ParseIP("10.246.0.0"), Mask: net.CIDRMask(24, 32)},
			LastSeen:            now,
			PersistentKeepalive: pka,
			DiscoveredEndpoints: de,
			Granularity:         CrossGranularity,
		}
	}

	bm := mkNode("wlprod01", "", bmKey, 0, nil)
	az1 := mkNode("worke01af000001", "azure", az1Key, 20*time.Second, nil)
	az2 := mkNode("wkrpol02000001", "azure", az2Key, 20*time.Second, nil)

	pka20 := 20 * time.Second
	pka0 := time.Duration(0)

	t.Run("bare-metal ignores discovered endpoint churn for non-keepalive bare-metal keys", func(t *testing.T) {
		m := &Mesh{
			hostname:    "wlprod01",
			granularity: CrossGranularity,
			nodes: map[string]*Node{
				"wlprod01":        bm,
				"worke01af000001": az1,
				"wkrpol02000001":  az2,
			},
			peers: map[string]*Peer{},
		}
		az1Updated := mkNode("worke01af000001", "azure", az1Key, 20*time.Second, map[string]*net.UDPAddr{
			bmKey.String(): {IP: net.ParseIP("203.0.113.10"), Port: 51820},
		})
		if !m.remoteNodesAreEqual(az1, az1Updated) {
			t.Fatalf("expected bare-metal node to ignore DiscoveredEndpoints entry for PersistentKeepalive==0 node")
		}
	})

	t.Run("azure node in cross mode ignores Azure-to-Azure discovered endpoint churn", func(t *testing.T) {
		m := &Mesh{
			hostname:    "worke01af000001",
			granularity: CrossGranularity,
			nodes: map[string]*Node{
				"wlprod01":        bm,
				"worke01af000001": az1,
				"wkrpol02000001":  az2,
			},
			peers: map[string]*Peer{},
		}
		az2Updated := mkNode("wkrpol02000001", "azure", az2Key, 20*time.Second, map[string]*net.UDPAddr{
			az2Key.String(): {IP: net.ParseIP("20.50.1.9"), Port: 41900},
		})
		if !m.remoteNodesAreEqual(az2, az2Updated) {
			t.Fatalf("expected Azure node in cross mode to ignore same-location Azure DiscoveredEndpoints churn")
		}
	})

	t.Run("bare-metal detects discovered endpoint change for cross-location NAT Azure peer when not locally discovered", func(t *testing.T) {
		m := &Mesh{
			hostname:    "wlprod01",
			granularity: CrossGranularity,
			nodes: map[string]*Node{
				"wlprod01":        bm,
				"worke01af000001": az1,
				"wkrpol02000001":  az2,
			},
			peers: map[string]*Peer{},
		}
		az1Updated := mkNode("worke01af000001", "azure", az1Key, 20*time.Second, map[string]*net.UDPAddr{
			az2Key.String(): {IP: net.ParseIP("20.50.1.9"), Port: 41900},
		})
		if m.remoteNodesAreEqual(az1, az1Updated) {
			t.Fatalf("expected bare-metal node to detect newly discovered NAT endpoint for cross-location Azure peer")
		}

		// Once local node already has its own direct handshake endpoint for az2Key, remote gossip for az2Key is shadowed.
		bmWithLocalDE := mkNode("wlprod01", "", bmKey, 0, map[string]*net.UDPAddr{
			az2Key.String(): {IP: net.ParseIP("20.50.1.8"), Port: 51820},
		})
		m.nodes["wlprod01"] = bmWithLocalDE
		if !m.remoteNodesAreEqual(az1, az1Updated) {
			t.Fatalf("expected remote DiscoveredEndpoints entry shadowed by local DiscoveredEndpoints to be ignored")
		}
	})

	t.Run("peer keepalive controls Peer CRD discovered endpoint relevance", func(t *testing.T) {
		m := &Mesh{
			hostname:    "wlprod01",
			granularity: CrossGranularity,
			nodes: map[string]*Node{
				"wlprod01":        bm,
				"worke01af000001": az1,
			},
			peers: map[string]*Peer{
				peerKey.String(): {
					Name: "vpn-peer",
					Peer: wireguard.Peer{
						PeerConfig: wgtypes.PeerConfig{
							PublicKey:                   peerKey,
							PersistentKeepaliveInterval: &pka0,
						},
					},
				},
			},
		}
		az1Updated := mkNode("worke01af000001", "azure", az1Key, 20*time.Second, map[string]*net.UDPAddr{
			peerKey.String(): {IP: net.ParseIP("198.51.100.5"), Port: 51820},
		})
		if !m.remoteNodesAreEqual(az1, az1Updated) {
			t.Fatalf("expected peer with PersistentKeepaliveInterval==0 to be ignored")
		}
		m.peers[peerKey.String()].PersistentKeepaliveInterval = &pka20
		if m.remoteNodesAreEqual(az1, az1Updated) {
			t.Fatalf("expected peer with PersistentKeepaliveInterval>0 to trigger diff")
		}
	})
}
