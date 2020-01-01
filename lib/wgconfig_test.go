package lib

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const testGoodConfig1 = `
# Test = Example comment

[Interface]
# Test comment 2
ListenPort = 3333
PrivateKey = MITUgapB4QfRFF54ITXL3TaiYiSsVYkchqfjAXjxM10=
[Peer]
PublicKey = pjFx72IjbMh84SH1nq8Qfbl7HD5mSScHXCV1eISR7lk=
AllowedIPs = 192.168.10.2/32, 2001:470:ed5d:a::2/128
PersistentKeepalive = 80

[Peer]
AllowedIPs = 192.168.10.40/32, 2001:470:ed5d:a::28/128
PublicKey = wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=
`

func TestReadConfig1(t *testing.T) {
	buf := strings.NewReader(testGoodConfig1)
	got, err := ReadConfig(buf)
	if err != nil {
		t.Fatalf("config read failed: %w", err)
	}

	wantPrivateKey, _ := wgtypes.ParseKey("MITUgapB4QfRFF54ITXL3TaiYiSsVYkchqfjAXjxM10=")
	wantListenPort := 3333
	wantPeer1PublicKey, _ := wgtypes.ParseKey("pjFx72IjbMh84SH1nq8Qfbl7HD5mSScHXCV1eISR7lk=")
	_, wantPeer1AllowedIP1, _ := net.ParseCIDR("192.168.10.2/32")
	_, wantPeer1AllowedIP2, _ := net.ParseCIDR("2001:470:ed5d:a::2/128")
	wantPeer1PersistentKeepalive, _ := time.ParseDuration("80s")
	wantPeer2PublicKey, _ := wgtypes.ParseKey("wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=")
	_, wantPeer2AllowedIP1, _ := net.ParseCIDR("192.168.10.40/32")
	_, wantPeer2AllowedIP2, _ := net.ParseCIDR("2001:470:ed5d:a::28/128")

	want := wgtypes.Config{
		PrivateKey:   &wantPrivateKey,
		ListenPort:   &wantListenPort,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			wgtypes.PeerConfig{
				PublicKey:         wantPeer1PublicKey,
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					*wantPeer1AllowedIP1,
					*wantPeer1AllowedIP2,
				},
				PersistentKeepaliveInterval: &wantPeer1PersistentKeepalive,
			},
			wgtypes.PeerConfig{
				PublicKey:         wantPeer2PublicKey,
				ReplaceAllowedIPs: true,
				AllowedIPs: []net.IPNet{
					*wantPeer2AllowedIP1,
					*wantPeer2AllowedIP2,
				},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("returned config is not what is wanted: \n%s", diff)
	}
}
