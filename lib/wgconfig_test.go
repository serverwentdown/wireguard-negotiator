package lib

import (
	"errors"
	"net"
	"strconv"
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
AllowedIPs = 192.168.10.2/32,  2001:470:ed5d:a::2/128
PersistentKeepalive = 80

[Peer]
AllowedIPs =     192.168.10.40/32   , 2001:470:ed5d:a::28/128
PublicKey = wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=
PresharedKey        = wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=
Endpoint = example.com:4444
`

func TestReadConfig1(t *testing.T) {
	buf := strings.NewReader(testGoodConfig1)
	got, gotEndpointMap, err := ReadConfig(buf)
	if err != nil {
		t.Fatalf("config read failed: %v", err)
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
	wantPeer2PresharedKey, _ := wgtypes.ParseKey("wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=")
	wantPeer2Endpoint, _ := net.ResolveUDPAddr("udp", "example.com:4444")

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
				Endpoint:     wantPeer2Endpoint,
				PresharedKey: &wantPeer2PresharedKey,
			},
		},
	}

	wantEndpointMap := EndpointMap{}
	wantEndpointMap.insert(*wantPeer2Endpoint, "example.com:4444")

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("returned config is not what is wanted: \n%s", diff)
	}
	if diff := cmp.Diff(wantEndpointMap, gotEndpointMap); diff != "" {
		t.Fatalf("returned endpointMap is not what is wanted: \n%s", diff)
	}
}

const testGoodConfig2 = `
[Interface]
PrivateKey = MITUgapB4QfRFF54ITXL3TaiYiSsVYkchqfjAXjxM10=

[Peer]
PublicKey = pjFx72IjbMh84SH1nq8Qfbl7HD5mSScHXCV1eISR7lk=

[Peer]
PublicKey = wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=
`

func TestReadConfig2(t *testing.T) {
	buf := strings.NewReader(testGoodConfig2)
	got, _, err := ReadConfig(buf)
	if err != nil {
		t.Fatalf("config read failed: %v", err)
	}

	wantPrivateKey, _ := wgtypes.ParseKey("MITUgapB4QfRFF54ITXL3TaiYiSsVYkchqfjAXjxM10=")
	wantPeer1PublicKey, _ := wgtypes.ParseKey("pjFx72IjbMh84SH1nq8Qfbl7HD5mSScHXCV1eISR7lk=")
	wantPeer2PublicKey, _ := wgtypes.ParseKey("wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=")

	want := wgtypes.Config{
		PrivateKey:   &wantPrivateKey,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			wgtypes.PeerConfig{
				PublicKey:         wantPeer1PublicKey,
				ReplaceAllowedIPs: true,
			},
			wgtypes.PeerConfig{
				PublicKey:         wantPeer2PublicKey,
				ReplaceAllowedIPs: true,
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("returned config is not what is wanted: \n%s", diff)
	}
}

const testWantConfig1 = `[Interface]
PrivateKey = MITUgapB4QfRFF54ITXL3TaiYiSsVYkchqfjAXjxM10=
ListenPort = 3333

[Peer]
PublicKey = pjFx72IjbMh84SH1nq8Qfbl7HD5mSScHXCV1eISR7lk=
AllowedIPs = 192.168.10.2/32, 2001:470:ed5d:a::2/128
PersistentKeepalive = 80
Endpoint = example.com:4444

[Peer]
PublicKey = wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=
PresharedKey = wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=
AllowedIPs = 192.168.10.40/32, 2001:470:ed5d:a::28/128
`

func TestWriteConfig1(t *testing.T) {
	var buf strings.Builder

	wantPrivateKey, _ := wgtypes.ParseKey("MITUgapB4QfRFF54ITXL3TaiYiSsVYkchqfjAXjxM10=")
	wantListenPort := 3333
	wantPeer1PublicKey, _ := wgtypes.ParseKey("pjFx72IjbMh84SH1nq8Qfbl7HD5mSScHXCV1eISR7lk=")
	_, wantPeer1AllowedIP1, _ := net.ParseCIDR("192.168.10.2/32")
	_, wantPeer1AllowedIP2, _ := net.ParseCIDR("2001:470:ed5d:a::2/128")
	wantPeer1PersistentKeepalive, _ := time.ParseDuration("80s")
	wantPeer2PublicKey, _ := wgtypes.ParseKey("wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=")
	_, wantPeer2AllowedIP1, _ := net.ParseCIDR("192.168.10.40/32")
	_, wantPeer2AllowedIP2, _ := net.ParseCIDR("2001:470:ed5d:a::28/128")
	wantPeer2PresharedKey, _ := wgtypes.ParseKey("wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=")
	wantPeer2Endpoint, _ := net.ResolveUDPAddr("udp", "example.com:4444")

	config := wgtypes.Device{
		PrivateKey: wantPrivateKey,
		ListenPort: wantListenPort,
		Peers: []wgtypes.Peer{
			wgtypes.Peer{
				PublicKey: wantPeer1PublicKey,
				AllowedIPs: []net.IPNet{
					*wantPeer1AllowedIP1,
					*wantPeer1AllowedIP2,
				},
				Endpoint:                    wantPeer2Endpoint,
				PersistentKeepaliveInterval: wantPeer1PersistentKeepalive,
			},
			wgtypes.Peer{
				PublicKey: wantPeer2PublicKey,
				AllowedIPs: []net.IPNet{
					*wantPeer2AllowedIP1,
					*wantPeer2AllowedIP2,
				},
				PresharedKey: wantPeer2PresharedKey,
			},
		},
	}

	endpointMap := EndpointMap{}
	endpointMap.insert(*wantPeer2Endpoint, "example.com:4444")

	WriteConfig(&buf, config, endpointMap)

	if diff := cmp.Diff(testWantConfig1, buf.String()); diff != "" {
		t.Fatalf("returned config is not what is wanted: \n%s", diff)
	}
}

func TestPersistentKeepalive(t *testing.T) {
	parseWant, _ := time.ParseDuration("10s")
	parseGot, err := parsePersistentKeepalive("10")
	if err != nil {
		t.Fatalf("parsed error %v, want %v", err, parseWant)
	}
	if parseWant != parseGot {
		t.Fatalf("parsed %v, want %v", parseGot, parseWant)
	}

	parseWant, _ = time.ParseDuration("0s")
	parseGot, err = parsePersistentKeepalive("off")
	if err != nil {
		t.Fatalf("parsed error %v, want %v", err, parseWant)
	}
	if parseWant != parseGot {
		t.Fatalf("parsed %v, want %v", parseGot, parseWant)
	}

	var reasonErr *strconv.NumError

	_, err = parsePersistentKeepalive("10e")
	if !errors.As(err, &reasonErr) || reasonErr.Err != strconv.ErrSyntax {
		t.Fatalf("parsed error %v, want error %v", reasonErr.Err, strconv.ErrSyntax)
	}

	_, err = parsePersistentKeepalive("1000000s")
	if !errors.As(err, &reasonErr) || reasonErr.Err != strconv.ErrSyntax {
		t.Fatalf("parsed error %v, want error %v", reasonErr.Err, strconv.ErrSyntax)
	}

	_, err = parsePersistentKeepalive("1000000")
	if !errors.Is(err, ErrPersistentKeepaliveRange) {
		t.Fatalf("parsed error %v, want error %v", err, ErrPersistentKeepaliveRange)
	}

	formatWant := "off"
	formatGot := formatPersistentKeepalive(time.Duration(0))
	if formatWant != formatGot {
		t.Fatalf("format %v, want %v", formatGot, formatWant)
	}

	formatWant = "11"
	formatGot = formatPersistentKeepalive(time.Duration(11 * int64(time.Second)))
	if formatWant != formatGot {
		t.Fatalf("format %v, want %v", formatGot, formatWant)
	}
}
