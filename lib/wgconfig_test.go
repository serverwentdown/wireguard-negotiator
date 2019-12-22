package lib

import (
	"strings"
	"testing"

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

[Peer]
AllowedIPs = 192.168.10.40/32, 2001:470:ed5d:a::28/128
PublicKey = wXU+vSTdEoIwSi+Tmv35SCOFg17wCAwnmYxeQPpbzDg=
`

var testGoodConfig1Want = wgtypes.Config{}

func TestReadConfig1(t *testing.T) {
	buf := strings.NewReader(testGoodConfig1)
	got, err := ReadConfig(buf)
	if err != nil {
		t.Fatalf("config read failed: %w", err)
	}
	if diff := cmp.Diff(testGoodConfig1Want, got); diff != "" {
		t.Fatalf("returned config is not what is wanted: \n%s", diff)
	}
}
