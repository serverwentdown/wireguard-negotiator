package lib

import "testing"

var testGoodConfiguration1 = `
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

func TestReadConfig(t *testing.T) {

}
