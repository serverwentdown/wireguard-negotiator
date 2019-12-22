package lib

import (
	"io"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ReadConfig is yet another INI-like configuration file parser, but for WireGuard
func ReadConfig(r io.Reader) (wgtypes.Config, error) {
	tmp := make([]byte, 1000)
	r.Read(tmp)
	return wgtypes.Config{}, nil
}
