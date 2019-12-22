package lib

type PeerConfigResponse struct {
	InterfaceIPs        []string
	AllowedIPs          []string
	PublicKey           string
	Endpoint            string
	PersistentKeepalive int
}
