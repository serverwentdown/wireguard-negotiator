// TODO: Should split between encoder and decoder
package lib

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	CommentChar    = "#"
	AssignmentChar = "="
)

const (
	SectionNone = iota
	SectionDevice
	SectionPeer
)

var sectionNames = []string{
	"None",
	"Device",
	"Peer",
}

var (
	ErrUnknownSection = fmt.Errorf("unknown section")
	ErrUnknownKey     = fmt.Errorf("unknown key")

	ErrValueParse = fmt.Errorf("value parse failed")
)

// ReadConfig is yet another INI-like configuration file parser, but for WireGuard
func ReadConfig(r io.Reader) (wgtypes.Config, error) {
	scanner := bufio.NewScanner(r)

	config := wgtypes.Config{ReplacePeers: true}
	section := SectionNone

	for scanner.Scan() {
		text := scanner.Text()
		line, _ := readConfigLine(text)

		s, k, v := parseLine(line)

		switch {
		case insensetiveMatch(s, "Interface"):
			section = SectionDevice
		case insensetiveMatch(s, "Peer"):
			section = SectionPeer
			config.Peers = append(config.Peers, wgtypes.PeerConfig{
				ReplaceAllowedIPs: true,
			})
		case len(s) > 0:
			return config, fmt.Errorf("%w: %v", ErrUnknownSection, s)
		}

		if len(k) == 0 {
			continue
		}

		// TODO: break out parsers into functions
		switch section {
		case SectionDevice:
			switch {
			case insensetiveMatch(k, "ListenPort"):
				listenPort, err := strconv.ParseInt(v, 0, 0)
				if err != nil {
					return config, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				listenPortInt := int(listenPort)
				config.ListenPort = &listenPortInt
			case insensetiveMatch(k, "FwMark"):
				fwMarkInt := 0
				if !insensetiveMatch(v, "off") {
					fwMark, err := strconv.ParseInt(v, 0, 0)
					if err != nil {
						return config, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
					}
					fwMarkInt = int(fwMark)
				}
				config.FirewallMark = &fwMarkInt
			case insensetiveMatch(k, "PrivateKey"):
				key, err := wgtypes.ParseKey(v)
				if err != nil {
					return config, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				config.PrivateKey = &key
			default:
				return config, fmt.Errorf("%w: %v: %v", ErrUnknownKey, sectionNames[section], k)
			}
		case SectionPeer:
			peer := &config.Peers[len(config.Peers)-1]
			switch {
			case insensetiveMatch(k, "Endpoint"):
				endpoint, err := net.ResolveUDPAddr("udp", v)
				if err != nil {
					return config, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				peer.Endpoint = endpoint
			case insensetiveMatch(k, "PublicKey"):
				key, err := wgtypes.ParseKey(v)
				if err != nil {
					return config, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				peer.PublicKey = key
			case insensetiveMatch(k, "AllowedIPs"):
				allowedIPs, err := parseAllowedIPs(v)
				if err != nil {
					return config, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				peer.AllowedIPs = allowedIPs
			case insensetiveMatch(k, "PersistentKeepalive"):
				persistentKeepalive := int64(0)
				var err error
				if !insensetiveMatch(v, "off") {
					persistentKeepalive, err = strconv.ParseInt(v, 0, 64)
					if err != nil {
						return config, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
					}
				}
				if persistentKeepalive < 0 || persistentKeepalive > 65535 {
					return config, fmt.Errorf("%w: Persistent keepalive interval is neither 0/off nor 1-65535: %v=%v", ErrValueParse, k, v)
				}
				persistentKeepaliveDuration := time.Duration(persistentKeepalive * int64(time.Second))
				peer.PersistentKeepaliveInterval = &persistentKeepaliveDuration
			case insensetiveMatch(k, "PresharedKey"):

			default:
				return config, fmt.Errorf("%w: %v: %v", ErrUnknownKey, sectionNames[section], k)
			}
		}
	}

	return config, nil
}

func readConfigLine(text string) (line, comments string) {
	line = text
	comments = ""

	comment := strings.Index(line, CommentChar)
	if comment >= 0 {
		line = text[:comment]
		comments = text[comment+1:]
	}

	line = strings.TrimSpace(line)
	comments = strings.TrimSpace(comments)
	return
}

func parseLine(line string) (section, key, value string) {
	if len(line) < 1 {
		return "", "", ""
	}

	if line[0] == '[' && line[len(line)-1] == ']' {
		return line[1 : len(line)-1], "", ""
	}

	assign := strings.Index(line, AssignmentChar)
	if assign >= 0 {
		return "", strings.TrimSpace(line[:assign]), strings.TrimSpace(line[assign+1:])
	}

	return "", "", ""
}

func insensetiveMatch(a string, b string) bool {
	return strings.ToLower(a) == strings.ToLower(b)
}

func parseAllowedIPs(s string) ([]net.IPNet, error) {
	parsedIPs := make([]net.IPNet, 0)
	stringIPs := strings.Split(s, ",")
	for _, stringIP := range stringIPs {
		stringIP := strings.TrimSpace(stringIP)
		_, parsedIP, err := net.ParseCIDR(stringIP)
		if err != nil {
			return parsedIPs, err
		}
		parsedIPs = append(parsedIPs, *parsedIP)
	}
	return parsedIPs, nil
}
