// TODO: Should split between encoder and decoder
package lib

import (
	"bufio"
	"bytes"
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

	ErrValueParse               = fmt.Errorf("value parse failed")
	ErrPersistentKeepaliveRange = fmt.Errorf("persistent keepalive interval is neither 0/off nor 1-65535")
)

type EndpointMap map[string]string

func (e EndpointMap) insert(udpAddr net.UDPAddr, endpoint string) {
	e[udpAddr.String()] = endpoint
}

func (e EndpointMap) revert(udpAddr net.UDPAddr) string {
	initial, ok := e[udpAddr.String()]
	if !ok {
		return udpAddr.String()
	}
	return initial
}

// ReadConfig is yet another INI-like configuration file parser, but for WireGuard Config
func ReadConfig(r io.Reader) (wgtypes.Config, EndpointMap, error) {
	scanner := bufio.NewScanner(r)

	config := wgtypes.Config{ReplacePeers: true}
	section := SectionNone
	endpointMap := make(EndpointMap)

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
			return config, endpointMap, fmt.Errorf("%w: %v", ErrUnknownSection, s)
		}

		if len(k) == 0 {
			continue
		}

		// TODO: break out parsers into functions
		switch section {
		case SectionDevice:
			switch {
			case insensetiveMatch(k, "ListenPort"):
				port, err := parsePort(v)
				if err != nil {
					return config, endpointMap, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				config.ListenPort = &port
			case insensetiveMatch(k, "FwMark"):
				fwMark, err := parseFwMark(v)
				if err != nil {
					return config, endpointMap, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				config.FirewallMark = &fwMark
			case insensetiveMatch(k, "PrivateKey"):
				key, err := wgtypes.ParseKey(v)
				if err != nil {
					return config, endpointMap, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				config.PrivateKey = &key
			default:
				return config, endpointMap, fmt.Errorf("%w: %v: %v", ErrUnknownKey, sectionNames[section], k)
			}
		case SectionPeer:
			peer := &config.Peers[len(config.Peers)-1]
			switch {
			case insensetiveMatch(k, "Endpoint"):
				endpoint, err := net.ResolveUDPAddr("udp", v)
				if err != nil {
					return config, endpointMap, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				endpointMap.insert(*endpoint, v)
				peer.Endpoint = endpoint
			case insensetiveMatch(k, "PublicKey"):
				key, err := wgtypes.ParseKey(v)
				if err != nil {
					return config, endpointMap, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				peer.PublicKey = key
			case insensetiveMatch(k, "AllowedIPs"):
				allowedIPs, err := parseAllowedIPs(v)
				if err != nil {
					return config, endpointMap, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				peer.AllowedIPs = allowedIPs
			case insensetiveMatch(k, "PersistentKeepalive"):
				persistentKeepalive, err := parsePersistentKeepalive(v)
				if err != nil {
					return config, endpointMap, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				peer.PersistentKeepaliveInterval = &persistentKeepalive
			case insensetiveMatch(k, "PresharedKey"):
				key, err := wgtypes.ParseKey(v)
				if err != nil {
					return config, endpointMap, fmt.Errorf("%w: %w: %v=%v", ErrValueParse, err, k, v)
				}
				peer.PresharedKey = &key
			default:
				return config, endpointMap, fmt.Errorf("%w: %v: %v", ErrUnknownKey, sectionNames[section], k)
			}
		}
	}

	return config, endpointMap, nil
}

// WriteConfig writes out WireGuard Device configuration into a buffer
func WriteConfig(w io.Writer, config wgtypes.Device, endpointMap EndpointMap) {
	var emptyKey [wgtypes.KeyLen]byte

	writeConfigLine(w, formatSection("Interface"))

	writeConfigLine(w, formatLineKeyValue("PrivateKey", config.PrivateKey.String()))
	if config.ListenPort > 0 {
		writeConfigLine(w, formatLineKeyValue("ListenPort", formatPort(config.ListenPort)))
	}
	if config.FirewallMark > 0 {
		writeConfigLine(w, formatLineKeyValue("FwMark", formatFwMark(config.FirewallMark)))
	}

	for _, peer := range config.Peers {
		writeConfigLine(w, "")
		writeConfigLine(w, formatSection("Peer"))
		writeConfigLine(w, formatLineKeyValue("PublicKey", peer.PublicKey.String()))
		if !bytes.Equal(peer.PresharedKey[:], emptyKey[:]) {
			writeConfigLine(w, formatLineKeyValue("PresharedKey", peer.PresharedKey.String()))
		}
		writeConfigLine(w, formatLineKeyValue("AllowedIPs", formatAllowedIPs(peer.AllowedIPs)))
		if peer.PersistentKeepaliveInterval > 0 {
			writeConfigLine(w, formatLineKeyValue("PersistentKeepalive", formatPersistentKeepalive(peer.PersistentKeepaliveInterval)))
		}
		if peer.Endpoint != nil {
			writeConfigLine(w, formatLineKeyValue("Endpoint", endpointMap.revert(*peer.Endpoint)))
		}
	}
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
func writeConfigLine(w io.Writer, line string) (int, error) {
	return io.WriteString(w, line+"\n")
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
func formatSection(section string) string {
	return "[" + section + "]"
}
func formatLineKeyValue(key, value string) string {
	return key + " = " + value
}

func insensetiveMatch(a string, b string) bool {
	return strings.ToLower(a) == strings.ToLower(b)
}

func parsePort(s string) (int, error) {
	port, err := strconv.ParseInt(s, 0, 0)
	return int(port), err
}
func formatPort(port int) string {
	return strconv.FormatInt(int64(port), 10)
}

func parseFwMark(s string) (int, error) {
	if insensetiveMatch(s, "off") {
		return 0, nil
	}
	fwMark, err := strconv.ParseInt(s, 0, 0)
	return int(fwMark), err
}
func formatFwMark(fwMark int) string {
	if fwMark == 0 {
		return "off"
	}
	return strconv.FormatInt(int64(fwMark), 10)
}

func parseAllowedIPs(s string) ([]net.IPNet, error) {
	stringIPs := strings.Split(s, ",")
	parsedIPs := make([]net.IPNet, len(stringIPs))
	for i, stringIP := range stringIPs {
		stringIP := strings.TrimSpace(stringIP)
		_, parsedIP, err := net.ParseCIDR(stringIP)
		if err != nil {
			return parsedIPs, err
		}
		parsedIPs[i] = *parsedIP
	}
	return parsedIPs, nil
}
func formatAllowedIPs(allowedIPs []net.IPNet) string {
	stringIPs := make([]string, len(allowedIPs))
	for i, allowedIP := range allowedIPs {
		stringIPs[i] = allowedIP.String()
	}
	return strings.Join(stringIPs, ", ")
}

func parsePersistentKeepalive(s string) (time.Duration, error) {
	if insensetiveMatch(s, "off") {
		return time.Duration(0), nil
	}
	persistentKeepalive, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return time.Duration(0), err
	}
	if persistentKeepalive < 0 || persistentKeepalive > 65535 {
		return time.Duration(0), ErrPersistentKeepaliveRange
	}

	return time.Duration(persistentKeepalive * int64(time.Second)), err
}
func formatPersistentKeepalive(persistentKeepalive time.Duration) string {
	if int64(persistentKeepalive) == 0 {
		return "off"
	}
	return strconv.FormatInt(int64(persistentKeepalive/time.Second), 10)
}
