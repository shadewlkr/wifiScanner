package scanner

import (
	"fmt"
	"math/rand"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// Network represents a discovered WiFi network.
type Network struct {
	BSSID     string
	SSID      string
	Signal    int // dBm
	Frequency int // MHz
	Channel   int
	Security  string // WPA3, WPA2, WPA2/WPA, WPA, WEP, OPEN
	LastSeen  time.Time
}

// Scanner handles WiFi network discovery.
type Scanner struct {
	Interface string
	Demo      bool
}

// New creates a Scanner, auto-detecting the wireless interface if not specified.
func New(iface string, demo bool) (*Scanner, error) {
	s := &Scanner{
		Interface: iface,
		Demo:      demo,
	}

	if demo {
		s.Interface = "wlan0"
		return s, nil
	}

	if iface == "" {
		detected, err := detectInterface()
		if err != nil {
			return nil, fmt.Errorf("no wireless interface found: %w", err)
		}
		s.Interface = detected
	}

	return s, nil
}

// detectInterface finds the first wireless interface via iw.
func detectInterface() (string, error) {
	out, err := exec.Command("iw", "dev").Output()
	if err != nil {
		return "", fmt.Errorf("failed to run 'iw dev': %w", err)
	}

	re := regexp.MustCompile(`Interface\s+(\S+)`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) < 2 {
		return "", fmt.Errorf("no wireless interface detected in 'iw dev' output")
	}
	return matches[1], nil
}

// Scan performs a WiFi scan and returns discovered networks.
func (s *Scanner) Scan() ([]Network, error) {
	if s.Demo {
		return s.mockScan(), nil
	}

	// Try active scan first, fall back to cached results
	out, err := exec.Command("iw", "dev", s.Interface, "scan").CombinedOutput()
	if err != nil {
		out, err = exec.Command("iw", "dev", s.Interface, "scan", "dump").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("scan failed: %w\n%s", err, string(out))
		}
	}

	networks := parseScanOutput(string(out))
	return networks, nil
}

// parseScanOutput parses iw scan output into Network structs.
func parseScanOutput(output string) []Network {
	var networks []Network

	// Split on BSS lines — each block describes one network
	blocks := regexp.MustCompile(`(?m)^BSS `).Split(output, -1)

	for _, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}

		n := Network{LastSeen: time.Now()}

		// BSSID (first 17 chars of the block: aa:bb:cc:dd:ee:ff)
		if m := regexp.MustCompile(`^([0-9a-fA-F:]{17})`).FindStringSubmatch(block); len(m) > 1 {
			n.BSSID = strings.ToUpper(m[1])
		} else {
			continue // Not a real BSS block (e.g. "BSS Load:" split artifact)
		}

		// SSID
		if m := regexp.MustCompile(`(?m)^[ \t]+SSID:[ \t]*(.*)$`).FindStringSubmatch(block); len(m) > 1 {
			n.SSID = strings.TrimSpace(m[1])
		}
		if n.SSID == "" {
			n.SSID = "<hidden>"
		}

		// Signal strength
		if m := regexp.MustCompile(`signal:\s*(-?\d+)`).FindStringSubmatch(block); len(m) > 1 {
			n.Signal, _ = strconv.Atoi(m[1])
		}

		// Frequency
		if m := regexp.MustCompile(`freq:\s*(\d+)`).FindStringSubmatch(block); len(m) > 1 {
			n.Frequency, _ = strconv.Atoi(m[1])
		}

		// Channel — prefer DS Parameter set, fall back to frequency calculation
		if m := regexp.MustCompile(`DS Parameter set: channel (\d+)`).FindStringSubmatch(block); len(m) > 1 {
			n.Channel, _ = strconv.Atoi(m[1])
		} else {
			n.Channel = freqToChannel(n.Frequency)
		}

		// Security
		n.Security = parseSecurity(block)

		networks = append(networks, n)
	}

	sort.Slice(networks, func(i, j int) bool {
		return networks[i].Signal > networks[j].Signal
	})

	return networks
}

func parseSecurity(block string) string {
	hasRSN := strings.Contains(block, "RSN:")
	hasWPA := strings.Contains(block, "WPA:")
	hasSAE := strings.Contains(block, "SAE")

	switch {
	case hasSAE:
		return "WPA3"
	case hasRSN && hasWPA:
		return "WPA2/WPA"
	case hasRSN:
		return "WPA2"
	case hasWPA:
		return "WPA"
	case strings.Contains(block, "Privacy"):
		return "WEP"
	default:
		return "OPEN"
	}
}

func freqToChannel(freq int) int {
	switch {
	case freq >= 2412 && freq <= 2472:
		return (freq - 2407) / 5
	case freq == 2484:
		return 14
	case freq >= 5180 && freq <= 5825:
		return (freq - 5000) / 5
	case freq >= 5955 && freq <= 7115:
		return (freq - 5950) / 5
	default:
		return 0
	}
}

// mockScan generates realistic fake network data for demo/testing.
func (s *Scanner) mockScan() []Network {
	type mock struct {
		ssid       string
		bssid      string
		security   string
		baseSignal int
		freq       int
	}

	mocks := []mock{
		{"NETGEAR-5G-Home", "A4:2B:8C:D1:E5:F0", "WPA2", -35, 5180},
		{"xfinitywifi", "B0:C7:45:3A:91:DE", "OPEN", -42, 2437},
		{"FBI_Surveillance_Van_7", "C8:3A:35:FF:02:11", "WPA3", -48, 5240},
		{"Pretty Fly for a WiFi", "D4:01:C3:7E:A8:55", "WPA2", -55, 2412},
		{"The LAN Before Time", "10:68:3F:6B:33:C7", "WPA2", -58, 2462},
		{"Bill Wi the Science Fi", "28:C6:8E:CE:47:9B", "WPA2/WPA", -63, 2427},
		{"DROP TABLE *;--", "00:0E:8E:BE:EF:00", "WPA2", -65, 5300},
		{"Skynet Global Defense", "00:09:0F:44:55:66", "WPA3", -68, 5500},
		{"404 Network Unavail", "AC:67:06:DD:EE:01", "WPA2", -72, 2452},
		{"wu-tang LAN", "34:A1:F7:8C:22:D0", "WPA2", -74, 2417},
		{"<hidden>", "B4:FB:E4:BC:DE:F0", "WPA2", -76, 5220},
		{"linksys", "78:A0:51:3E:C9:44", "WEP", -78, 2422},
		{"DIRECT-roku-123", "9C:B2:E4:16:F8:73", "WPA2", -82, 2447},
		{"HP-Print-A1-Officejet", "B0:5A:DA:01:23:45", "OPEN", -85, 2432},
		{"oldrouter", "D0:E1:F2:03:14:25", "OPEN", -88, 2442},
		{"TP-Link_Guest_5G", "50:C7:BF:15:26:37", "WPA2", -91, 5745},
	}

	networks := make([]Network, len(mocks))
	now := time.Now()

	for i, m := range mocks {
		jitter := rand.Intn(7) - 3 // -3 to +3 dBm variation
		networks[i] = Network{
			BSSID:     m.bssid,
			SSID:      m.ssid,
			Signal:    m.baseSignal + jitter,
			Frequency: m.freq,
			Channel:   freqToChannel(m.freq),
			Security:  m.security,
			LastSeen:  now,
		}
	}

	// Occasional roaming network to exercise new-network alerts (~30% chance)
	if rand.Intn(10) < 3 {
		networks = append(networks, Network{
			BSSID:     "A4:77:33:AB:CD:EF",
			SSID:      "GoogleGuest-5G",
			Signal:    -60 + rand.Intn(7) - 3,
			Frequency: 5500,
			Channel:   freqToChannel(5500),
			Security:  "WPA2",
			LastSeen:  now,
		})
	}

	sort.Slice(networks, func(i, j int) bool {
		return networks[i].Signal > networks[j].Signal
	})

	return networks
}
