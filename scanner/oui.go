package scanner

import "strings"

// LookupVendor resolves a BSSID to its manufacturer name via OUI prefix.
// Lookup happens at display time — no data is stored on the Network struct.
func LookupVendor(bssid string) string {
	if isLocallyAdministered(bssid) {
		return "Local"
	}
	prefix := strings.ToUpper(bssid)
	if len(prefix) < 8 {
		return "Unknown"
	}
	prefix = prefix[:8] // "AA:BB:CC"
	if vendor, ok := ouiTable[prefix]; ok {
		return vendor
	}
	return "Unknown"
}

// isLocallyAdministered checks if the second hex digit's bit 1 is set,
// meaning the address is locally administered (not a real OUI).
func isLocallyAdministered(bssid string) bool {
	if len(bssid) < 2 {
		return false
	}
	// Second hex character of the first octet
	c := bssid[1]
	var nibble byte
	switch {
	case c >= '0' && c <= '9':
		nibble = c - '0'
	case c >= 'a' && c <= 'f':
		nibble = c - 'a' + 10
	case c >= 'A' && c <= 'F':
		nibble = c - 'A' + 10
	default:
		return false
	}
	// Bit 1 (0x02) of the first octet = locally administered
	return nibble&0x02 != 0
}

// ouiTable maps the first 3 octets (e.g. "A4:2B:8C") to manufacturer names.
var ouiTable = map[string]string{
	// Apple
	"A4:83:E7": "Apple",
	"AC:BC:32": "Apple",
	"38:C9:86": "Apple",
	"3C:22:FB": "Apple",
	"DC:A9:04": "Apple",
	"F0:18:98": "Apple",
	"28:6A:BA": "Apple",
	"70:56:81": "Apple",
	"B8:53:AC": "Apple",
	"D0:03:4B": "Apple",
	"8C:85:90": "Apple",
	"40:A6:D9": "Apple",
	"14:7D:DA": "Apple",
	"58:55:CA": "Apple",
	"78:7E:61": "Apple",
	"A8:66:7F": "Apple",

	// Samsung
	"B0:72:BF": "Samsung",
	"34:14:5F": "Samsung",
	"8C:77:12": "Samsung",
	"E4:92:FB": "Samsung",
	"00:26:37": "Samsung",
	"D0:87:E2": "Samsung",
	"5C:49:7D": "Samsung",
	"50:01:BB": "Samsung",
	"AC:5A:14": "Samsung",
	"C0:BD:D1": "Samsung",

	// Cisco / Cisco-Linksys
	"00:1A:A1": "Cisco",
	"00:1B:0D": "Cisco",
	"00:26:CB": "Cisco",
	"58:6D:8F": "Cisco",
	"B0:FA:EB": "Cisco",
	"D4:A0:2A": "Cisco",
	"78:A0:51": "Cisco-Linksys",
	"C0:C1:C0": "Cisco-Linksys",
	"68:7F:74": "Cisco-Linksys",

	// Netgear
	"A4:2B:8C": "Netgear",
	"C4:3D:C7": "Netgear",
	"20:4E:7F": "Netgear",
	"B0:7F:B9": "Netgear",
	"84:1B:5E": "Netgear",
	"6C:B0:CE": "Netgear",
	"44:94:FC": "Netgear",
	"E0:91:F5": "Netgear",
	"28:C6:8E": "Netgear",
	"9C:3D:CF": "Netgear",

	// TP-Link
	"50:C7:BF": "TP-Link",
	"30:B5:C2": "TP-Link",
	"EC:08:6B": "TP-Link",
	"C0:06:C3": "TP-Link",
	"D8:47:32": "TP-Link",
	"60:A4:4C": "TP-Link",
	"A4:2B:B0": "TP-Link",
	"54:C8:0F": "TP-Link",
	"14:CC:20": "TP-Link",
	"B0:BE:76": "TP-Link",

	// Intel
	"00:1E:64": "Intel",
	"00:1F:3B": "Intel",
	"3C:97:0E": "Intel",
	"68:17:29": "Intel",
	"7C:5C:F8": "Intel",
	"80:86:F2": "Intel",
	"8C:8D:28": "Intel",
	"A4:34:D9": "Intel",
	"B4:6B:FC": "Intel",
	"DC:71:96": "Intel",

	// Qualcomm / Qualcomm Atheros
	"00:03:7F": "Qualcomm Atheros",
	"00:0E:8E": "Qualcomm Atheros",
	"1C:B7:2C": "Qualcomm Atheros",
	"54:E6:FC": "Qualcomm Atheros",
	"9C:B7:0D": "Qualcomm Atheros",
	"B4:EE:B4": "Qualcomm Atheros",

	// Broadcom
	"00:10:18": "Broadcom",
	"00:90:4C": "Broadcom",
	"D8:B1:22": "Broadcom",
	"20:10:7A": "Broadcom",

	// Aruba Networks / HPE Aruba
	"00:0B:86": "Aruba",
	"00:1A:1E": "Aruba",
	"00:24:6C": "Aruba",
	"04:BD:88": "Aruba",
	"18:64:72": "Aruba",
	"24:DE:C6": "Aruba",
	"40:E3:D6": "Aruba",
	"6C:F3:7F": "Aruba",
	"94:B4:0F": "Aruba",
	"D8:C7:C8": "Aruba",

	// Ubiquiti
	"00:27:22": "Ubiquiti",
	"04:18:D6": "Ubiquiti",
	"18:E8:29": "Ubiquiti",
	"24:5A:4C": "Ubiquiti",
	"44:D9:E7": "Ubiquiti",
	"68:D7:9A": "Ubiquiti",
	"74:83:C2": "Ubiquiti",
	"80:2A:A8": "Ubiquiti",
	"B4:FB:E4": "Ubiquiti",
	"FC:EC:DA": "Ubiquiti",

	// Google / Nest
	"54:60:09": "Google",
	"F4:F5:D8": "Google",
	"A4:77:33": "Google",
	"30:FD:38": "Google",
	"18:D6:C7": "Google Nest",

	// Amazon
	"F0:F0:A4": "Amazon",
	"44:65:0D": "Amazon",
	"AC:63:BE": "Amazon",
	"68:54:FD": "Amazon",
	"B0:FC:0D": "Amazon",
	"50:DC:E7": "Amazon",

	// Huawei / Honor
	"00:18:82": "Huawei",
	"00:25:68": "Huawei",
	"00:46:4B": "Huawei",
	"04:F9:38": "Huawei",
	"08:19:A6": "Huawei",
	"0C:96:BF": "Huawei",
	"20:A6:80": "Huawei",
	"48:46:FB": "Huawei",
	"70:8A:09": "Huawei",
	"88:28:B3": "Huawei",

	// ASUS
	"00:0C:6E": "ASUS",
	"00:0E:A6": "ASUS",
	"00:1A:92": "ASUS",
	"04:D4:C4": "ASUS",
	"08:60:6E": "ASUS",
	"10:C3:7B": "ASUS",
	"1C:87:2C": "ASUS",
	"2C:FD:A1": "ASUS",
	"30:5A:3A": "ASUS",
	"40:B0:76": "ASUS",

	// D-Link
	"00:05:5D": "D-Link",
	"00:0D:88": "D-Link",
	"00:17:9A": "D-Link",
	"00:1B:11": "D-Link",
	"00:1E:58": "D-Link",
	"00:22:B0": "D-Link",
	"14:D6:4D": "D-Link",
	"1C:7E:E5": "D-Link",
	"28:10:7B": "D-Link",
	"34:08:04": "D-Link",

	// Motorola
	"00:04:56": "Motorola",
	"00:08:0E": "Motorola",
	"00:0C:E5": "Motorola",
	"34:BB:1F": "Motorola",
	"5C:5A:C7": "Motorola",

	// Comcast / Xfinity
	"B0:C7:45": "Comcast Xfinity",
	"14:91:82": "Comcast Xfinity",
	"58:D5:6E": "Comcast Xfinity",
	"74:85:2A": "Comcast Xfinity",
	"F4:6B:EF": "Comcast Xfinity",
	"A4:11:62": "Comcast Xfinity",

	// Microsoft
	"00:0D:3A": "Microsoft",
	"00:12:5A": "Microsoft",
	"00:17:FA": "Microsoft",
	"28:18:78": "Microsoft",
	"7C:1E:52": "Microsoft",
	"B4:AE:2B": "Microsoft",

	// Sony
	"00:04:1F": "Sony",
	"00:13:A9": "Sony",
	"00:19:63": "Sony",
	"F8:D0:AC": "Sony",
	"AC:89:95": "Sony",
	"78:C8:81": "Sony",

	// LG
	"00:1C:62": "LG",
	"00:1E:75": "LG",
	"10:68:3F": "LG",
	"34:4D:F7": "LG",
	"58:A2:B5": "LG",
	"CC:FA:00": "LG",

	// Dell
	"00:06:5B": "Dell",
	"00:08:74": "Dell",
	"00:0B:DB": "Dell",
	"14:18:77": "Dell",
	"18:03:73": "Dell",
	"24:B6:FD": "Dell",

	// HP
	"00:0D:9D": "HP",
	"00:11:0A": "HP",
	"00:14:38": "HP",
	"00:17:A4": "HP",
	"3C:D9:2B": "HP",
	"94:57:A5": "HP",
	"B0:5A:DA": "HP",

	// Ruckus Wireless
	"00:25:C4": "Ruckus",
	"C8:3A:35": "Ruckus",
	"58:B6:33": "Ruckus",
	"AC:67:06": "Ruckus",

	// Juniper / Mist
	"00:05:85": "Juniper",
	"5C:5E:AB": "Juniper Mist",

	// Extreme / Aerohive
	"00:04:96": "Extreme",
	"08:BD:43": "Aerohive",

	// Roku
	"9C:B2:E4": "Roku",
	"B0:A7:37": "Roku",
	"D8:31:34": "Roku",
	"CC:6D:A0": "Roku",

	// Sonos
	"00:0E:58": "Sonos",
	"5C:AA:FD": "Sonos",
	"78:28:CA": "Sonos",
	"94:9F:3E": "Sonos",
	"B8:E9:37": "Sonos",

	// Ring / Blink
	"34:3E:A4": "Ring",
	"B0:09:DA": "Ring",

	// Belkin
	"08:86:3B": "Belkin",
	"94:10:3E": "Belkin",
	"C0:56:27": "Belkin",
	"EC:1A:59": "Belkin",

	// Xiaomi
	"00:9E:C8": "Xiaomi",
	"04:CF:8C": "Xiaomi",
	"0C:1D:AF": "Xiaomi",
	"28:6C:07": "Xiaomi",
	"34:CE:00": "Xiaomi",
	"58:44:98": "Xiaomi",
	"64:B4:73": "Xiaomi",
	"7C:1D:D9": "Xiaomi",

	// MediaTek
	"00:0C:E7": "MediaTek",
	"00:0C:43": "MediaTek",

	// Ralink / MediaTek
	"00:17:7C": "Ralink",

	// Realtek
	"00:E0:4C": "Realtek",
	"52:54:00": "Realtek",

	// Espressif (ESP32/ESP8266 IoT)
	"24:0A:C4": "Espressif",
	"24:62:AB": "Espressif",
	"30:AE:A4": "Espressif",
	"A4:CF:12": "Espressif",
	"BC:DD:C2": "Espressif",

	// Raspberry Pi
	"B8:27:EB": "Raspberry Pi",
	"DC:A6:32": "Raspberry Pi",
	"E4:5F:01": "Raspberry Pi",

	// Wyze
	"2C:AA:8E": "Wyze",

	// AT&T / Pace
	"08:EA:44": "AT&T",
	"14:C0:3E": "AT&T",
	"B8:AD:3E": "AT&T",
	"D4:01:C3": "AT&T",

	// Verizon / Fios
	"00:1E:C1": "Verizon",
	"20:C0:47": "Verizon",
	"48:5D:36": "Verizon",

	// CenturyLink / Calix
	"34:68:95": "CenturyLink",
	"68:F9:56": "Calix",

	// Charter / Spectrum
	"14:ED:BB": "Charter Spectrum",
	"40:B7:F3": "Charter Spectrum",

	// Eero
	"F8:BB:BF": "eero",

	// ARRIS / Motorola (cable modems)
	"00:00:CA": "ARRIS",
	"00:15:96": "ARRIS",
	"00:1D:CE": "ARRIS",
	"10:86:8C": "ARRIS",
	"20:3D:66": "ARRIS",
	"E8:ED:05": "ARRIS",

	// Meraki (Cisco)
	"00:18:0A": "Cisco Meraki",
	"AC:17:02": "Cisco Meraki",

	// ZTE
	"00:19:CB": "ZTE",
	"00:1E:73": "ZTE",
	"34:4B:50": "ZTE",

	// OnePlus
	"94:65:2D": "OnePlus",

	// Hewlett Packard Enterprise
	"00:1C:C4": "HPE",
	"3C:52:82": "HPE",
	"D4:C9:EF": "HPE",

	// Sagemcom (ISP routers)
	"00:1E:B4": "Sagemcom",
	"64:7C:34": "Sagemcom",

	// Fortinet
	"00:09:0F": "Fortinet",

	// Palo Alto
	"00:1B:17": "Palo Alto",

	// Additional common
	"D0:E1:F2": "Technicolor",
	"34:A1:F7": "Shenzhen RF-Link",
	"00:DE:AD": "Private",
	"11:22:33": "Private",
	"AA:BB:CC": "Private",
}
