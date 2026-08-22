package security

import (
	"strings"
)

// PortShieldItem represents a sensitive network port definition with threat metadata.
type PortShieldItem struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`     // "TCP", "UDP", "TCP/UDP"
	Name        string `json:"name"`         // Name in requested language
	ThreatRisk  string `json:"threat_risk"`  // Description of risk / exploits in requested language
	Severity    string `json:"severity"`     // "critical", "high", "medium"
	DefaultOn   bool   `json:"default_on"`   // Recommended default shielding state
	Category    string `json:"category"`     // "remote_access", "file_sharing", "network_discovery", "rpc"
}

// Built-in catalog entries
var defaultPortCatalog = []struct {
	Port       int
	Protocol   string
	NameEN     string
	NameRU     string
	RiskEN     string
	RiskRU     string
	Severity   string
	DefaultOn  bool
	Category   string
}{
	{
		Port:      445,
		Protocol:  "TCP",
		NameEN:    "SMB / Windows File Sharing",
		NameRU:    "SMB / Общий доступ к файлам Windows",
		RiskEN:    "Vector for ransomware propagation (WannaCry, NotPetya) and EternalBlue exploits.",
		RiskRU:    "Вектор распространения вирусов-вымогателей (Ransomware, WannaCry) и EternalBlue.",
		Severity:  "critical",
		DefaultOn: false,
		Category:  "file_sharing",
	},
	{
		Port:      135,
		Protocol:  "TCP",
		NameEN:    "RPC Endpoint Mapper",
		NameRU:    "RPC Endpoint Mapper",
		RiskEN:    "Remote code execution and network service enumeration via DCOM RPC.",
		RiskRU:    "Удаленное выполнение кода и перечисление сетевых сервисов через DCOM RPC.",
		Severity:  "critical",
		DefaultOn: false,
		Category:  "rpc",
	},
	{
		Port:      139,
		Protocol:  "TCP",
		NameEN:    "NetBIOS Session Service",
		NameRU:    "NetBIOS Session Service",
		RiskEN:    "NTLM hash relaying, credential leakage, and unauthorized local share access.",
		RiskRU:    "Утечка NTLM-хэшей и несанкционированный доступ к локальным ресурсам.",
		Severity:  "high",
		DefaultOn: false,
		Category:  "file_sharing",
	},
	{
		Port:      3389,
		Protocol:  "TCP/UDP",
		NameEN:    "Remote Desktop (RDP)",
		NameRU:    "Remote Desktop (RDP)",
		RiskEN:    "Vulnerable to credential brute-forcing, BlueKeep exploits, and unauthorized remote control.",
		RiskRU:    "Уязвимость к брутфорсу паролей, BlueKeep и несанкционированному удаленному доступу.",
		Severity:  "critical",
		DefaultOn: false,
		Category:  "remote_access",
	},
	{
		Port:      22,
		Protocol:  "TCP",
		NameEN:    "SSH Remote Console",
		NameRU:    "SSH Remote Console",
		RiskEN:    "Target for automated credential brute-force bots and unauthorized terminal access.",
		RiskRU:    "Несанкционированный доступ и брутфорс учетных записей сервера (SSH).",
		Severity:  "high",
		DefaultOn: false,
		Category:  "remote_access",
	},
	{
		Port:      23,
		Protocol:  "TCP",
		NameEN:    "Telnet Remote Console",
		NameRU:    "Telnet Remote Console",
		RiskEN:    "Cleartext unencrypted remote management protocol (high credential interception risk).",
		RiskRU:    "Незащищенный текстовый протокол управления (высокий риск перехвата учетных данных).",
		Severity:  "high",
		DefaultOn: false,
		Category:  "remote_access",
	},
	{
		Port:      5353,
		Protocol:  "UDP",
		NameEN:    "mDNS / Multicast Name Resolution",
		NameRU:    "mDNS / Multicast Name Resolution",
		RiskEN:    "Vulnerable to local network name spoofing and poisoning (Responder/Poisoning).",
		RiskRU:    "Уязвимость к атакам подмены сетевых имен (Responder/Poisoning) в локальной сети.",
		Severity:  "medium",
		DefaultOn: false,
		Category:  "network_discovery",
	},
	{
		Port:      5900,
		Protocol:  "TCP",
		NameEN:    "VNC Remote Desktop",
		NameRU:    "VNC Удаленный рабочий стол",
		RiskEN:    "Often unauthenticated or weakly encrypted remote frame buffer access.",
		RiskRU:    "Слабозащищенный доступ к удаленному рабочему столу VNC.",
		Severity:  "high",
		DefaultOn: false,
		Category:  "remote_access",
	},
	{
		Port:      5355,
		Protocol:  "UDP",
		NameEN:    "LLMNR Link-Local Multicast",
		NameRU:    "LLMNR Разрешение имен",
		RiskEN:    "Susceptible to LLMNR poisoning and NTLMv2 password hash capture.",
		RiskRU:    "Уязвимость к атакам перехвата NTLMv2 хэшей через LLMNR poisoning.",
		Severity:  "high",
		DefaultOn: false,
		Category:  "network_discovery",
	},
}

// GetPortShieldCatalog returns the localized catalog of sensitive ports.
func GetPortShieldCatalog(lang string) []PortShieldItem {
	isRU := strings.HasPrefix(strings.ToLower(strings.TrimSpace(lang)), "ru")
	items := make([]PortShieldItem, len(defaultPortCatalog))

	for i, c := range defaultPortCatalog {
		name := c.NameEN
		risk := c.RiskEN
		if isRU {
			name = c.NameRU
			risk = c.RiskRU
		}

		items[i] = PortShieldItem{
			Port:       c.Port,
			Protocol:   c.Protocol,
			Name:       name,
			ThreatRisk: risk,
			Severity:   c.Severity,
			DefaultOn:  c.DefaultOn,
			Category:   c.Category,
		}
	}
	return items
}
