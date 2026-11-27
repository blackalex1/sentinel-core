package netfilter

import (
	"fmt"
	"strings"
)

// ThreatLevel defines the severity level of a classified network event.
type ThreatLevel string

const (
	LevelInfo     ThreatLevel = "INFO"
	LevelWarning  ThreatLevel = "WARNING"
	LevelCritical ThreatLevel = "CRITICAL"
)

// ClassifierPolicy defines configuration parameters for classifying netfilter traffic.
type ClassifierPolicy struct {
	VPNVMID                    int      `json:"vpn_vmid"`
	VPNVMIDs                   []int    `json:"vpn_vmids,omitempty"`
	TrustedAdminIPs            []string `json:"trusted_admin_ips,omitempty"`
	ProxmoxHost                string   `json:"proxmox_host,omitempty"`
	SensitivePorts             []int    `json:"sensitive_ports,omitempty"`
	WhitelistPorts             []int    `json:"whitelist_ports,omitempty"`
	VPNPorts                   []int    `json:"vpn_ports,omitempty"`
	LXCWhitelistVMIDs          []int    `json:"lxc_whitelist_vmids,omitempty"`
	AlertVPNClientUnusualPorts bool     `json:"alert_vpn_client_unusual_ports"`
}

// ClassificationResult contains the severity verdict and descriptive texts.
type ClassificationResult struct {
	RiskLevel   ThreatLevel `json:"risk_level"`
	Label       string      `json:"label"`
	Description string      `json:"description"`
}

// DefaultClassifierPolicy returns sensible defaults for connection classification.
func DefaultClassifierPolicy() ClassifierPolicy {
	return ClassifierPolicy{
		VPNVMID:                    100,
		SensitivePorts:             []int{22, 23, 3389, 3306, 5432, 27017, 6379, 8006, 9200, 2375},
		WhitelistPorts:            []int{80, 443, 53, 123, 8080, 8443},
		VPNPorts:                  []int{443, 8443, 2083, 2087, 2096, 80},
		AlertVPNClientUnusualPorts: false,
	}
}

func containsInt(slice []int, val int) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}

func isVPNVMID(vmid int, policy ClassifierPolicy) bool {
	if vmid > 0 && vmid == policy.VPNVMID {
		return true
	}
	return containsInt(policy.VPNVMIDs, vmid)
}

func localizedVerdict(isRu bool, level ThreatLevel, ruLabel, ruDesc, enLabel, enDesc string) ClassificationResult {
	if isRu {
		return ClassificationResult{RiskLevel: level, Label: ruLabel, Description: ruDesc}
	}
	return ClassificationResult{RiskLevel: level, Label: enLabel, Description: enDesc}
}

// ClassifyConnection analyzes an IptablesEvent against policy rules and returns a structured risk verdict.
func ClassifyConnection(event IptablesEvent, policy ClassifierPolicy, lang string) ClassificationResult {
	isRu := strings.ToLower(lang) != "en"

	sensitivePorts := policy.SensitivePorts
	if len(sensitivePorts) == 0 {
		sensitivePorts = []int{22, 23, 3389, 3306, 5432, 27017, 6379, 8006}
	}
	whitelistPorts := policy.WhitelistPorts
	if len(whitelistPorts) == 0 {
		whitelistPorts = []int{80, 443, 53, 123}
	}
	vpnPorts := policy.VPNPorts
	if len(vpnPorts) == 0 {
		vpnPorts = []int{443, 8443, 2083, 2087, 2096}
	}

	if event.VMID == 0 {
		return classifyHostTraffic(event, policy, sensitivePorts, isRu)
	}
	if isVPNVMID(event.VMID, policy) {
		return classifyVPNTraffic(event, policy, sensitivePorts, whitelistPorts, vpnPorts, isRu)
	}
	return classifyLXCTraffic(event, policy, sensitivePorts, whitelistPorts, isRu)
}

func classifyHostTraffic(event IptablesEvent, policy ClassifierPolicy, sensitivePorts []int, isRu bool) ClassificationResult {
	src, dst, dpt := event.Src, event.Dst, event.DPT
	if event.Direction == "IN" && (dpt == 22 || dpt == 8006) {
		if containsString(policy.TrustedAdminIPs, src) || src == dst || src == "127.0.0.1" || src == "::1" || src == "localhost" {
			return localizedVerdict(isRu, LevelInfo,
				fmt.Sprintf("🟢 Локальный вход на Хост (порт :%d)", dpt),
				fmt.Sprintf("Информационное: Доверенное подключение к панели управления Хоста с IP %s", src),
				fmt.Sprintf("🟢 Trusted Host Login (port :%d)", dpt),
				fmt.Sprintf("Info: Trusted connection to Host management from IP %s", src),
			)
		}
		if !IsPrivateIP(src) {
			return localizedVerdict(isRu, LevelCritical,
				fmt.Sprintf("🚨 Вход на Хост (порт :%d) из Интернета", dpt),
				fmt.Sprintf("КРИТИЧЕСКИЙ РИСК: Попытка подключения к управлению Хостом со внешнего IP %s!", src),
				fmt.Sprintf("🚨 Internet Host Access (port :%d)", dpt),
				fmt.Sprintf("CRITICAL RISK: Attempt to access Host management from external IP %s!", src),
			)
		}
		return localizedVerdict(isRu, LevelWarning,
			fmt.Sprintf("⚠️ Подозрительный локальный вход на Хост (порт :%d)", dpt),
			fmt.Sprintf("Внимание: Неавторизованный локальный IP %s подключился к порту управления %d!", src, dpt),
			fmt.Sprintf("⚠️ Suspicious Local Host Access (port :%d)", dpt),
			fmt.Sprintf("Warning: Unauthorized local IP %s connected to management port %d!", src, dpt),
		)
	}

	if event.Direction == "OUT" && containsInt(sensitivePorts, dpt) {
		proxmoxIP := "127.0.0.1"
		if policy.ProxmoxHost != "" {
			if pIP := strings.Split(policy.ProxmoxHost, ":")[0]; pIP != "" {
				proxmoxIP = pIP
			}
		}
		if dst == proxmoxIP || dst == "127.0.0.1" || dst == "::1" || dst == "localhost" || dst == src {
			return localizedVerdict(isRu, LevelInfo,
				fmt.Sprintf("🟢 Локальное служебное обращение Хоста (порт :%d)", dpt),
				fmt.Sprintf("Информационное: Локальное обращение хоста к собственному сервису на порту %d", dpt),
				fmt.Sprintf("🟢 Local Host Service Query (port :%d)", dpt),
				fmt.Sprintf("Info: Local host query to internal service on port %d", dpt),
			)
		}
		return localizedVerdict(isRu, LevelCritical,
			fmt.Sprintf("🚨 Исходящий запрос Хоста на sensitive порт :%d", dpt),
			fmt.Sprintf("КРИТИЧЕСКИЙ РИСК: Хост Proxmox VE обратился к чувствительному порту %d внешнего узла %s!", dpt, dst),
			fmt.Sprintf("🚨 Outbound Host Query to sensitive port :%d", dpt),
			fmt.Sprintf("CRITICAL RISK: Proxmox Host accessed sensitive port %d of external node %s!", dpt, dst),
		)
	}

	return localizedVerdict(isRu, LevelInfo,
		"Трафик Хоста",
		fmt.Sprintf("Соединение с Хостом на порт %d", dpt),
		"Host Traffic",
		fmt.Sprintf("Host connection on port %d", dpt),
	)
}

func classifyVPNTraffic(event IptablesEvent, policy ClassifierPolicy, sensitivePorts, whitelistPorts, vpnPorts []int, isRu bool) ClassificationResult {
	src, dst, dpt := event.Src, event.Dst, event.DPT
	if event.Direction == "IN" {
		if containsInt(vpnPorts, dpt) {
			return localizedVerdict(isRu, LevelInfo,
				"VPN-вход (Клиент)",
				"Легитимное подключение клиента к VPN-серверу",
				"VPN Inbound (Client)",
				"Legitimate client connection to VPN server",
			)
		}
		if dpt == 22 {
			if !IsPrivateIP(src) {
				return localizedVerdict(isRu, LevelCritical,
					"🚨 Вход SSH на VPN из Интернета",
					"КРИТИЧЕСКИЙ РИСК: Попытка входа по SSH на VPN-сервер из внешней сети!",
					"🚨 SSH Inbound on VPN from Internet",
					"CRITICAL RISK: SSH login attempt on VPN server from external network!",
				)
			}
			return localizedVerdict(isRu, LevelWarning,
				"⚠️ Локальный SSH на VPN-сервер",
				"Подозрительно: Попытка локального SSH входа на VPN-сервер",
				"⚠️ Local SSH to VPN Server",
				"Suspicious: Local SSH login attempt to VPN server",
			)
		}
		if containsInt(sensitivePorts, dpt) {
			if !IsPrivateIP(src) {
				return localizedVerdict(isRu, LevelCritical,
					fmt.Sprintf("🚨 Доступ к sensitive порту :%d из Сети", dpt),
					fmt.Sprintf("КРИТИЧЕСКИЙ РИСК: Внешний доступ к порту %d на VPN-сервере", dpt),
					fmt.Sprintf("🚨 Access to sensitive port :%d from Internet", dpt),
					fmt.Sprintf("CRITICAL RISK: External access to port %d on VPN server", dpt),
				)
			}
			return localizedVerdict(isRu, LevelWarning,
				fmt.Sprintf("⚠️ Локальный доступ к sensitive порту :%d", dpt),
				fmt.Sprintf("Подозрительно: Локальный доступ к чувствительному порту %d", dpt),
				fmt.Sprintf("⚠️ Local access to sensitive port :%d", dpt),
				fmt.Sprintf("Suspicious: Local access to sensitive port %d", dpt),
			)
		}
		return localizedVerdict(isRu, LevelInfo,
			"Входящий трафик VPN-сервера",
			fmt.Sprintf("Входящий запрос к VPN-серверу на порт %d", dpt),
			"VPN Inbound Traffic",
			fmt.Sprintf("Inbound query to VPN server on port %d", dpt),
		)
	}

	if event.Direction == "OUT" {
		isSensitive := containsInt(sensitivePorts, dpt)
		isWhitelisted := containsInt(whitelistPorts, dpt) || dpt == 80 || dpt == 443 || dpt == 53 || dpt == 123
		if event.IsLocalProcess {
			if isWhitelisted {
				return localizedVerdict(isRu, LevelInfo,
					"Локальный процесс VPN (Безопасный OUT)",
					fmt.Sprintf("Безопасный исходящий веб-запрос локального процесса VPN на порт %d", dpt),
					"VPN Local Process (Safe OUT)",
					fmt.Sprintf("Safe outbound web request from local VPN process on port %d", dpt),
				)
			}
			if isSensitive {
				return localizedVerdict(isRu, LevelCritical,
					fmt.Sprintf("🚨 Локальный процесс VPN: запрос на sensitive порт :%d", dpt),
					fmt.Sprintf("ОПАСНОСТЬ КОМПРОМЕТАЦИИ: Локальный процесс внутри VPN-контейнера обратился к чувствительному порту %d внешней сети (%s)!", dpt, dst),
					fmt.Sprintf("🚨 VPN Local Process: query to sensitive port :%d", dpt),
					fmt.Sprintf("COMPROMISE HAZARD: Local process inside VPN container accessed sensitive port %d of external network (%s)!", dpt, dst),
				)
			}
			return localizedVerdict(isRu, LevelWarning,
				fmt.Sprintf("⚠️ Локальный процесс VPN: нетипичный исходящий порт :%d", dpt),
				fmt.Sprintf("ПОДОЗРИТЕЛЬНО: Локальный процесс внутри VPN-контейнера обратился к неразрешенному порту %d внешней сети (%s)", dpt, dst),
				fmt.Sprintf("⚠️ VPN Local Process: unusual outbound port :%d", dpt),
				fmt.Sprintf("SUSPICIOUS: Local process inside VPN container accessed unallowed port %d of external network (%s)", dpt, dst),
			)
		}

		if isWhitelisted {
			return localizedVerdict(isRu, LevelInfo,
				"VPN-транзит (Безопасный OUT)",
				fmt.Sprintf("Пересылка безопасного веб-трафика VPN-клиента на порт %d", dpt),
				"VPN Transit (Safe OUT)",
				fmt.Sprintf("Forwarding safe web traffic of VPN client on port %d", dpt),
			)
		}
		if isSensitive {
			return localizedVerdict(isRu, LevelCritical,
				fmt.Sprintf("🚨 VPN-клиент: атака на sensitive порт :%d", dpt),
				fmt.Sprintf("ОПАСНОСТЬ: Подключенный VPN-клиент инициировал исходящую атаку / брутфорс на чувствительный порт %d внешней сети (%s)", dpt, dst),
				fmt.Sprintf("🚨 VPN Client: attack on sensitive port :%d", dpt),
				fmt.Sprintf("HAZARD: Connected VPN client initiated outbound probe/attack on sensitive port %d of external network (%s)", dpt, dst),
			)
		}
		if IsPrivateIP(dst) {
			return localizedVerdict(isRu, LevelInfo,
				"VPN-транзит (Локальный OUT)",
				fmt.Sprintf("Локальный запрос VPN-клиента на порт %d внутри подсети", dpt),
				"VPN Transit (Local OUT)",
				fmt.Sprintf("Local query of VPN client to port %d inside subnet", dpt),
			)
		}
		riskLvl := LevelInfo
		prefix := ""
		if policy.AlertVPNClientUnusualPorts {
			riskLvl = LevelWarning
			prefix = "⚠️ "
		}
		return localizedVerdict(isRu, riskLvl,
			fmt.Sprintf("%sVPN-клиент: нетипичный исходящий порт :%d", prefix, dpt),
			fmt.Sprintf("Внимание: Подключенный VPN-клиент обратился к нетипичному внешнему порту %d (%s)", dpt, dst),
			fmt.Sprintf("%sVPN Client: unusual outbound port :%d", prefix, dpt),
			fmt.Sprintf("Warning: Connected VPN client accessed unusual external port %d (%s)", dpt, dst),
		)
	}

	return localizedVerdict(isRu, LevelInfo, "Неизвестная активность", "Не удалось классифицировать сетевую активность", "Unknown Activity", "Failed to classify network activity")
}

func classifyLXCTraffic(event IptablesEvent, policy ClassifierPolicy, sensitivePorts, whitelistPorts []int, isRu bool) ClassificationResult {
	vmid, src, dst, dpt := event.VMID, event.Src, event.Dst, event.DPT
	isSrcPrivate := IsPrivateIP(src)
	isDstPrivate := IsPrivateIP(dst)
	isSensitive := containsInt(sensitivePorts, dpt)
	isWhitelisted := containsInt(whitelistPorts, dpt)

	if event.Direction == "IN" {
		if isSensitive {
			if !isSrcPrivate {
				return localizedVerdict(isRu, LevelCritical,
					fmt.Sprintf("🚨 Вход на порт :%d из Интернета", dpt),
					fmt.Sprintf("ОПАСНОСТЬ: Внешний доступ к критическому порту %d с IP %s", dpt, src),
					fmt.Sprintf("🚨 Port :%d access from Internet", dpt),
					fmt.Sprintf("HAZARD: External access to critical port %d from IP %s", dpt, src),
				)
			}
			return localizedVerdict(isRu, LevelWarning,
				fmt.Sprintf("⚠️ Локальный вход на порт :%d", dpt),
				fmt.Sprintf("Внимание: Доступ к критическому порту %d из локальной сети с IP %s", dpt, src),
				fmt.Sprintf("⚠️ Local access to port :%d", dpt),
				fmt.Sprintf("Warning: Access to critical port %d from local network IP %s", dpt, src),
			)
		}
		if isWhitelisted || dpt == 80 || dpt == 443 || dpt == 8080 {
			return localizedVerdict(isRu, LevelInfo,
				"Безопасный входящий трафик",
				fmt.Sprintf("Запрос на разрешенный порт %d", dpt),
				"Safe Inbound Traffic",
				fmt.Sprintf("Query to allowed port %d", dpt),
			)
		}
		return localizedVerdict(isRu, LevelInfo,
			"Обычное входящее соединение",
			fmt.Sprintf("Входящее соединение на порт %d", dpt),
			"Normal Inbound Connection",
			fmt.Sprintf("Inbound connection on port %d", dpt),
		)
	}

	if event.Direction == "OUT" {
		if containsInt(policy.LXCWhitelistVMIDs, vmid) {
			return localizedVerdict(isRu, LevelInfo,
				"Доверенный исходящий трафик LXC",
				fmt.Sprintf("Легитимная исходящая активность доверенного контейнера %d на порт %d", vmid, dpt),
				"Trusted LXC Outbound Traffic",
				fmt.Sprintf("Legitimate outbound activity of whitelisted container %d to port %d", vmid, dpt),
			)
		}
		if isSensitive {
			return localizedVerdict(isRu, LevelWarning,
				fmt.Sprintf("⚠️ Исходящий SSH/DB запрос на :%d", dpt),
				fmt.Sprintf("Внимание: Контейнер инициировал исходящее соединение на чувствительный порт %d", dpt),
				fmt.Sprintf("⚠️ Outbound SSH/DB query to :%d", dpt),
				fmt.Sprintf("Warning: Container initiated outbound connection to sensitive port %d", dpt),
			)
		}
		if isWhitelisted || dpt == 80 || dpt == 443 || dpt == 53 || dpt == 123 {
			return localizedVerdict(isRu, LevelInfo,
				"Безопасный веб-трафик (OUT)",
				fmt.Sprintf("Запрос во внешнюю сеть на стандартный порт %d", dpt),
				"Safe Web Traffic (OUT)",
				fmt.Sprintf("Query to external network on standard port %d", dpt),
			)
		}
		if !isDstPrivate {
			return localizedVerdict(isRu, LevelWarning,
				fmt.Sprintf("⚠️ Нетипичный исходящий порт :%d", dpt),
				fmt.Sprintf("ПОДОЗРИТЕЛЬНО: Исходящее соединение на неразрешенный внешний порт %d (возможный backdoor!)", dpt),
				fmt.Sprintf("⚠️ Unusual Outbound Port :%d", dpt),
				fmt.Sprintf("SUSPICIOUS: Outbound connection to unallowed external port %d (possible backdoor!)", dpt),
			)
		}
		return localizedVerdict(isRu, LevelInfo,
			"Исходящее локальное соединение",
			fmt.Sprintf("Исходящий запрос в локальной сети на порт %d", dpt),
			"Outbound Local Connection",
			fmt.Sprintf("Outbound local subnet query on port %d", dpt),
		)
	}

	return localizedVerdict(isRu, LevelInfo, "Неизвестная активность", "Не удалось классифицировать сетевую активность", "Unknown Activity", "Failed to classify network activity")
}
