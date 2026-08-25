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

	vmid := event.VMID
	direction := event.Direction
	src := event.Src
	dst := event.Dst
	dpt := event.DPT

	// 0. Proxmox VE Host traffic (vmid == 0)
	if vmid == 0 {
		if direction == "IN" {
			if dpt == 22 || dpt == 8006 {
				if containsString(policy.TrustedAdminIPs, src) || src == dst || src == "127.0.0.1" || src == "::1" || src == "localhost" {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelInfo,
							Label:       fmt.Sprintf("🟢 Локальный вход на Хост (порт :%d)", dpt),
							Description: fmt.Sprintf("Информационное: Доверенное подключение к панели управления Хоста с IP %s", src),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelInfo,
						Label:       fmt.Sprintf("🟢 Trusted Host Login (port :%d)", dpt),
						Description: fmt.Sprintf("Info: Trusted connection to Host management from IP %s", src),
					}
				} else if !IsPrivateIP(src) {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelCritical,
							Label:       fmt.Sprintf("🚨 Вход на Хост (порт :%d) из Интернета", dpt),
							Description: fmt.Sprintf("КРИТИЧЕСКИЙ РИСК: Попытка подключения к управлению Хостом со внешнего IP %s!", src),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelCritical,
						Label:       fmt.Sprintf("🚨 Internet Host Access (port :%d)", dpt),
						Description: fmt.Sprintf("CRITICAL RISK: Attempt to access Host management from external IP %s!", src),
					}
				} else {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelWarning,
							Label:       fmt.Sprintf("⚠️ Подозрительный локальный вход на Хост (порт :%d)", dpt),
							Description: fmt.Sprintf("Внимание: Неавторизованный локальный IP %s подключился к порту управления %d!", src, dpt),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelWarning,
						Label:       fmt.Sprintf("⚠️ Suspicious Local Host Access (port :%d)", dpt),
						Description: fmt.Sprintf("Warning: Unauthorized local IP %s connected to management port %d!", src, dpt),
					}
				}
			}
		} else if direction == "OUT" {
			if containsInt(sensitivePorts, dpt) {
				proxmoxIP := "127.0.0.1"
				if policy.ProxmoxHost != "" {
					pIP := strings.Split(policy.ProxmoxHost, ":")[0]
					if pIP != "" {
						proxmoxIP = pIP
					}
				}

				if dst == proxmoxIP || dst == "127.0.0.1" || dst == "::1" || dst == "localhost" || dst == src {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelInfo,
							Label:       fmt.Sprintf("🟢 Локальное служебное обращение Хоста (порт :%d)", dpt),
							Description: fmt.Sprintf("Информационное: Локальное обращение хоста к собственному сервису на порту %d", dpt),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelInfo,
						Label:       fmt.Sprintf("🟢 Local Host Service Query (port :%d)", dpt),
						Description: fmt.Sprintf("Info: Local host query to internal service on port %d", dpt),
					}
				}

				if isRu {
					return ClassificationResult{
						RiskLevel:   LevelCritical,
						Label:       fmt.Sprintf("🚨 Исходящий запрос Хоста на sensitive порт :%d", dpt),
						Description: fmt.Sprintf("КРИТИЧЕСКИЙ РИСК: Хост Proxmox VE обратился к чувствительному порту %d внешнего узла %s!", dpt, dst),
					}
				}
				return ClassificationResult{
					RiskLevel:   LevelCritical,
					Label:       fmt.Sprintf("🚨 Outbound Host Query to sensitive port :%d", dpt),
					Description: fmt.Sprintf("CRITICAL RISK: Proxmox Host accessed sensitive port %d of external node %s!", dpt, dst),
				}
			}
		}

		if isRu {
			return ClassificationResult{
				RiskLevel:   LevelInfo,
				Label:       "Трафик Хоста",
				Description: fmt.Sprintf("Соединение с Хостом на порт %d", dpt),
			}
		}
		return ClassificationResult{
			RiskLevel:   LevelInfo,
			Label:       "Host Traffic",
			Description: fmt.Sprintf("Host connection on port %d", dpt),
		}
	}

	// 1. VPN / Spectre Panel container
	if isVPNVMID(vmid, policy) {
		isLocal := event.IsLocalProcess

		if direction == "IN" {
			if containsInt(vpnPorts, dpt) {
				if isRu {
					return ClassificationResult{
						RiskLevel:   LevelInfo,
						Label:       "VPN-вход (Клиент)",
						Description: "Легитимное подключение клиента к VPN-серверу",
					}
				}
				return ClassificationResult{
					RiskLevel:   LevelInfo,
					Label:       "VPN Inbound (Client)",
					Description: "Legitimate client connection to VPN server",
				}
			}

			if dpt == 22 {
				if !IsPrivateIP(src) {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelCritical,
							Label:       "🚨 Вход SSH на VPN из Интернета",
							Description: "КРИТИЧЕСКИЙ РИСК: Попытка входа по SSH на VPN-сервер из внешней сети!",
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelCritical,
						Label:       "🚨 SSH Inbound on VPN from Internet",
						Description: "CRITICAL RISK: SSH login attempt on VPN server from external network!",
					}
				} else {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelWarning,
							Label:       "⚠️ Локальный SSH на VPN-сервер",
							Description: "Подозрительно: Попытка локального SSH входа на VPN-сервер",
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelWarning,
						Label:       "⚠️ Local SSH to VPN Server",
						Description: "Suspicious: Local SSH login attempt to VPN server",
					}
				}
			}

			if containsInt(sensitivePorts, dpt) {
				if !IsPrivateIP(src) {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelCritical,
							Label:       fmt.Sprintf("🚨 Доступ к sensitive порту :%d из Сети", dpt),
							Description: fmt.Sprintf("КРИТИЧЕСКИЙ РИСК: Внешний доступ к порту %d на VPN-сервере", dpt),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelCritical,
						Label:       fmt.Sprintf("🚨 Access to sensitive port :%d from Internet", dpt),
						Description: fmt.Sprintf("CRITICAL RISK: External access to port %d on VPN server", dpt),
					}
				} else {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelWarning,
							Label:       fmt.Sprintf("⚠️ Локальный доступ к sensitive порту :%d", dpt),
							Description: fmt.Sprintf("Подозрительно: Локальный доступ к чувствительному порту %d", dpt),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelWarning,
						Label:       fmt.Sprintf("⚠️ Local access to sensitive port :%d", dpt),
						Description: fmt.Sprintf("Suspicious: Local access to sensitive port %d", dpt),
					}
				}
			}

			if isRu {
				return ClassificationResult{
					RiskLevel:   LevelInfo,
					Label:       "Входящий трафик VPN-сервера",
					Description: fmt.Sprintf("Входящий запрос к VPN-серверу на порт %d", dpt),
				}
			}
			return ClassificationResult{
				RiskLevel:   LevelInfo,
				Label:       "VPN Inbound Traffic",
				Description: fmt.Sprintf("Inbound query to VPN server on port %d", dpt),
			}
		} else if direction == "OUT" {
			isSensitive := containsInt(sensitivePorts, dpt)
			isWhitelisted := containsInt(whitelistPorts, dpt) || dpt == 80 || dpt == 443 || dpt == 53 || dpt == 123

			if isLocal {
				if isWhitelisted {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelInfo,
							Label:       "Локальный процесс VPN (Безопасный OUT)",
							Description: fmt.Sprintf("Безопасный исходящий веб-запрос локального процесса VPN на порт %d", dpt),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelInfo,
						Label:       "VPN Local Process (Safe OUT)",
						Description: fmt.Sprintf("Safe outbound web request from local VPN process on port %d", dpt),
					}
				} else if isSensitive {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelCritical,
							Label:       fmt.Sprintf("🚨 Локальный процесс VPN: запрос на sensitive порт :%d", dpt),
							Description: fmt.Sprintf("ОПАСНОСТЬ КОМПРОМЕТАЦИИ: Локальный процесс внутри VPN-контейнера обратился к чувствительному порту %d внешней сети (%s)!", dpt, dst),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelCritical,
						Label:       fmt.Sprintf("🚨 VPN Local Process: query to sensitive port :%d", dpt),
						Description: fmt.Sprintf("COMPROMISE HAZARD: Local process inside VPN container accessed sensitive port %d of external network (%s)!", dpt, dst),
					}
				} else {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelWarning,
							Label:       fmt.Sprintf("⚠️ Локальный процесс VPN: нетипичный исходящий порт :%d", dpt),
							Description: fmt.Sprintf("ПОДОЗРИТЕЛЬНО: Локальный процесс внутри VPN-контейнера обратился к неразрешенному порту %d внешней сети (%s)", dpt, dst),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelWarning,
						Label:       fmt.Sprintf("⚠️ VPN Local Process: unusual outbound port :%d", dpt),
						Description: fmt.Sprintf("SUSPICIOUS: Local process inside VPN container accessed unallowed port %d of external network (%s)", dpt, dst),
					}
				}
			} else {
				if isWhitelisted {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelInfo,
							Label:       "VPN-транзит (Безопасный OUT)",
							Description: fmt.Sprintf("Пересылка безопасного веб-трафика VPN-клиента на порт %d", dpt),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelInfo,
						Label:       "VPN Transit (Safe OUT)",
						Description: fmt.Sprintf("Forwarding safe web traffic of VPN client on port %d", dpt),
					}
				} else if isSensitive {
					if isRu {
						return ClassificationResult{
							RiskLevel:   LevelCritical,
							Label:       fmt.Sprintf("🚨 VPN-клиент: атака на sensitive порт :%d", dpt),
							Description: fmt.Sprintf("ОПАСНОСТЬ: Подключенный VPN-клиент инициировал исходящую атаку / брутфорс на чувствительный порт %d внешней сети (%s)", dpt, dst),
						}
					}
					return ClassificationResult{
						RiskLevel:   LevelCritical,
						Label:       fmt.Sprintf("🚨 VPN Client: attack on sensitive port :%d", dpt),
						Description: fmt.Sprintf("HAZARD: Connected VPN client initiated outbound probe/attack on sensitive port %d of external network (%s)", dpt, dst),
					}
				} else {
					if IsPrivateIP(dst) {
						if isRu {
							return ClassificationResult{
								RiskLevel:   LevelInfo,
								Label:       "VPN-транзит (Локальный OUT)",
								Description: fmt.Sprintf("Локальный запрос VPN-клиента на порт %d внутри подсети", dpt),
							}
						}
						return ClassificationResult{
							RiskLevel:   LevelInfo,
							Label:       "VPN Transit (Local OUT)",
							Description: fmt.Sprintf("Local query of VPN client to port %d inside subnet", dpt),
						}
					}

					riskLvl := LevelInfo
					prefix := ""
					if policy.AlertVPNClientUnusualPorts {
						riskLvl = LevelWarning
						prefix = "⚠️ "
					}
					if isRu {
						return ClassificationResult{
							RiskLevel:   riskLvl,
							Label:       fmt.Sprintf("%sVPN-клиент: нетипичный исходящий порт :%d", prefix, dpt),
							Description: fmt.Sprintf("Внимание: Подключенный VPN-клиент обратился к нетипичному внешнему порту %d (%s)", dpt, dst),
						}
					}
					return ClassificationResult{
						RiskLevel:   riskLvl,
						Label:       fmt.Sprintf("%sVPN Client: unusual outbound port :%d", prefix, dpt),
						Description: fmt.Sprintf("Warning: Connected VPN client accessed unusual external port %d (%s)", dpt, dst),
					}
				}
			}
		}
	}

	// 2. Generic rules for all other LXC containers
	isSrcPrivate := IsPrivateIP(src)
	isDstPrivate := IsPrivateIP(dst)
	isSensitive := containsInt(sensitivePorts, dpt)
	isWhitelisted := containsInt(whitelistPorts, dpt)

	if direction == "IN" {
		if isSensitive {
			if !isSrcPrivate {
				if isRu {
					return ClassificationResult{
						RiskLevel:   LevelCritical,
						Label:       fmt.Sprintf("🚨 Вход на порт :%d из Интернета", dpt),
						Description: fmt.Sprintf("ОПАСНОСТЬ: Внешний доступ к критическому порту %d с IP %s", dpt, src),
					}
				}
				return ClassificationResult{
					RiskLevel:   LevelCritical,
					Label:       fmt.Sprintf("🚨 Port :%d access from Internet", dpt),
					Description: fmt.Sprintf("HAZARD: External access to critical port %d from IP %s", dpt, src),
				}
			}
			if isRu {
				return ClassificationResult{
					RiskLevel:   LevelWarning,
					Label:       fmt.Sprintf("⚠️ Локальный вход на порт :%d", dpt),
					Description: fmt.Sprintf("Внимание: Доступ к критическому порту %d из локальной сети с IP %s", dpt, src),
				}
			}
			return ClassificationResult{
				RiskLevel:   LevelWarning,
				Label:       fmt.Sprintf("⚠️ Local access to port :%d", dpt),
				Description: fmt.Sprintf("Warning: Access to critical port %d from local network IP %s", dpt, src),
			}
		}

		if isWhitelisted || dpt == 80 || dpt == 443 || dpt == 8080 {
			if isRu {
				return ClassificationResult{
					RiskLevel:   LevelInfo,
					Label:       "Безопасный входящий трафик",
					Description: fmt.Sprintf("Запрос на разрешенный порт %d", dpt),
				}
			}
			return ClassificationResult{
				RiskLevel:   LevelInfo,
				Label:       "Safe Inbound Traffic",
				Description: fmt.Sprintf("Query to allowed port %d", dpt),
			}
		}

		if isRu {
			return ClassificationResult{
				RiskLevel:   LevelInfo,
				Label:       "Обычное входящее соединение",
				Description: fmt.Sprintf("Входящее соединение на порт %d", dpt),
			}
		}
		return ClassificationResult{
			RiskLevel:   LevelInfo,
			Label:       "Normal Inbound Connection",
			Description: fmt.Sprintf("Inbound connection on port %d", dpt),
		}
	} else if direction == "OUT" {
		if containsInt(policy.LXCWhitelistVMIDs, vmid) {
			if isRu {
				return ClassificationResult{
					RiskLevel:   LevelInfo,
					Label:       "Доверенный исходящий трафик LXC",
					Description: fmt.Sprintf("Легитимная исходящая активность доверенного контейнера %d на порт %d", vmid, dpt),
				}
			}
			return ClassificationResult{
				RiskLevel:   LevelInfo,
				Label:       "Trusted LXC Outbound Traffic",
				Description: fmt.Sprintf("Legitimate outbound activity of whitelisted container %d to port %d", vmid, dpt),
			}
		}

		if isSensitive {
			if isRu {
				return ClassificationResult{
					RiskLevel:   LevelWarning,
					Label:       fmt.Sprintf("⚠️ Исходящий SSH/DB запрос на :%d", dpt),
					Description: fmt.Sprintf("Внимание: Контейнер инициировал исходящее соединение на чувствительный порт %d", dpt),
				}
			}
			return ClassificationResult{
				RiskLevel:   LevelWarning,
				Label:       fmt.Sprintf("⚠️ Outbound SSH/DB query to :%d", dpt),
				Description: fmt.Sprintf("Warning: Container initiated outbound connection to sensitive port %d", dpt),
			}
		}

		if isWhitelisted || dpt == 80 || dpt == 443 || dpt == 53 || dpt == 123 {
			if isRu {
				return ClassificationResult{
					RiskLevel:   LevelInfo,
					Label:       "Безопасный веб-трафик (OUT)",
					Description: fmt.Sprintf("Запрос во внешнюю сеть на стандартный порт %d", dpt),
				}
			}
			return ClassificationResult{
				RiskLevel:   LevelInfo,
				Label:       "Safe Web Traffic (OUT)",
				Description: fmt.Sprintf("Query to external network on standard port %d", dpt),
			}
		}

		if !isDstPrivate {
			if isRu {
				return ClassificationResult{
					RiskLevel:   LevelWarning,
					Label:       fmt.Sprintf("⚠️ Нетипичный исходящий порт :%d", dpt),
					Description: fmt.Sprintf("ПОДОЗРИТЕЛЬНО: Исходящее соединение на неразрешенный внешний порт %d (возможный backdoor!)", dpt),
				}
			}
			return ClassificationResult{
				RiskLevel:   LevelWarning,
				Label:       fmt.Sprintf("⚠️ Unusual Outbound Port :%d", dpt),
				Description: fmt.Sprintf("SUSPICIOUS: Outbound connection to unallowed external port %d (possible backdoor!)", dpt),
			}
		}

		if isRu {
			return ClassificationResult{
				RiskLevel:   LevelInfo,
				Label:       "Исходящее локальное соединение",
				Description: fmt.Sprintf("Исходящий запрос в локальной сети на порт %d", dpt),
			}
		}
		return ClassificationResult{
			RiskLevel:   LevelInfo,
			Label:       "Outbound Local Connection",
			Description: fmt.Sprintf("Outbound local subnet query on port %d", dpt),
		}
	}

	if isRu {
		return ClassificationResult{
			RiskLevel:   LevelInfo,
			Label:       "Неизвестная активность",
			Description: "Не удалось классифицировать сетевую активность",
		}
	}
	return ClassificationResult{
		RiskLevel:   LevelInfo,
		Label:       "Unknown Activity",
		Description: "Failed to classify network activity",
	}
}
