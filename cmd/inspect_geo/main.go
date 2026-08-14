package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"
)

type CategoryInfo struct {
	Tag         string
	DomainCount int
	SampleItems []string
}

type GeoIPInfo struct {
	CountryCode string
	CIDRCount   int
}

func main() {
	fmt.Println("==================================================")
	fmt.Println("   АНАЛИЗ И СТРУКТУРА ФАЙЛОВ GEOSITE.DAT И GEOIP.DAT")
	fmt.Println("==================================================")

	geositeData, err := os.ReadFile("data/geosite.dat")
	if err != nil {
		fmt.Printf("Ошибка чтения geosite.dat: %v\n", err)
		return
	}

	geoipData, err := os.ReadFile("data/geoip.dat")
	if err != nil {
		fmt.Printf("Ошибка чтения geoip.dat: %v\n", err)
		return
	}

	categories := parseGeositeProtobuf(geositeData)
	geoipList := parseGeoIPProtobuf(geoipData)

	fmt.Printf("\n📂 1. ФАЙЛ GEOSITE.DAT (Размер: %.2f МБ)\n", float64(len(geositeData))/(1024*1024))
	fmt.Printf("   Всего обнаружено категорий и баз доменов: %d\n\n", len(categories))

	// Group into logical sections
	fmt.Println("--- 🛡️ КАТЕГОРИИ БЛОКИРОВКИ И БЕЗОПАСНОСТИ (AdBlock & Malware):")
	printFiltered(categories, func(tag string) bool {
		return strings.Contains(tag, "ads") || strings.Contains(tag, "malware") || strings.Contains(tag, "phishing") || strings.Contains(tag, "cryptominers") || strings.Contains(tag, "porn") || tag == "adaway"
	})

	fmt.Println("\n--- 🇷🇺 РОССИЙСКИЕ СЕРВИСЫ И ГОСУСЛУГИ (RU Services & Gov):")
	printFiltered(categories, func(tag string) bool {
		return strings.Contains(tag, "gov-ru") || tag == "ru" || tag == "yandex" || tag == "vk" || tag == "mailru" || tag == "sberbank" || tag == "tinkoff" || tag == "ozon" || tag == "wildberries" || tag == "rutracker" || tag == "2gis" || tag == "avito"
	})

	fmt.Println("\n--- 🤖 НЕЙРОСЕТИ И AI (AI & LLM Services):")
	printFiltered(categories, func(tag string) bool {
		return strings.Contains(tag, "openai") || strings.Contains(tag, "anthropic") || strings.Contains(tag, "claude") || strings.Contains(tag, "bard") || strings.Contains(tag, "chatgpt") || strings.Contains(tag, "perplexity") || strings.Contains(tag, "midjourney")
	})

	fmt.Println("\n--- 🎬 СТРИМИНГ, МЕДИА И СОЦСЕТИ (Streaming & Social):")
	printFiltered(categories, func(tag string) bool {
		return tag == "youtube" || tag == "netflix" || tag == "spotify" || tag == "twitch" || tag == "tiktok" || tag == "instagram" || tag == "twitter" || tag == "facebook" || tag == "discord" || tag == "telegram"
	})

	fmt.Println("\n--- 🌐 КРУПНЫЕ ТЕХНОЛОГИЧЕСКИЕ И ОБЛАЧНЫЕ ПЛАТФОРМЫ:")
	printFiltered(categories, func(tag string) bool {
		return tag == "google" || tag == "apple" || tag == "microsoft" || tag == "github" || tag == "cloudflare" || tag == "amazon" || tag == "steam" || tag == "epicgames"
	})

	fmt.Printf("\n\n📂 2. ФАЙЛ GEOIP.DAT (Размер: %.2f МБ)\n", float64(len(geoipData))/(1024*1024))
	fmt.Printf("   Всего обнаружено баз GeoIP стран и сервисов: %d\n\n", len(geoipList))

	fmt.Println("--- 🌍 КЛЮЧЕВЫЕ БАЗЫ GEOIP (Подсети IP-адресов):")
	for _, g := range geoipList {
		code := strings.ToLower(g.CountryCode)
		if code == "ru" || code == "private" || code == "telegram" || code == "cloudflare" || code == "google" || code == "netflix" || code == "facebook" || code == "twitter" || code == "us" || code == "de" || code == "nl" || code == "kz" || code == "by" || code == "ua" {
			fmt.Printf("  • geoip:%-15s ➔ %6d IP/CIDR диапазонов\n", code, g.CIDRCount)
		}
	}
}

func printFiltered(categories []CategoryInfo, match func(string) bool) {
	count := 0
	for _, c := range categories {
		tagLower := strings.ToLower(c.Tag)
		if match(tagLower) {
			sample := ""
			if len(c.SampleItems) > 0 {
				sample = fmt.Sprintf(" (Примеры: %s)", strings.Join(c.SampleItems[:min(3, len(c.SampleItems))], ", "))
			}
			fmt.Printf("  • geosite:%-25s ➔ %5d доменов%s\n", tagLower, c.DomainCount, sample)
			count++
		}
	}
	if count == 0 {
		fmt.Println("  (нет явных совпадений)")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Protobuf decoder for GeositeList
func parseGeositeProtobuf(data []byte) []CategoryInfo {
	var categories []CategoryInfo
	offset := 0

	for offset < len(data) {
		tagWire, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		wireType := tagWire & 7
		fieldNum := tagWire >> 3

		if wireType != 2 {
			break
		}
		length, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		if offset+int(length) > len(data) {
			break
		}

		if fieldNum == 1 { // Entry message
			entryData := data[offset : offset+int(length)]
			cat := parseSingleSiteGroup(entryData)
			if cat.Tag != "" {
				categories = append(categories, cat)
			}
		}
		offset += int(length)
	}

	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Tag < categories[j].Tag
	})

	return categories
}

func parseSingleSiteGroup(data []byte) CategoryInfo {
	var cat CategoryInfo
	offset := 0

	for offset < len(data) {
		tagWire, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		fieldNum := tagWire >> 3
		wireType := tagWire & 7

		if wireType == 2 {
			length, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			valBytes := data[offset : offset+int(length)]
			offset += int(length)

			if fieldNum == 1 { // tag string
				cat.Tag = string(valBytes)
			} else if fieldNum == 2 { // Domain message
				cat.DomainCount++
				if len(cat.SampleItems) < 5 {
					domainVal := extractDomainValue(valBytes)
					if domainVal != "" {
						cat.SampleItems = append(cat.SampleItems, domainVal)
					}
				}
			}
		} else if wireType == 0 {
			_, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
		} else {
			break
		}
	}
	return cat
}

func extractDomainValue(domainData []byte) string {
	offset := 0
	for offset < len(domainData) {
		tagWire, n := binary.Uvarint(domainData[offset:])
		if n <= 0 {
			break
		}
		offset += n
		fieldNum := tagWire >> 3
		wireType := tagWire & 7

		if wireType == 2 {
			length, n := binary.Uvarint(domainData[offset:])
			if n <= 0 {
				break
			}
			offset += n
			if fieldNum == 2 { // value string
				return string(domainData[offset : offset+int(length)])
			}
			offset += int(length)
		} else if wireType == 0 {
			_, n := binary.Uvarint(domainData[offset:])
			if n <= 0 {
				break
			}
			offset += n
		} else {
			break
		}
	}
	return ""
}

// Protobuf decoder for GeoIPList
func parseGeoIPProtobuf(data []byte) []GeoIPInfo {
	var list []GeoIPInfo
	offset := 0

	for offset < len(data) {
		tagWire, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		fieldNum := tagWire >> 3
		wireType := tagWire & 7

		if wireType != 2 {
			break
		}
		length, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		if offset+int(length) > len(data) {
			break
		}

		if fieldNum == 1 { // GeoIP message
			g := parseSingleGeoIP(data[offset : offset+int(length)])
			if g.CountryCode != "" {
				list = append(list, g)
			}
		}
		offset += int(length)
	}

	return list
}

func parseSingleGeoIP(data []byte) GeoIPInfo {
	var g GeoIPInfo
	offset := 0

	for offset < len(data) {
		tagWire, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			break
		}
		offset += n
		fieldNum := tagWire >> 3
		wireType := tagWire & 7

		if wireType == 2 {
			length, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
			valBytes := data[offset : offset+int(length)]
			offset += int(length)

			if fieldNum == 1 { // country_code
				g.CountryCode = string(valBytes)
			} else if fieldNum == 2 { // Cidr message
				g.CIDRCount++
			}
		} else if wireType == 0 {
			_, n := binary.Uvarint(data[offset:])
			if n <= 0 {
				break
			}
			offset += n
		} else {
			break
		}
	}
	return g
}
