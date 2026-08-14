package i18n

// ruTranslations contains all Russian localization strings
var ruTranslations = map[string]string{
	// General Status & Errors
	"CORE_INITIALIZED":                   "Ядро Sentinel-Core успешно инициализировано (v%s)",
	"UNKNOWN_ERROR":                      "Неизвестная ошибка ядра: %s",
	"INVALID_SYNTAX":                     "Синтаксическая ошибка в конфигурации: %s",
	"UNSUPPORTED_PROTOCOL":               "Протокол '%s' не поддерживается ядром '%s'",
	"ERR_SERVER_NODE_NIL":               "Профиль сервера не может быть пустым",
	"ERR_UNSUPPORTED_PROTOCOL_SUGGEST":   "Ядро '%s' не поддерживает протокол '%s'. Рекомендуется переключить ядро на Sing-box",
	"ERR_PQ_STRICT_MODE":                 "Постквантовое шифрование включено для узла '%s', но ядро '%s' (%s) его не поддерживает",
	"ERR_REALITY_UNSUPPORTED":            "Ядро '%s' не поддерживает Reality для протокола '%s'",
	"ERR_FLOW_VISION_STRICT":             "Ядро '%s' не поддерживает XTLS Vision flow ('%s')",

	// Crypto & DB Vault
	"CRYPTO_KEY_TOO_SHORT":               "Ключ шифрования БД слишком короткий (требуется минимум 16 символов)",
	"CRYPTO_TAMPER_DETECTED":             "ВНИМАНИЕ: Обнаружена подделка или повреждение зашифрованных данных (AEAD tag mismatch)",
	"CRYPTO_DECRYPT_FAILED":              "Не удалось расшифровать параметры узла. Неверный мастер-ключ или поврежденные данные",
	"CRYPTO_ENCRYPT_SUCCESS":             "Данные успешно зашифрованы алгоритмом AES-256-GCM AEAD",

	// URI Parser
	"PARSER_INVALID_URI":                 "Некорректная ссылка на прокси: '%s'",
	"PARSER_UNSUPPORTED_SCHEME":          "Неподдерживаемая схема протокола: '%s'",
	"PARSER_MISSING_HOST":                "В ссылке отсутствует адрес сервера",
	"PARSER_MISSING_AUTH":                "В ссылке отсутствует ключ авторизации (UUID/пароль)",

	// Capability Matrix & Auto-Negotiation
	"PQ_DOWNGRADED_SINGBOX":              "Постквантовое шифрование Reality (Kyber768) автоматически переключено на стандартное X25519 для ядра %s",
	"PQ_STRICT_REJECT":                   "Ядро '%s' не поддерживает постквантовое шифрование TLS в строгом режиме",
	"FLOW_VISION_STRIPPED":               "XTLS Flow '%s' отключен для ядра '%s'",
	"HY2_AUTO_SWITCH_SINGBOX":            "Нативное ядро Hysteria 2 не поддерживает правила маршрутизации и TUN-режим. Конфиг автоматически переключен на Sing-box (с протоколом Hysteria2) для сохранения таблицы маршрутизации",
	"HY2_STRICT_REJECT":                  "Нативное ядро Hysteria 2 не поддерживает правила маршрутизации и системный TUN-режим",

	// Diagnostics & Health Checks
	"HEALTH_CHECK_PASSED":                "Все подсистемы ядра работают в штатном режиме",
	"HEALTH_CHECK_FAILED":                "Обнаружены неполадки в подсистемах ядра",
	"HEALTH_PORT_OCCUPIED":               "Порт %d (%s) уже занят другим приложением в системе",
	"HEALTH_PORT_OCCUPIED_SIMPLE":        "Локальный порт %d занят другим процессом",
	"HEALTH_PORT_FREE":                   "Порт %d (%s) свободен для прослушивания",
	"HEALTH_DNS_OK":                      "DNS-резолвер доступен (задержка: %dмс)",
	"HEALTH_DNS_TIMEOUT":                 "DNS-сервер '%s' не отвечает (таймаут)",
	"HEALTH_DNS_LOOKUP_ERROR":            "Ошибка разрешения DNS для хоста '%s'",
	"HEALTH_VAULT_OK":                    "Криптографический сейф БД проверен и готов к работе",
	"HEALTH_VAULT_INIT_FAIL":             "Сбой инициализации Crypto Vault: %v",
	"HEALTH_VAULT_ENCRYPT_FAIL":          "Сбой тестового шифрования AEAD",
	"HEALTH_VAULT_DECRYPT_FAIL":          "Сбой тестовой расшифровки AEAD",

	// Routing Actions (Действия правил)
	"ACTION_DIRECT":                      "Прямое подключение (DIRECT)",
	"ACTION_PROXY":                       "Проксирование (PROXY)",
	"ACTION_BLOCK":                       "Блокировка (BLOCKED)",
	"ACTION_CUSTOM_OUTBOUND":             "Направить в узел: %s",

	// Routing Category Presets (Категории трафика)
	"CATEGORY_ADS":                       "Реклама и трекеры",
	"CATEGORY_RU_SERVICES":               "Сервисы РФ и банки",
	"CATEGORY_AI_SERVICES":               "Нейросети и AI (OpenAI, Claude, Gemini)",
	"CATEGORY_STREAMING":                 "Стриминг и соцсети (YouTube, Instagram, X)",
	"CATEGORY_LAN":                       "Локальная сеть (LAN)",
	"CATEGORY_BITTORRENT":                "BitTorrent / P2P протокол",
	"CATEGORY_IP_LOOKUP":                 "Сервисы определения IP",

	// Routing Modes (Режимы маршрутизации)
	"ROUTING_MODE_SMART_NAME":            "Умные правила (Smart Rule)",
	"ROUTING_MODE_SMART_DESC":            "Маршрутизация по таблице правил",
	"ROUTING_MODE_GLOBAL_NAME":           "Глобальный прокси (Global Proxy)",
	"ROUTING_MODE_GLOBAL_DESC":           "Весь сетевой трафик устройства направляется через туннель (кроме LAN)",
	"ROUTING_MODE_DIRECT_NAME":           "Прямое подключение (Direct All)",
	"ROUTING_MODE_DIRECT_DESC":           "Весь сетевой трафик идет напрямую без проксирования",

	// UI Headers (Заголовки таблицы маршрутизации)
	"UI_ROUTING_TABLE_TITLE":             "Правила маршрутизации",
	"UI_ROUTING_TABLE_SUBTITLE":          "Правила проверяются сверху вниз. Вы можете менять порядок (приоритет) правил с помощью стрелок.",
	"UI_COL_ORDER":                       "ПОРЯДОК",
	"UI_COL_DESCRIPTION":                 "ОПИСАНИЕ",
	"UI_COL_CONDITIONS":                  "УСЛОВИЯ",
	"UI_COL_DESTINATION":                 "НАЗНАЧЕНИЕ",
	"UI_COL_STATUS":                      "СТАТУС",
	"UI_COL_ACTIONS":                     "ДЕЙСТВИЯ",
}
