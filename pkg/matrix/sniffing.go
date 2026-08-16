package matrix

import (
	"github.com/blackalex1/sentinel-core/pkg/i18n"
	"github.com/blackalex1/sentinel-core/pkg/matrix/types"
)

// GetSniffingOptions returns supported sniffing protocols localized for RU / EN
func GetSniffingOptions(lang string) []types.SniffingOption {
	loc := i18n.Locale(lang)
	return []types.SniffingOption{
		{ID: "tls", DisplayName: i18n.T(loc, "SNIFF_TLS_NAME"), Description: i18n.T(loc, "SNIFF_TLS_DESC"), Default: true},
		{ID: "http", DisplayName: i18n.T(loc, "SNIFF_HTTP_NAME"), Description: i18n.T(loc, "SNIFF_HTTP_DESC"), Default: true},
		{ID: "quic", DisplayName: i18n.T(loc, "SNIFF_QUIC_NAME"), Description: i18n.T(loc, "SNIFF_QUIC_DESC"), Default: true},
		{ID: "fakedns", DisplayName: i18n.T(loc, "SNIFF_FAKEDNS_NAME"), Description: i18n.T(loc, "SNIFF_FAKEDNS_DESC"), Default: true},
	}
}
