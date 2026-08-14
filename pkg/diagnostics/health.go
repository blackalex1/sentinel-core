package diagnostics

import (
	"net"
	"time"
	"github.com/blackalex1/sentinel-core/pkg/crypto"
	"github.com/blackalex1/sentinel-core/pkg/i18n"
)

// HealthCheckReport holds the comprehensive self-check results
type HealthCheckReport struct {
	Timestamp      int64             `json:"timestamp"`
	Passed         bool              `json:"passed"`
	PortResults    []PortCheckResult `json:"portResults"`
	DNSResolving   bool              `json:"dnsResolving"`
	DNSLatencyMs   int64             `json:"dnsLatencyMs"`
	CryptoVaultOK  bool              `json:"cryptoVaultOk"`
	Issues         []string          `json:"issues"`
}

// RunHealthCheck executes all internal diagnostic checks
func RunHealthCheck(socksPort, httpPort int, testHost string, masterSecret string) HealthCheckReport {
	report := HealthCheckReport{
		Timestamp: time.Now().Unix(),
		Passed:    true,
		Issues:    make([]string, 0),
	}

	// 1. Port checks
	portsToCheck := []int{socksPort, httpPort}
	report.PortResults = CheckPorts(portsToCheck)
	for _, pr := range report.PortResults {
		if !pr.IsFree {
			report.Passed = false
			report.Issues = append(report.Issues, i18n.TGlobal("HEALTH_PORT_OCCUPIED_SIMPLE", pr.Port))
		}
	}

	// 2. DNS check
	dnsStart := time.Now()
	lookupHost := testHost
	if lookupHost == "" {
		lookupHost = "one.one.one.one"
	}
	ips, err := net.LookupHost(lookupHost)
	if err != nil || len(ips) == 0 {
		report.DNSResolving = false
		report.Passed = false
		report.Issues = append(report.Issues, i18n.TGlobal("HEALTH_DNS_LOOKUP_ERROR", lookupHost))
	} else {
		report.DNSResolving = true
		report.DNSLatencyMs = time.Since(dnsStart).Milliseconds()
	}

	// 3. Crypto Vault check
	if masterSecret != "" {
		vault, err := crypto.NewVault(masterSecret)
		if err != nil {
			report.CryptoVaultOK = false
			report.Passed = false
			report.Issues = append(report.Issues, i18n.TGlobal("HEALTH_VAULT_INIT_FAIL", err))
		} else {
			testPlaintext := "sentinel_crypto_integrity_check"
			enc, err := vault.EncryptString(testPlaintext)
			if err != nil {
				report.CryptoVaultOK = false
				report.Passed = false
				report.Issues = append(report.Issues, i18n.TGlobal("HEALTH_VAULT_ENCRYPT_FAIL"))
			} else {
				dec, err := vault.DecryptString(enc)
				if err != nil || dec != testPlaintext {
					report.CryptoVaultOK = false
					report.Passed = false
					report.Issues = append(report.Issues, i18n.TGlobal("HEALTH_VAULT_DECRYPT_FAIL"))
				} else {
					report.CryptoVaultOK = true
				}
			}
		}
	} else {
		report.CryptoVaultOK = true
	}

	return report
}
