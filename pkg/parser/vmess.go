package parser

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/blackalex1/sentinel-core/pkg/ast"
)

type flexInt int

func (f *flexInt) UnmarshalJSON(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" || s == "null" {
		return nil
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		unquoted, err := strconv.Unquote(s)
		if err != nil {
			return nil
		}
		p, _ := strconv.Atoi(strings.TrimSpace(unquoted))
		*f = flexInt(p)
		return nil
	}
	var n float64
	if err := json.Unmarshal(data, &n); err == nil {
		*f = flexInt(int(n))
	}
	return nil
}

func parseVMess(raw string) (*ast.ServerProfile, error) {
	cleanURI, fragment := extractFragmentAndClean(raw)
	b64 := strings.TrimPrefix(cleanURI, "vmess://")
	decoded, err := decodeBase64Safe(b64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode vmess base64: %w", err)
	}

	var v struct {
		PS   string  `json:"ps"`
		Add  string  `json:"add"`
		Port flexInt `json:"port"`
		ID   string  `json:"id"`
		Net  string  `json:"net"`
		Type string  `json:"type"`
		Host string  `json:"host"`
		Path string  `json:"path"`
		TLS  string  `json:"tls"`
		SNI  string  `json:"sni"`
		ALPN string  `json:"alpn"`
		FP   string  `json:"fp"`
		Scy  string  `json:"scy"`
	}

	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return nil, fmt.Errorf("failed to parse vmess json: %w", err)
	}

	port := int(v.Port)

	var alpn []string
	if v.ALPN != "" {
		alpn = strings.Split(v.ALPN, ",")
	}

	name := v.PS
	if name == "" {
		name = fragment
	}

	profile := &ast.ServerProfile{
		Protocol:    ast.ProtoVMess,
		Name:        name,
		Address:     v.Add,
		Port:        port,
		UUID:        v.ID,
		Transport:   v.Net,
		Path:        v.Path,
		Host:        v.Host,
		HeaderType:  v.Type,
		SNI:         v.SNI,
		Fingerprint: v.FP,
		ALPN:        alpn,
	}
	if v.TLS == "tls" {
		profile.Security = ast.SecurityTLS
	}

	if profile.Name == "" {
		profile.Name = fmt.Sprintf("VMess-%s:%d", profile.Address, profile.Port)
	}
	profile.Normalize()
	return profile, nil
}
