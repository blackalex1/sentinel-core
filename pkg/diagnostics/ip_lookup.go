package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// PublicIPInfo contains the resolved public IP and geographic metadata
type PublicIPInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	City        string `json:"city,omitempty"`
	Region      string `json:"region,omitempty"`
	Org         string `json:"org,omitempty"`
	ASN         string `json:"asn,omitempty"`
}

var (
	ipv4Regex = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	ipv6Regex = regexp.MustCompile(`\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b`)
)

type ipEndpoint struct {
	URL      string
	IsJSON   bool
	Parser   func(body []byte) (*PublicIPInfo, error)
}

var defaultIPEndpoints = []ipEndpoint{
	{
		URL:    "https://ipwho.is/?output=json",
		IsJSON: true,
		Parser: func(body []byte) (*PublicIPInfo, error) {
			var resp struct {
				Success     bool   `json:"success"`
				IP          string `json:"ip"`
				Country     string `json:"country"`
				CountryCode string `json:"country_code"`
				City        string `json:"city"`
				Region      string `json:"region"`
				Connection  struct {
					ASN string `json:"asn"`
					Org string `json:"org"`
					ISP string `json:"isp"`
				} `json:"connection"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				return nil, err
			}
			if !resp.Success && resp.IP == "" {
				return nil, fmt.Errorf("ipwho.is returned failure")
			}
			org := resp.Connection.Org
			if org == "" {
				org = resp.Connection.ISP
			}
			return &PublicIPInfo{
				IP:          resp.IP,
				Country:     resp.Country,
				CountryCode: resp.CountryCode,
				City:        resp.City,
				Region:      resp.Region,
				Org:         org,
				ASN:         resp.Connection.ASN,
			}, nil
		},
	},
	{
		URL:    "https://ifconfig.co/json",
		IsJSON: true,
		Parser: func(body []byte) (*PublicIPInfo, error) {
			var resp struct {
				IP          string `json:"ip"`
				Country     string `json:"country"`
				CountryCode string `json:"country_iso"`
				City        string `json:"city"`
				ASN         string `json:"asn"`
				Org         string `json:"asn_org"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				return nil, err
			}
			if resp.IP == "" {
				return nil, fmt.Errorf("empty IP from ifconfig.co")
			}
			return &PublicIPInfo{
				IP:          resp.IP,
				Country:     resp.Country,
				CountryCode: resp.CountryCode,
				City:        resp.City,
				Org:         resp.Org,
				ASN:         resp.ASN,
			}, nil
		},
	},
	{
		URL:    "https://api.ipify.org?format=json",
		IsJSON: true,
		Parser: func(body []byte) (*PublicIPInfo, error) {
			var resp struct {
				IP string `json:"ip"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				return nil, err
			}
			if resp.IP == "" {
				return nil, fmt.Errorf("empty IP from ipify")
			}
			return &PublicIPInfo{
				IP: resp.IP,
			}, nil
		},
	},
	{
		URL:    "https://checkip.amazonaws.com",
		IsJSON: false,
		Parser: func(body []byte) (*PublicIPInfo, error) {
			text := strings.TrimSpace(string(body))
			match := ipv4Regex.FindString(text)
			if match == "" {
				match = ipv6Regex.FindString(text)
			}
			if match == "" {
				return nil, fmt.Errorf("no valid IP found in amazonaws response")
			}
			return &PublicIPInfo{
				IP: match,
			}, nil
		},
	},
}

// GetPublicIP concurrently probes trusted endpoints through an optional SOCKS5 proxy and returns the fastest valid result
func GetPublicIP(socksPort int, authUser, authPass string, timeout time.Duration) (*PublicIPInfo, error) {
	if timeout <= 0 {
		timeout = 3500 * time.Millisecond
	}

	var transport *http.Transport
	if socksPort > 0 {
		var proxyURL *url.URL
		var err error
		if authUser != "" {
			proxyURL, err = url.Parse(fmt.Sprintf("socks5://%s:%s@127.0.0.1:%d", url.QueryEscape(authUser), url.QueryEscape(authPass), socksPort))
		} else {
			proxyURL, err = url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", socksPort))
		}
		if err != nil {
			return nil, fmt.Errorf("invalid socks5 proxy URL: %w", err)
		}
		transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: -1,
			}).DialContext,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		}
	} else {
		transport = &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: -1,
			}).DialContext,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: timeout,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	type fetchResult struct {
		info *PublicIPInfo
		err  error
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resChan := make(chan fetchResult, len(defaultIPEndpoints))

	for _, ep := range defaultIPEndpoints {
		go func(endpoint ipEndpoint) {
			req, err := http.NewRequestWithContext(ctx, "GET", endpoint.URL, nil)
			if err != nil {
				resChan <- fetchResult{nil, err}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelCore/1.0")
			req.Header.Set("Accept", "application/json, text/plain, */*")

			resp, err := client.Do(req)
			if err != nil {
				resChan <- fetchResult{nil, err}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				resChan <- fetchResult{nil, fmt.Errorf("http status %d", resp.StatusCode)}
				return
			}

			body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*64))
			if err != nil {
				resChan <- fetchResult{nil, err}
				return
			}

			info, err := endpoint.Parser(body)
			if err != nil || info == nil || info.IP == "" {
				resChan <- fetchResult{nil, fmt.Errorf("parse error: %v", err)}
				return
			}

			resChan <- fetchResult{info, nil}
		}(ep)
	}

	var lastErr error
	for i := 0; i < len(defaultIPEndpoints); i++ {
		select {
		case r := <-resChan:
			if r.err == nil && r.info != nil && r.info.IP != "" {
				cancel()
				return r.info, nil
			}
			lastErr = r.err
		case <-ctx.Done():
			return nil, fmt.Errorf("public IP fetch timeout: %w", ctx.Err())
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("failed to resolve public IP from all endpoints")
	}
	return nil, lastErr
}
