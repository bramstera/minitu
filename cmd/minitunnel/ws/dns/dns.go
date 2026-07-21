// Package dns resolves hostnames to IP addresses using DNS-over-HTTPS,
// falling back to the system resolver.
package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type dnsResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// ResolveHost resolves a hostname to an IPv4 address using Google DNS-over-HTTPS
// (dns.google) and, on failure, falls back to the system resolver.
func ResolveHost(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	dnsQuery := fmt.Sprintf("https://dns.google/resolve?name=%s&type=A", host)
	resp, err := client.Get(dnsQuery)
	if err == nil {
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr == nil {
			var dnsResp dnsResponse
			if json.Unmarshal(body, &dnsResp) == nil {
				if dnsResp.Status == 0 {
					for _, answer := range dnsResp.Answer {
						if answer.Type == 1 {
							return answer.Data, nil
						}
					}
				}
			}
		}
	}

	// Fallback to system DNS.
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found for %s", host)
}
