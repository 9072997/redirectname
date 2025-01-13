package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var ErrNotUs = errors.New("hostname does not resolve to this server")
var ErrTooManyDots = errors.New("too many labels in hostname")
var ErrNoNS = errors.New("no NS records found at any level")
var ErrIP = errors.New("hostname is an IP address")
var publicIPs []net.IP

func init() {
	// From PUBLIC_IPS environment variable
	envIPs := os.Getenv("PUBLIC_IPS")
	if envIPs != "" {
		for _, ipStr := range strings.Split(envIPs, ",") {
			ip := net.ParseIP(strings.TrimSpace(ipStr))
			if ip != nil {
				publicIPs = append(publicIPs, ip)
			}
		}
	}

	// From local network interfaces
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// skip IPv6 and non-public addresses
			if ip != nil {
				ip = ip.To4()
			}
			if ip != nil && ip.IsGlobalUnicast() {
				publicIPs = append(publicIPs, ip)
			}
		}
	}
}

// getNSRecords attempts LookupNS iteratively from the full host down to the
// apex. This isn't really efficient, but it's simple and works.
func getNSRecords(host string) ([]*net.NS, error) {
	labels := strings.Split(host, ".")
	// sanity check
	if len(labels) > 10 {
		return nil, ErrTooManyDots
	}

	for i := range labels {
		candidate := strings.Join(labels[i:], ".")
		nsRecords, err := net.LookupNS(candidate)
		// If we found NS for this level, return them.
		if err == nil && len(nsRecords) > 0 {
			return nsRecords, nil
		}
	}
	return nil, ErrNoNS
}

// PreCheck verifies that the hostname resolves to this server by directly
// querying the authoritative nameservers for the hostname (to avoid any
// caching issues). It returns an error if the hostname does not resolve to
// this server.
func PreCheck(ctx context.Context, hostname string) error {
	// fail early if hostname is just an IP address
	if net.ParseIP(hostname) != nil {
		return ErrIP
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// fast-path: use normal system resolver
	{
		ips, err := net.LookupIP(hostname)
		if err != nil {
			goto SlowPath
		}
		for _, ip := range ips {
			if ip = ip.To4(); ip != nil {
				for _, pubIP := range publicIPs {
					if pubIP.Equal(ip) {
						return nil
					}
				}
			}
		}
	}

SlowPath:
	nsRecords, err := getNSRecords(hostname)
	if err != nil {
		return err
	}

	for _, ns := range nsRecords {
		nsAddr := strings.TrimSuffix(ns.Host, ".") + ":53"

		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

		client := new(dns.Client)
		resp, _, err := client.ExchangeContext(ctx, msg, nsAddr)
		if err != nil {
			continue
		}

		for _, ans := range resp.Answer {
			log.Println(ans)
			switch rr := ans.(type) {
			case *dns.A:
				for _, pubIP := range publicIPs {
					if pubIP.Equal(rr.A) {
						return nil
					}
				}
			case *dns.CNAME:
				// Resolve the CNAME target using system resolver.
				// The rational is that the CNAME target should be
				// older and more stable than the CNAME itself.
				ips, err := net.LookupIP(rr.Target)
				if err != nil {
					continue
				}
				for _, ip := range ips {
					if ip = ip.To4(); ip != nil {
						for _, pubIP := range publicIPs {
							if pubIP.Equal(ip) {
								return nil
							}
						}
					}
				}
			}
		}
	}

	return ErrNotUs
}
