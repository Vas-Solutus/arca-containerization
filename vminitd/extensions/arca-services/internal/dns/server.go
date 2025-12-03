package dns

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/miekg/dns" // DNS library
)

// Server is a DNS server that handles internal container names and forwards external queries
type Server struct {
	addr        string
	resolver    *Resolver
	upstreamDNS []string // External DNS servers (e.g., ["8.8.8.8:53", "8.8.4.4:53"])
	dnsServer   *dns.Server
}

// NewServer creates a new DNS server
// Starts with fallback DNS servers; updated to use vmnet gateway when first network is added
func NewServer(addr string, resolver *Resolver) *Server {
	// Start with fallback DNS - will be updated to vmnet gateway when first network added
	upstreamDNS := []string{"8.8.8.8:53", "8.8.4.4:53"}

	log.Printf("[DNS] Starting with fallback DNS servers: %v", upstreamDNS)
	log.Printf("[DNS] Will be updated to vmnet gateway when first network is added")

	return &Server{
		addr:        addr,
		resolver:    resolver,
		upstreamDNS: upstreamDNS,
	}
}

// UpdateUpstreamDNS updates the upstream DNS servers (called when gateway is discovered)
func (s *Server) UpdateUpstreamDNS(upstreams []string) {
	s.upstreamDNS = upstreams
	log.Printf("[DNS] Updated upstream DNS servers: %v", upstreams)
}

// ListenAndServe starts the DNS server
func (s *Server) ListenAndServe(ctx context.Context) error {
	// Create DNS server
	s.dnsServer = &dns.Server{
		Addr:    s.addr,
		Net:     "udp",
		Handler: dns.HandlerFunc(s.handleDNSRequest),
	}

	log.Printf("[DNS] Listening on %s (UDP)", s.addr)

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		if err := s.dnsServer.ListenAndServe(); err != nil {
			errChan <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		log.Println("[DNS] Shutting down DNS server...")
		return s.dnsServer.Shutdown()
	case err := <-errChan:
		return fmt.Errorf("DNS server error: %v", err)
	}
}

// handleDNSRequest processes DNS requests
func (s *Server) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	// Create response message
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = false
	resp.RecursionAvailable = true

	// Only handle queries with exactly one question
	if len(req.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		w.WriteMsg(resp)
		return
	}

	question := req.Question[0]
	hostname := question.Name

	// Remove trailing dot from hostname
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}

	log.Printf("[DNS] Query: %s (type=%s)", hostname, dns.TypeToString[question.Qtype])

	// Try to resolve internally first (only for A and AAAA records)
	if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		if ip, found := s.resolver.Resolve(hostname); found {
			log.Printf("[DNS] Resolved internally: %s -> %s", hostname, ip)

			// Create A record response for IPv4
			if question.Qtype == dns.TypeA {
				rr := &dns.A{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60, // 60 second TTL
					},
					A: net.ParseIP(ip),
				}
				resp.Answer = append(resp.Answer, rr)
				resp.Authoritative = true
				w.WriteMsg(resp)
				return
			} else if question.Qtype == dns.TypeAAAA {
				// We only have IPv4 addresses, return authoritative NODATA (empty answer, not NXDOMAIN)
				// This tells the client "this name exists but has no AAAA record"
				resp.Authoritative = true
				w.WriteMsg(resp)
				return
			}
		}
	}

	// Not found internally or not an A/AAAA record - forward to upstream DNS
	log.Printf("[DNS] Forwarding to upstream DNS: %s", hostname)
	upstreamResp := s.forwardToUpstream(req)

	if upstreamResp != nil {
		upstreamResp.Id = req.Id // Match transaction ID
		w.WriteMsg(upstreamResp)
	} else {
		// Upstream failed, return SERVFAIL
		resp.Rcode = dns.RcodeServerFailure
		w.WriteMsg(resp)
	}
}

// forwardToUpstream forwards a DNS query to upstream DNS servers
func (s *Server) forwardToUpstream(req *dns.Msg) *dns.Msg {
	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	// Try each upstream server
	for _, upstream := range s.upstreamDNS {
		resp, rtt, err := client.Exchange(req, upstream)
		if err != nil {
			log.Printf("[DNS] Failed to query upstream %s: %v", upstream, err)
			continue
		}

		if resp != nil {
			log.Printf("[DNS] ✓ Received response from %s (rtt=%v, answers=%d)", upstream, rtt, len(resp.Answer))
			return resp
		}
	}

	log.Printf("[DNS] All upstream DNS servers failed")
	return nil
}
