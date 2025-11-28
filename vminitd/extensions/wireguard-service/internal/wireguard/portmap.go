package wireguard

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"runtime"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// PortMapping represents a published port mapping
type PortMapping struct {
	Protocol      string // "tcp" or "udp"
	HostPort      uint32
	ContainerIP   string
	ContainerPort uint32
}

// PublishPort creates nftables rules to expose a container port on the vmnet interface
// This adds:
// 1. PREROUTING DNAT rule: vmnet_eth0:host_port → container_overlay_ip:container_port
// 2. INPUT ACCEPT rule: allow traffic to host_port on vmnet eth0
func PublishPort(protocol string, hostPort uint32, containerIP string, containerPort uint32) error {
	// Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Printf("Publishing port: %s %d → %s:%d", protocol, hostPort, containerIP, containerPort)

	// Connect to nftables
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}

	// Get or create the arca-wireguard table (AddTable is idempotent)
	table := conn.AddTable(&nftables.Table{
		Name:   "arca-wireguard",
		Family: nftables.TableFamilyIPv4,
	})

	// Create or get PREROUTING chain for DNAT (AddChain is idempotent)
	preroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "prerouting-portmap",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	// Create or get FORWARD chain for DNATed traffic (AddChain is idempotent)
	// Priority -1 runs BEFORE security rules (which use ChainPriorityFilter = 0)
	filterPriority := nftables.ChainPriorityFilter
	portmapPriority := *filterPriority - 1
	forwardChain := conn.AddChain(&nftables.Chain{
		Name:     "forward-portmap",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: &portmapPriority, // Higher priority than security rules
	})

	// Parse container IP
	containerIPAddr := net.ParseIP(containerIP)
	if containerIPAddr == nil {
		return fmt.Errorf("invalid container IP: %s", containerIP)
	}
	containerIPv4 := containerIPAddr.To4()
	if containerIPv4 == nil {
		return fmt.Errorf("container IP is not IPv4: %s", containerIP)
	}

	// Determine protocol number
	var protoNum byte
	if strings.ToLower(protocol) == "tcp" {
		protoNum = unix.IPPROTO_TCP
	} else if strings.ToLower(protocol) == "udp" {
		protoNum = unix.IPPROTO_UDP
	} else {
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	// RULE 1: PREROUTING DNAT rule (vmnet eth0 → container overlay IP)
	// Match: iifname eth0, protocol, dport host_port
	// Action: DNAT to container_ip:container_port
	log.Printf("Adding PREROUTING DNAT rule: %s dport %d → %s:%d", protocol, hostPort, containerIP, containerPort)

	hostPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(hostPortBytes, uint16(hostPort))

	containerPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(containerPortBytes, uint16(containerPort))

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: preroutingChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoNum},
			},
			// Match destination port
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     hostPortBytes,
			},
			// Counter (for debugging - shows packets hitting DNAT rule)
			&expr.Counter{},
			// DNAT: Immediate load container IP and port into registers
			&expr.Immediate{
				Register: 1,
				Data:     containerIPv4,
			},
			&expr.Immediate{
				Register: 2,
				Data:     containerPortBytes,
			},
			// NAT: DNAT to container_ip:container_port
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      uint32(nftables.TableFamilyIPv4),
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	})

	// RULE 2a: INPUT ACCEPT rule (allow NEW connections to published port)
	// This accepts the initial SYN packet from macOS to vmnet IP:host_port
	// Priority -1 runs BEFORE vmnet security DROP rule (priority 0)
	filterPriority2 := nftables.ChainPriorityFilter
	inputPortmapPriority := *filterPriority2 - 1
	inputChain := conn.AddChain(&nftables.Chain{
		Name:     "input-portmap",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &inputPortmapPriority, // Priority -1, runs before security DROP
	})

	log.Printf("Adding INPUT ACCEPT rule: %s dport %d", protocol, hostPort)

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoNum},
			},
			// Match destination port (pre-DNAT = host port)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     hostPortBytes,
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// RULE 2b: FORWARD ACCEPT rule (allow DNATed traffic to container)
	// After DNAT, packets are forwarded to overlay IP, not local INPUT
	// Match: protocol, dest IP = container_ip, dport = container_port
	// Action: ACCEPT
	log.Printf("Adding FORWARD ACCEPT rule: %s dip %s dport %d (post-DNAT)", protocol, containerIP, containerPort)

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			// Match protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoNum},
			},
			// Match destination IP (post-DNAT = container IP)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // IPv4 destination address offset
				Len:          4,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     containerIPv4,
			},
			// Match destination port (post-DNAT = container port)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     containerPortBytes,
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// RULE 2c: FORWARD ACCEPT rule for RETURN traffic (container → vmnet)
	// This accepts return packets from the container back to the proxy
	// Match: protocol, source IP = container_ip, sport = container_port
	// Action: ACCEPT (prevents forward-security from dropping return traffic)
	log.Printf("Adding FORWARD ACCEPT rule for return traffic: %s sip %s sport %d", protocol, containerIP, containerPort)

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			// Match protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoNum},
			},
			// Match SOURCE IP (return traffic = container IP)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // IPv4 SOURCE address offset
				Len:          4,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     containerIPv4,
			},
			// Match SOURCE port (return traffic = container port)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0, // Source port offset
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     containerPortBytes,
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// RULE 3: POSTROUTING MASQUERADE rule for port-mapped connections
	// This ensures conntrack properly tracks the connection so reverse DNAT works
	// Match: protocol, ct status dnat, dport = container_port
	// Action: MASQUERADE (source becomes gateway IP, e.g., 172.17.0.1)
	log.Printf("Adding POSTROUTING MASQUERADE rule: %s dport %d → gateway IP", protocol, containerPort)

	// Use higher priority (lower number) than postrouting-nat (100) to ensure
	// port-mapped traffic is MASQUERADED before the general overlay MASQUERADE rule.
	// This prevents priority conflicts that can break conntrack.
	portmapPostPriority := *nftables.ChainPriorityNATSource - 50 // Priority 50
	postroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting-portmap",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: &portmapPostPriority,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: postroutingChain,
		Exprs: []expr.Any{
			// Match protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{protoNum},
			},
			// Match ct status: DNAT (only MASQUERADE port-mapped connections)
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATUS,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x00, 0x00, 0x00, 0x08}, // DNAT bit
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Match destination port (to ensure we only MASQUERADE traffic for this port mapping)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     containerPortBytes,
			},
			// Counter (for debugging)
			&expr.Counter{},
			// MASQUERADE: Rewrite source to outgoing interface IP (gateway)
			&expr.Masq{},
		},
	})

	// RULE 4: Ensure jump to forward-security exists as fallback (added only once)
	// This jump rule is executed only if no port mapping rules match
	// It allows forward-security to drop traffic from overlay to control plane
	if err := ensureForwardSecurityJump(conn, table, forwardChain); err != nil {
		return fmt.Errorf("failed to add forward-security jump: %w", err)
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables rules: %w", err)
	}

	log.Printf("✓ Port published successfully: %s %d → %s:%d", protocol, hostPort, containerIP, containerPort)
	return nil
}

// UnpublishPort removes nftables rules for a published port
// Removes both PREROUTING DNAT and INPUT ACCEPT rules
func UnpublishPort(protocol string, hostPort uint32) error {
	// Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Printf("Unpublishing port: %s %d", protocol, hostPort)

	// Connect to nftables
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}

	// Get or create the arca-wireguard table (AddTable is idempotent)
	table := conn.AddTable(&nftables.Table{
		Name:   "arca-wireguard",
		Family: nftables.TableFamilyIPv4,
	})

	// Determine protocol number
	var protoNum byte
	if strings.ToLower(protocol) == "tcp" {
		protoNum = unix.IPPROTO_TCP
	} else if strings.ToLower(protocol) == "udp" {
		protoNum = unix.IPPROTO_UDP
	} else {
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	hostPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(hostPortBytes, uint16(hostPort))

	// Get or create PREROUTING chain (AddChain is idempotent)
	preroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "prerouting-portmap",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	// Find and delete matching rules in PREROUTING chain
	rules, err := conn.GetRules(table, preroutingChain)
	if err != nil {
		log.Printf("Warning: failed to get PREROUTING rules (chain may not exist): %v", err)
	} else {
		for _, rule := range rules {
			// Check if this rule matches our protocol and port
			if ruleMatchesPortMapping(rule, protoNum, hostPortBytes) {
				log.Printf("Deleting PREROUTING rule for %s:%d", protocol, hostPort)
				if err := conn.DelRule(rule); err != nil {
					log.Printf("Warning: failed to delete PREROUTING rule: %v", err)
				}
			}
		}
	}

	// Get or create FORWARD chain (AddChain is idempotent)
	// Priority -1 runs BEFORE security rules (which use ChainPriorityFilter = 0)
	filterPriority := nftables.ChainPriorityFilter
	portmapPriority := *filterPriority - 1
	forwardChain := conn.AddChain(&nftables.Chain{
		Name:     "forward-portmap",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: &portmapPriority, // Higher priority than security rules
	})

	// Find and delete matching rules in FORWARD chain
	rules, err = conn.GetRules(table, forwardChain)
	if err != nil {
		log.Printf("Warning: failed to get FORWARD rules (chain may not exist): %v", err)
	} else {
		for _, rule := range rules {
			// Check if this rule matches our protocol and port
			if ruleMatchesPortMapping(rule, protoNum, hostPortBytes) {
				log.Printf("Deleting FORWARD rule for %s:%d", protocol, hostPort)
				if err := conn.DelRule(rule); err != nil {
					log.Printf("Warning: failed to delete FORWARD rule: %v", err)
				}
			}
		}
	}

	// Get or create POSTROUTING chain (AddChain is idempotent)
	// Must use same priority as PublishPort (priority 50)
	portmapPostPriority := *nftables.ChainPriorityNATSource - 50
	postroutingChain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting-portmap",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: &portmapPostPriority,
	})

	// Find and delete matching rules in POSTROUTING chain
	rules, err = conn.GetRules(table, postroutingChain)
	if err != nil {
		log.Printf("Warning: failed to get POSTROUTING rules (chain may not exist): %v", err)
	} else {
		for _, rule := range rules {
			// Check if this rule matches our protocol and port
			if ruleMatchesPortMapping(rule, protoNum, hostPortBytes) {
				log.Printf("Deleting POSTROUTING rule for %s:%d", protocol, hostPort)
				if err := conn.DelRule(rule); err != nil {
					log.Printf("Warning: failed to delete POSTROUTING rule: %v", err)
				}
			}
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables rules: %w", err)
	}

	log.Printf("✓ Port unpublished successfully: %s %d", protocol, hostPort)
	return nil
}

// ensureForwardSecurityJump ensures a jump rule to forward-security exists
// This is added to forward-portmap as a fallback - if no port mapping rules match,
// jump to forward-security to apply security filtering (drop overlay→control traffic)
func ensureForwardSecurityJump(conn *nftables.Conn, table *nftables.Table, forwardChain *nftables.Chain) error {
	// Check if jump rule already exists
	rules, err := conn.GetRules(table, forwardChain)
	if err != nil {
		return fmt.Errorf("failed to get forward-portmap rules: %w", err)
	}

	// Look for existing jump to forward-security
	for _, rule := range rules {
		for _, e := range rule.Exprs {
			if verdict, ok := e.(*expr.Verdict); ok {
				if verdict.Kind == expr.VerdictJump && verdict.Chain == "forward-security" {
					// Jump rule already exists
					log.Printf("Jump to forward-security already exists in forward-portmap")
					return nil
				}
			}
		}
	}

	// Jump rule doesn't exist, add it
	log.Printf("Adding jump rule: forward-portmap → forward-security (fallback)")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			// No match conditions - this is a fallback that always executes
			// Jump to forward-security chain for security filtering
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: "forward-security",
			},
		},
	})

	return nil
}

// ruleMatchesPortMapping checks if an nftables rule matches a given protocol and port
func ruleMatchesPortMapping(rule *nftables.Rule, protoNum byte, portBytes []byte) bool {
	matchesProto := false
	matchesPort := false

	for i, e := range rule.Exprs {
		// Check for protocol match
		if cmp, ok := e.(*expr.Cmp); ok {
			if len(cmp.Data) == 1 && cmp.Data[0] == protoNum {
				matchesProto = true
			}
		}

		// Check for port match
		if cmp, ok := e.(*expr.Cmp); ok {
			if len(cmp.Data) == 2 && cmp.Data[0] == portBytes[0] && cmp.Data[1] == portBytes[1] {
				// Verify previous expression is a transport header payload (offset 2 = dport)
				if i > 0 {
					if payload, ok := rule.Exprs[i-1].(*expr.Payload); ok {
						if payload.Base == expr.PayloadBaseTransportHeader && payload.Offset == 2 {
							matchesPort = true
						}
					}
				}
			}
		}
	}

	return matchesProto && matchesPort
}

// ConfigureDefaultVmnetSecurity sets up default INPUT rules to block all vmnet traffic except WireGuard
// This secures the vmnet interface as WireGuard underlay only
func ConfigureDefaultVmnetSecurity() error {
	// Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Printf("Configuring default vmnet security (block all except WireGuard UDP)")

	// CRITICAL: Enable IP forwarding FIRST
	// This must be done BEFORE any nftables rules for forwarding to work
	forwardingPath := "/proc/sys/net/ipv4/ip_forward"
	if err := ioutil.WriteFile(forwardingPath, []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}
	log.Printf("✓ IP forwarding enabled in root namespace")

	// Connect to nftables
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to connect to nftables: %w", err)
	}

	// Get or create the arca-wireguard table (AddTable is idempotent)
	table := conn.AddTable(&nftables.Table{
		Name:   "arca-wireguard",
		Family: nftables.TableFamilyIPv4,
	})

	// CRITICAL: Create PREROUTING chain to enable conntrack for ALL packets
	// This ensures conntrack is enabled for forwarded packets (port mapping)
	// Without this, ct status dnat bit isn't set and MASQUERADE rule doesn't match
	// Priority -150 runs BEFORE all other PREROUTING chains
	preroutingConntrackPriority := *nftables.ChainPriorityNATDest - 50
	preroutingConntrackChain := conn.AddChain(&nftables.Chain{
		Name:     "prerouting-conntrack",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: &preroutingConntrackPriority, // Priority -150
	})

	// RULE: Touch ct state for all packets to enable conntrack
	log.Printf("Adding PREROUTING rule: Touch ct state to enable conntrack for all packets")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: preroutingConntrackChain,
		Exprs: []expr.Any{
			// Touch ct state to enable conntrack (this is critical!)
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// Create INPUT security chain
	// Priority 0 runs AFTER portmap rules (which use priority -1)
	// This ensures published ports are accepted before the security DROP rule
	inputChain := conn.AddChain(&nftables.Chain{
		Name:     "input-vmnet-security",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter, // Lower priority than portmap rules
	})

	// RULE 1: ACCEPT DNS responses from vmnet gateway (for embedded DNS server)
	// CRITICAL: Must come BEFORE established/related rule to ensure DNS responses are accepted
	// The DNS server in root namespace queries the vmnet gateway, responses come from src_port=53
	log.Printf("Adding INPUT rule: ACCEPT UDP from vmnet gateway port 53 (DNS responses)")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match protocol: UDP
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			// Match source port: 53 (DNS responses)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       0, // Source port offset in UDP header
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0, 53}, // Port 53 in big-endian
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// RULE 2: ACCEPT established and related connections
	log.Printf("Adding INPUT rule: ACCEPT established,related connections on eth0")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match connection state: established or related
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x00, 0x00, 0x00, 0x06}, // ESTABLISHED | RELATED
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// RULE 3: ACCEPT WireGuard UDP traffic (port 51820 and higher)
	// We use a range check: dport >= 51820
	log.Printf("Adding INPUT rule: ACCEPT UDP port 51820+ on eth0 (WireGuard underlay)")

	minPort := uint16(51820)
	minPortBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(minPortBytes, minPort)

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Match protocol: UDP
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       9,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			// Match destination port >= 51820
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpGte,
				Register: 1,
				Data:     minPortBytes,
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// RULE 4: DROP all other traffic on eth0 (vmnet)
	log.Printf("Adding INPUT rule: DROP all other traffic on eth0 (vmnet secured as underlay)")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Counter (for debugging - shows what we're blocking)
			&expr.Counter{},
			// Verdict: DROP
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	// Create OUTPUT security chain to enable conntrack for outgoing packets
	// CRITICAL: This ensures connection tracking works for DNS queries from root namespace
	// Without this, DNS responses don't match "ct state established,related" and get dropped
	// Priority 0 runs after any port mapping rules (which would use negative priority)
	outputChain := conn.AddChain(&nftables.Chain{
		Name:     "output-vmnet-security",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter, // Priority 0
	})

	// RULE: ACCEPT all outgoing traffic on eth0 (but touch ct state to enable tracking)
	// This is critical for DNS queries and port mapping conntrack to work properly
	log.Printf("Adding OUTPUT rule: ACCEPT all traffic on eth0 (enables conntrack)")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: outputChain,
		Exprs: []expr.Any{
			// Match output interface: eth0 (vmnet)
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"),
			},
			// Touch ct state to enable conntrack (this is the key!)
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	// Create FORWARD security chain for port mapping return traffic
	// Priority -1 runs BEFORE control plane protection rules (which use priority 0)
	// This is CRITICAL: return traffic from containers to macOS must be accepted
	// before the control plane DROP rule (which blocks 172.16.0.0/12 → vmnet subnet)
	filterPriority := nftables.ChainPriorityFilter
	forwardSecurityPriority := *filterPriority - 1
	forwardChain := conn.AddChain(&nftables.Chain{
		Name:     "forward-vmnet-security",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: &forwardSecurityPriority, // Priority -1, same as portmap rules
	})

	// FORWARD RULE: ACCEPT established and related connections going TO control plane
	// This allows return traffic from containers back to macOS for port-mapped connections
	// Specifically: packets with dst in 192.168.0.0/16 (vmnet control plane)
	// This prevents containers from initiating connections to control plane while allowing
	// return traffic from port-mapped connections (SYN-ACK, data, etc.)
	log.Printf("Adding FORWARD rule: ACCEPT established,related → control plane (for port mapping return traffic)")

	// Parse control plane subnet (192.168.0.0/16)
	_, controlPlaneNet, err := net.ParseCIDR("192.168.0.0/16")
	if err != nil {
		return fmt.Errorf("failed to parse control plane subnet: %w", err)
	}

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			// Match connection state: established or related
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x00, 0x00, 0x00, 0x06}, // ESTABLISHED | RELATED
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Match destination IP: control plane subnet (192.168.0.0/16)
			// This ensures we only accept return traffic TO control plane, not FROM
			&expr.Payload{
				DestRegister: 2,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // Destination IP offset
				Len:          4,
			},
			&expr.Bitwise{
				SourceRegister: 2,
				DestRegister:   2,
				Len:            4,
				Mask:           controlPlaneNet.Mask, // /16 mask
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 2,
				Data:     controlPlaneNet.IP.To4(), // 192.168.0.0
			},
			// Counter (for debugging)
			&expr.Counter{},
			// Verdict: ACCEPT
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables rules: %w", err)
	}

	log.Printf("✓ Default vmnet security configured successfully")
	return nil
}

// DumpNftables returns the full nftables ruleset for debugging
// Includes all tables, chains, rules, and packet counters
func DumpNftables() (string, error) {
	// Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Printf("Dumping nftables ruleset for debugging")

	// Connect to nftables
	conn, err := nftables.New()
	if err != nil {
		return "", fmt.Errorf("failed to connect to nftables: %w", err)
	}

	// Get all tables
	tables, err := conn.ListTables()
	if err != nil {
		return "", fmt.Errorf("failed to list tables: %w", err)
	}

	var output strings.Builder
	output.WriteString("=== NFTABLES RULESET DUMP ===\n\n")

	// Iterate through each table and dump its contents
	for _, table := range tables {
		familyName := fmt.Sprintf("family_%d", table.Family)
		if table.Family == nftables.TableFamilyIPv4 {
			familyName = "ip"
		}

		output.WriteString(fmt.Sprintf("table %s %s {\n", familyName, table.Name))

		// Get chains for this table
		chains, err := conn.ListChains()
		if err != nil {
			return "", fmt.Errorf("failed to list chains: %w", err)
		}

		// Filter chains for this table
		for _, chain := range chains {
			if chain.Table.Name != table.Name || chain.Table.Family != table.Family {
				continue
			}

			// Format chain header
			output.WriteString(fmt.Sprintf("  chain %s {\n", chain.Name))

			// Format chain type/hook/priority if this is a base chain
			if chain.Hooknum != nil {
				hookNum := *chain.Hooknum
				priority := int32(0)
				if chain.Priority != nil {
					priority = int32(*chain.Priority)
				}

				output.WriteString(fmt.Sprintf("    type=%s hook=%d priority=%d;\n",
					chain.Type, hookNum, priority))
			}

			// Get rules for this chain
			rules, err := conn.GetRules(table, chain)
			if err != nil {
				return "", fmt.Errorf("failed to get rules for chain %s: %w", chain.Name, err)
			}

			// Format each rule with packet counters
			for i, rule := range rules {
				output.WriteString(fmt.Sprintf("    rule %d: ", i))

				// Extract key information from expressions
				hasCounter := false
				var counterPackets, counterBytes uint64
				hasVerdict := false
				var verdictKind int32
				var verdictChain string

				for _, e := range rule.Exprs {
					switch expr := e.(type) {
					case *expr.Counter:
						hasCounter = true
						counterPackets = expr.Packets
						counterBytes = expr.Bytes
					case *expr.Verdict:
						hasVerdict = true
						verdictKind = int32(expr.Kind)
						verdictChain = expr.Chain
					case *expr.Meta:
						output.WriteString(fmt.Sprintf("meta(key=%d) ", expr.Key))
					case *expr.Cmp:
						output.WriteString(fmt.Sprintf("cmp(op=%d) ", expr.Op))
					case *expr.Payload:
						output.WriteString(fmt.Sprintf("payload(base=%d,off=%d,len=%d) ", expr.Base, expr.Offset, expr.Len))
					case *expr.NAT:
						output.WriteString(fmt.Sprintf("nat(type=%d) ", expr.Type))
					case *expr.Masq:
						output.WriteString("MASQUERADE ")
					case *expr.Ct:
						output.WriteString(fmt.Sprintf("ct(key=%d) ", expr.Key))
					case *expr.Bitwise:
						output.WriteString("bitwise ")
					case *expr.Immediate:
						// Show first few bytes of immediate data
						dataStr := fmt.Sprintf("%v", expr.Data)
						if len(dataStr) > 20 {
							dataStr = dataStr[:20] + "..."
						}
						output.WriteString(fmt.Sprintf("imm(%s) ", dataStr))
					}
				}

				// Show counter FIRST (most important for debugging)
				if hasCounter {
					output.WriteString(fmt.Sprintf("→ COUNTER: %d pkts, %d bytes ", counterPackets, counterBytes))
				}

				// Show verdict
				if hasVerdict {
					verdictName := "unknown"
					switch verdictKind {
					case -1:
						verdictName = "ACCEPT"
					case 0:
						verdictName = "DROP"
					case 1:
						verdictName = "QUEUE"
					case 2:
						verdictName = "CONTINUE"
					case 3:
						verdictName = "BREAK"
					case 4:
						verdictName = "JUMP"
					case 5:
						verdictName = "GOTO"
					default:
						verdictName = fmt.Sprintf("verdict_%d", verdictKind)
					}
					// For jump/goto, include the chain name
					if (verdictKind == 4 || verdictKind == 5) && verdictChain != "" {
						output.WriteString(fmt.Sprintf("→ %s %s", verdictName, verdictChain))
					} else {
						output.WriteString(fmt.Sprintf("→ %s", verdictName))
					}
				}

				output.WriteString("\n")
			}

			output.WriteString("  }\n")
		}

		output.WriteString("}\n\n")
	}

	output.WriteString("=== END NFTABLES DUMP ===\n")
	return output.String(), nil
}
