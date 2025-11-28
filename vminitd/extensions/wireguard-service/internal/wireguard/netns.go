// Network namespace utilities for WireGuard container networking
//
// This file provides utilities for managing network namespaces to implement
// the WireGuard namespace architecture where:
// - eth0 (vmnet) stays in root namespace for internet access
// - wg0 is created in ROOT namespace (same as eth0) for UDP socket access
// - veth pair connects root namespace to container namespace
// - veth-cont is RENAMED to eth0 in container namespace (clean abstraction)
//
// Architecture:
//   Root Namespace (vminitd):                    Container Namespace (OCI):
//   eth0 (vmnet) ←→ wg0 ←→ veth-root       eth0 (renamed veth-cont, has WireGuard IP)
//
// Why wg0 must be in root namespace:
//   - WireGuard encrypted packets arrive on vmnet eth0 (UDP port 51820)
//   - WireGuard's UDP socket is created in the same namespace as wg0
//   - If wg0 is in container namespace, packets on eth0 can't reach it
//   - Solution: wg0 in root namespace receives packets from eth0
//
// Why veth-cont is renamed to eth0:
//   - Container sees a normal eth0 interface (clean abstraction)
//   - WireGuard implementation details hidden from container
//   - Matches user expectations from Docker

package wireguard

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// findContainerNetNs finds the network namespace of the OCI container and extracts container ID
// Apple's Containerization framework creates containers in separate network namespaces.
// Since each VM has exactly ONE container, we find it by comparing namespace inodes.
// Returns (netnsPath, containerID, error)
func findContainerNetNs() (string, string, error) {
	log.Printf("Searching for container network namespace...")

	// Get our own (vminitd/WireGuard service) network namespace handle
	ownNs, err := netns.Get()
	if err != nil {
		return "", "", fmt.Errorf("failed to get own network namespace: %w", err)
	}
	defer ownNs.Close()

	// Read our own namespace to get the inode for comparison
	ownNsPath := "/proc/self/ns/net"
	ownNsLink, err := os.Readlink(ownNsPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read own namespace link: %w", err)
	}
	log.Printf("vminitd network namespace: %s", ownNsLink)

	// Scan /proc for processes
	procDir, err := os.Open("/proc")
	if err != nil {
		return "", "", fmt.Errorf("failed to open /proc: %w", err)
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return "", "", fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		// Skip non-numeric entries (not PIDs)
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		// Skip low PIDs (vminitd, WireGuard service, and other boot services)
		if pid <= 100 {
			continue
		}

		// Read this process's network namespace
		netnsPath := filepath.Join("/proc", entry, "ns", "net")
		processNsLink, err := os.Readlink(netnsPath)
		if err != nil {
			continue
		}

		// Compare namespace inodes - different means it's the container!
		if processNsLink != ownNsLink {
			log.Printf("Found container network namespace: pid=%d ns=%s path=%s", pid, processNsLink, netnsPath)

			// Extract container ID from process environment
			containerID := ""
			environPath := filepath.Join("/proc", entry, "environ")
			if environData, err := ioutil.ReadFile(environPath); err == nil {
				// environ is null-separated key=value pairs
				for _, env := range bytes.Split(environData, []byte{0}) {
					if bytes.HasPrefix(env, []byte("ARCA_CONTAINER_ID=")) {
						containerID = string(bytes.TrimPrefix(env, []byte("ARCA_CONTAINER_ID=")))
						break
					}
				}
			}

			if containerID != "" {
				log.Printf("Found container ID from environment: %s", containerID)
			}

			return netnsPath, containerID, nil
		}
	}

	return "", "", fmt.Errorf("container network namespace not found (no process in different network namespace)")
}

// createVethPair creates a veth pair in the root namespace
// veth-root stays in root namespace, veth-cont will be moved to container namespace
func createVethPair() error {
	log.Printf("Creating veth pair: veth-root <-> veth-cont")

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "veth-root",
		},
		PeerName: "veth-cont",
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}

	log.Printf("Veth pair created successfully")
	return nil
}

// moveInterfaceToNetNs moves a network interface to a different network namespace
func moveInterfaceToNetNs(linkName string, netnsPath string) error {
	log.Printf("Moving interface %s to namespace %s", linkName, netnsPath)

	// Get the link
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", linkName, err)
	}

	// Open the namespace file
	fd, err := unix.Open(netnsPath, unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open namespace %s: %w", netnsPath, err)
	}
	defer unix.Close(fd)

	// Move the link to the namespace
	if err := netlink.LinkSetNsFd(link, fd); err != nil {
		return fmt.Errorf("failed to move link to namespace: %w", err)
	}

	log.Printf("Interface %s moved to namespace successfully", linkName)
	return nil
}

// configureVethRootWithIP assigns the gateway IP to veth-root and adds a route for the container's overlay IP
// veth-root gets the overlay network's gateway IP as /32 (e.g., 172.18.0.1/32) to avoid creating broad subnet routes.
// CRITICAL: Must use /32 to prevent kernel from creating a 172.18.0.0/16 connected route that would block
// WireGuard from auto-creating its /32 peer routes (e.g., 172.18.0.3/32 dev wg0).
// Containers use this as their default gateway, and the kernel routes peer traffic to wg0 via WireGuard's routes.
// Note: wg0 has a DIFFERENT IP (10.254.0.1) - WireGuard doesn't need to be in the overlay subnet!
func configureVethRootWithIP(ipAddress string, networkCIDR string) error {
	log.Printf("Configuring veth-root with gateway IP and route for container IP %s", ipAddress)

	// Get veth-root interface
	vethRoot, err := netlink.LinkByName("veth-root")
	if err != nil {
		return fmt.Errorf("failed to get veth-root: %w", err)
	}

	// Calculate gateway IP (first IP in network range: 172.18.0.1 for 172.18.0.0/16)
	_, ipNet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse network CIDR %s: %w", networkCIDR, err)
	}

	// Gateway is first usable IP in range (network address + 1)
	gatewayIP := make(net.IP, len(ipNet.IP))
	copy(gatewayIP, ipNet.IP)
	gatewayIP[len(gatewayIP)-1] |= 1 // Set last bit to get .1

	// CRITICAL FIX: Use /32 instead of /16 to prevent broad subnet route
	// This allows WireGuard to create its peer routes (172.18.0.x/32 dev wg0)
	gatewayAddr := fmt.Sprintf("%s/32", gatewayIP.String())
	addr, err := netlink.ParseAddr(gatewayAddr)
	if err != nil {
		return fmt.Errorf("failed to parse gateway IP %s: %w", gatewayAddr, err)
	}

	log.Printf("Assigning gateway IP %s to veth-root (using /32 to avoid subnet route conflict)", gatewayAddr)
	if err := netlink.AddrAdd(vethRoot, addr); err != nil {
		return fmt.Errorf("failed to assign gateway IP to veth-root: %w", err)
	}

	// Bring up veth-root
	if err := netlink.LinkSetUp(vethRoot); err != nil {
		return fmt.Errorf("failed to bring up veth-root: %w", err)
	}

	// Add route for container's overlay IP pointing to veth-root
	// This allows the root namespace to reach the local container
	_, containerIPNet, err := net.ParseCIDR(fmt.Sprintf("%s/32", ipAddress))
	if err != nil {
		return fmt.Errorf("failed to parse container IP %s: %w", ipAddress, err)
	}

	route := &netlink.Route{
		LinkIndex: vethRoot.Attrs().Index,
		Dst:       containerIPNet,
	}

	log.Printf("Adding route: %s/32 dev veth-root", ipAddress)
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route for container IP: %w", err)
	}

	// Enable IP forwarding in root namespace (critical for routing between interfaces)
	forwardingPath := "/proc/sys/net/ipv4/ip_forward"
	if err := ioutil.WriteFile(forwardingPath, []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	log.Printf("veth-root configured successfully: gateway=%s, route=%s/32 dev veth-root", gatewayAddr, ipAddress)
	return nil
}

// ConfigureNATForInternet configures NAT/masquerading for internet access
// This allows container traffic to reach the internet via eth0 (vmnet)
// SECURITY: Blocks access to control plane vmnet network (192.168.64.0/16)
// Uses nftables via netlink (no userspace binaries required)
// CRITICAL: Must run in ROOT namespace where both veth-root0 and vmnet eth0 exist
func ConfigureNATForInternet() error {
	// CRITICAL: Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Printf("Configuring NAT for internet access via eth0")

	// Get eth0 interface (vmnet) to detect control plane subnet
	eth0, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("failed to get eth0 interface: %w", err)
	}

	// Get eth0's IP address to determine control plane subnet
	addrs, err := netlink.AddrList(eth0, unix.AF_INET)
	if err != nil || len(addrs) == 0 {
		log.Printf("Warning: Could not determine eth0 IP, assuming 192.168.64.0/24 for control plane")
	}

	// vmnet typically uses 192.168.64.0/24 or similar
	// We use the actual subnet from eth0's address to avoid blocking unrelated RFC1918 ranges
	// (e.g., user's LAN at 192.168.2.0/24 should NOT be blocked)
	controlPlaneSubnet := "192.168.64.0/24"
	if len(addrs) > 0 {
		// Use the actual subnet from eth0's address (includes proper mask)
		addr := addrs[0]
		// Get the network address by masking the IP with the subnet mask
		network := addr.IPNet.IP.Mask(addr.IPNet.Mask)
		ones, _ := addr.IPNet.Mask.Size()
		controlPlaneSubnet = fmt.Sprintf("%s/%d", network.String(), ones)
		log.Printf("Detected control plane subnet from eth0: %s (from %s)", controlPlaneSubnet, addr.IPNet.String())
	}

	// Parse subnets
	_, containerNet, err := net.ParseCIDR("172.16.0.0/12") // Container overlay networks
	if err != nil {
		return fmt.Errorf("failed to parse container subnet: %w", err)
	}

	_, controlNet, err := net.ParseCIDR(controlPlaneSubnet)
	if err != nil {
		return fmt.Errorf("failed to parse control plane subnet: %w", err)
	}

	// Create nftables connection (talks directly to kernel via netlink)
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("failed to create nftables connection: %w", err)
	}

	// Create or get "arca-wireguard" table for IPv4
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "arca-wireguard",
	})

	// SECURITY RULE 1: Create FORWARD chain to block control plane access
	// NOTE: This is now a REGULAR chain (not a base chain), so it's only executed
	// when jumped to from forward-portmap. This ensures port mapping rules are
	// checked BEFORE security rules, fixing the issue where both base chains
	// would process packets and the DROP rule would execute even after ACCEPT.
	forwardChain := conn.AddChain(&nftables.Chain{
		Name:  "forward-security",
		Table: table,
		// No Type, Hooknum, or Priority - this is a regular chain, not a base chain
	})

	// Rule: DROP packets from container networks to control plane
	// Match: source = 172.16.0.0/12 AND destination = control plane subnet
	log.Printf("Adding FORWARD rule: DROP 172.16.0.0/12 -> %s (control plane protection)", controlPlaneSubnet)
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: forwardChain,
		Exprs: []expr.Any{
			// Match source IP: 172.16.0.0/12
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12, // Source IP offset in IPv4 header
				Len:          4,  // IPv4 address length
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           containerNet.Mask, // /12 mask
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     containerNet.IP.To4(), // 172.16.0.0
			},
			// Match destination IP: control plane subnet
			&expr.Payload{
				DestRegister: 2,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // Destination IP offset in IPv4 header
				Len:          4,
			},
			&expr.Bitwise{
				SourceRegister: 2,
				DestRegister:   2,
				Len:            4,
				Mask:           controlNet.Mask, // /16 mask
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 2,
				Data:     controlNet.IP.To4(),
			},
			// Counter (for debugging - shows what we're dropping)
			&expr.Counter{},
			// Verdict: DROP
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	// SECURITY RULE 2: Create INPUT chain to block DNS from control plane
	inputChain := conn.AddChain(&nftables.Chain{
		Name:     "input-security",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	// Rule: DROP DNS queries (port 53) arriving on eth0 (control plane)
	// This blocks host access to DNS while allowing container access via veth
	log.Printf("Adding INPUT rule: DROP port 53 from eth0 (block host DNS access)")
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Match input interface: eth0 (control plane)
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"), // Null-terminated interface name
			},
			// Match protocol: UDP (17)
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
			// Match destination port: 53 (DNS)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0, 53}, // Port 53 in big-endian
			},
			// Verdict: DROP
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	// NAT RULE: Create POSTROUTING chain for masquerading
	postRoutingChain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting-nat",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// Rule: MASQUERADE traffic going out eth0 (except control plane subnet)
	// Control plane is the vmnet subnet (e.g., 192.168.64.0/16) - we must NOT masquerade traffic to it
	// (DNS queries to gateway, etc.) or responses can't find their way back
	// NOTE: We use the dynamically-detected controlNet, not a hardcoded 192.168.0.0/16,
	// so that traffic to other RFC1918 networks (e.g., user's LAN at 192.168.2.0/24) is still masqueraded
	log.Printf("Adding POSTROUTING rule: MASQUERADE on eth0 for internet access (excluding %s)", controlPlaneSubnet)
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: postRoutingChain,
		Exprs: []expr.Any{
			// Match output interface: eth0
			&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("eth0\x00"), // Null-terminated interface name
			},
			// Load destination IP address into register 1
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // IPv4 destination address offset
				Len:          4,  // 4 bytes for IPv4 address
			},
			// Apply netmask from detected control plane subnet to get network portion
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           controlNet.Mask, // Use detected mask (typically /16)
				Xor:            []byte{0x00, 0x00, 0x00, 0x00},
			},
			// Check destination network != control plane subnet (e.g., 192.168.64.0/16)
			// If destination IS in control plane, rule doesn't match, no MASQUERADE
			// Traffic to other RFC1918 networks (user's LAN, etc.) will be masqueraded
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     controlNet.IP.To4(), // Detected control plane network (e.g., 192.168.64.0)
			},
			// Verdict: MASQUERADE (only if destination is NOT control plane)
			&expr.Masq{},
		},
	})

	// Apply all rules to kernel
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to apply nftables rules: %w", err)
	}

	log.Printf("✓ NAT configuration complete: internet access enabled, control plane blocked")
	log.Printf("  - Created nftables table: arca-wireguard (family ipv4)")
	log.Printf("  - INPUT chain: DROP port 53 from eth0 (block host DNS access)")
	log.Printf("  - FORWARD chain: DROP 172.16.0.0/12 → %s", controlPlaneSubnet)
	log.Printf("  - POSTROUTING chain: MASQUERADE on eth0")

	return nil
}

// SetupDefaultRoute adds a default route in the root namespace for internet access
// Called when the first network is added (after eth0 has an IP address)
// The DNS server needs this route to reach upstream DNS via vmnet gateway
// Returns the gateway IP address for DNS server configuration
func SetupDefaultRoute() (string, error) {
	// CRITICAL: Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Printf("Setting up default route in root namespace via eth0")

	// Get eth0 interface (vmnet)
	eth0, err := netlink.LinkByName("eth0")
	if err != nil {
		return "", fmt.Errorf("failed to get eth0 interface: %w", err)
	}

	// Get eth0's IP addresses to determine gateway
	addrs, err := netlink.AddrList(eth0, unix.AF_INET)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("could not determine eth0 IP for gateway: %w", err)
	}

	// Extract gateway IP (first IP in subnet, e.g., 192.168.64.0/24 → 192.168.64.1)
	ip := addrs[0].IP
	mask := addrs[0].Mask

	// Calculate network address
	network := ip.Mask(mask)

	// Gateway is typically network + 1 (e.g., 192.168.64.0 + 1 = 192.168.64.1)
	gateway := make(net.IP, len(network))
	copy(gateway, network)
	gateway[len(gateway)-1] += 1

	log.Printf("Detected vmnet gateway from eth0 subnet: %s", gateway.String())

	// Check if default route already exists (avoid duplicate route error)
	// Use nil to get ALL routes, not just eth0's routes (default route is global)
	routes, err := netlink.RouteList(nil, unix.AF_INET)
	if err != nil {
		return "", fmt.Errorf("failed to list routes: %w", err)
	}

	for _, route := range routes {
		// Default route has Dst == nil (0.0.0.0/0)
		if route.Dst == nil {
			log.Printf("Default route already exists via %s, skipping", route.Gw.String())
			return gateway.String(), nil // Return discovered gateway
		}
	}

	// Add default route via vmnet gateway
	defaultRoute := &netlink.Route{
		Dst:       nil, // nil means default route (0.0.0.0/0)
		Gw:        gateway,
		LinkIndex: eth0.Attrs().Index,
	}

	log.Printf("Adding default route: 0.0.0.0/0 via %s dev eth0", gateway.String())
	if err := netlink.RouteAdd(defaultRoute); err != nil {
		// Even if adding fails, return the gateway so DNS can be updated
		log.Printf("Warning: failed to add default route: %v (returning gateway anyway)", err)
		return gateway.String(), nil
	}

	log.Printf("✓ Default route added in root namespace (DNS can now reach upstream via vmnet gateway)")
	return gateway.String(), nil
}

// ============================================================================
// GENERALIZED HELPER FUNCTIONS FOR MULTI-NETWORK SUPPORT
// These functions accept interface names as parameters to support wg0, wg1, wg2, etc.
// ============================================================================

// createVethPairWithNames creates a veth pair with specified names
func createVethPairWithNames(rootName, contName string) error {
	log.Printf("Creating veth pair: %s <-> %s", rootName, contName)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: rootName,
		},
		PeerName: contName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}

	log.Printf("Veth pair created successfully: %s <-> %s", rootName, contName)
	return nil
}

// createWgInterfaceInRootNs creates a WireGuard interface with the specified name in root namespace
func createWgInterfaceInRootNs(ifName, privateKey string, listenPort uint32) error {
	log.Printf("Creating %s in root namespace with listen_port=%d", ifName, listenPort)

	// CRITICAL: Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Parse WireGuard configuration
	privKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	port := int(listenPort)
	config := wgtypes.Config{
		PrivateKey: &privKey,
		ListenPort: &port,
	}

	// Create WireGuard interface in root namespace
	log.Printf("Creating %s interface in root namespace", ifName)
	wg := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName,
		},
	}

	if err := netlink.LinkAdd(wg); err != nil {
		return fmt.Errorf("failed to create %s interface: %w", ifName, err)
	}

	// Create wgctrl client in root namespace
	client, err := wgctrl.New()
	if err != nil {
		netlink.LinkDel(wg)
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Configure WireGuard device
	log.Printf("Configuring %s with private key and listen port %d", ifName, listenPort)
	if err := client.ConfigureDevice(ifName, config); err != nil {
		netlink.LinkDel(wg)
		return fmt.Errorf("failed to configure %s: %w", ifName, err)
	}

	// Assign endpoint IP to interface
	// Use unique IPs for each interface: wg0=10.254.0.1, wg1=10.254.0.2, wg2=10.254.0.3, etc.
	// Extract index from interface name (wg0 -> 0, wg1 -> 1, etc.)
	var ifIndex int
	if _, err := fmt.Sscanf(ifName, "wg%d", &ifIndex); err != nil {
		ifIndex = 0 // Default to 0 if parsing fails
	}
	endpointIP := fmt.Sprintf("10.254.0.%d/32", ifIndex+1)

	addr, err := netlink.ParseAddr(endpointIP)
	if err != nil {
		netlink.LinkDel(wg)
		return fmt.Errorf("failed to parse endpoint IP %s: %w", endpointIP, err)
	}

	log.Printf("Assigning endpoint IP %s to %s", endpointIP, ifName)
	if err := netlink.AddrAdd(wg, addr); err != nil {
		netlink.LinkDel(wg)
		return fmt.Errorf("failed to assign endpoint IP to %s: %w", ifName, err)
	}

	// Bring interface up
	log.Printf("Bringing %s up", ifName)
	if err := netlink.LinkSetUp(wg); err != nil {
		netlink.LinkDel(wg)
		return fmt.Errorf("failed to bring %s up: %w", ifName, err)
	}

	log.Printf("%s created successfully in root namespace with endpoint IP %s", ifName, endpointIP)
	return nil
}

// configureVethRootWithGateway configures a veth root interface with gateway IP
func configureVethRootWithGateway(vethName, gateway, networkCIDR, containerIP string, networkIndex uint32) error {
	log.Printf("Configuring %s with gateway IP %s", vethName, gateway)

	// Get veth interface
	vethRoot, err := netlink.LinkByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to get %s: %w", vethName, err)
	}

	// CRITICAL: Use /32 to prevent broad subnet route
	// This allows WireGuard to create its peer routes
	gatewayAddr := fmt.Sprintf("%s/32", gateway)
	addr, err := netlink.ParseAddr(gatewayAddr)
	if err != nil {
		return fmt.Errorf("failed to parse gateway IP %s: %w", gatewayAddr, err)
	}

	log.Printf("Assigning gateway IP %s to %s (using /32 to avoid subnet route conflict)", gatewayAddr, vethName)
	if err := netlink.AddrAdd(vethRoot, addr); err != nil {
		return fmt.Errorf("failed to assign gateway IP to %s: %w", vethName, err)
	}

	// Bring up interface
	if err := netlink.LinkSetUp(vethRoot); err != nil {
		return fmt.Errorf("failed to bring up %s: %w", vethName, err)
	}

	// CRITICAL: Add route for container's IP pointing to this veth interface
	// This allows the root namespace to reach the container for inbound traffic (e.g., ping replies)
	// Without this route, packets destined for the container get dropped
	_, containerIPNet, err := net.ParseCIDR(fmt.Sprintf("%s/32", containerIP))
	if err != nil {
		return fmt.Errorf("failed to parse container IP %s: %w", containerIP, err)
	}

	route := &netlink.Route{
		LinkIndex: vethRoot.Attrs().Index,
		Dst:       containerIPNet,
	}

	log.Printf("Adding route: %s/32 dev %s (for inbound traffic to container)", containerIP, vethName)
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route for container IP: %w", err)
	}

	// Enable IP forwarding in root namespace (critical for routing between interfaces)
	forwardingPath := "/proc/sys/net/ipv4/ip_forward"
	if err := ioutil.WriteFile(forwardingPath, []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}

	log.Printf("%s configured successfully: gateway=%s, route=%s/32 dev %s", vethName, gatewayAddr, containerIP, vethName)
	return nil
}

// renameVethToEthNInContainerNs renames a veth interface to ethN in container namespace
func renameVethToEthNInContainerNs(netnsPath, oldName, newName, ipAddress, networkCIDR string) error {
	log.Printf("Renaming %s to %s in container namespace and assigning IP %s", oldName, newName, ipAddress)

	// CRITICAL: Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current namespace (root namespace) to return to later
	rootNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root namespace: %w", err)
	}
	defer rootNs.Close()

	// Open the container namespace
	containerNs, err := netns.GetFromPath(netnsPath)
	if err != nil {
		return fmt.Errorf("failed to get container namespace: %w", err)
	}
	defer containerNs.Close()

	// Ensure we always return to root namespace
	defer func() {
		if err := netns.Set(rootNs); err != nil {
			log.Printf("Warning: failed to return to root namespace: %v", err)
		}
	}()

	// Switch to container namespace
	log.Printf("Switching to container namespace")
	if err := netns.Set(containerNs); err != nil {
		return fmt.Errorf("failed to switch to container namespace: %w", err)
	}

	// CRITICAL: Ensure loopback interface is up in container namespace
	// Each namespace gets its own loopback that starts DOWN
	// DNS server listens on 127.0.0.11:53, so loopback must be UP
	// (Idempotent - safe to call even if already up from eth0 setup)
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get loopback interface: %w", err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return fmt.Errorf("failed to bring up loopback interface: %w", err)
	}
	log.Printf("Loopback interface ensured up in container namespace")

	// Get interface by old name
	link, err := netlink.LinkByName(oldName)
	if err != nil {
		return fmt.Errorf("failed to get %s interface: %w", oldName, err)
	}

	// Rename interface
	log.Printf("Renaming %s to %s", oldName, newName)
	if err := netlink.LinkSetName(link, newName); err != nil {
		return fmt.Errorf("failed to rename %s to %s: %w", oldName, newName, err)
	}

	// Re-fetch the link with new name
	link, err = netlink.LinkByName(newName)
	if err != nil {
		return fmt.Errorf("failed to get renamed %s interface: %w", newName, err)
	}

	// CRITICAL: Use /32 to force all traffic through gateway
	addr, err := netlink.ParseAddr(fmt.Sprintf("%s/32", ipAddress))
	if err != nil {
		return fmt.Errorf("failed to parse IP address: %w", err)
	}

	log.Printf("Assigning IP %s/32 to %s", ipAddress, newName)
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to assign IP to %s: %w", newName, err)
	}

	// Bring interface up
	log.Printf("Bringing %s up", newName)
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring %s up: %w", newName, err)
	}

	// Add default route via gateway for this network
	// Parse gateway from network CIDR (first IP in range)
	_, ipNet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse network CIDR %s: %w", networkCIDR, err)
	}

	gatewayIP := make(net.IP, len(ipNet.IP))
	copy(gatewayIP, ipNet.IP)
	gatewayIP[len(gatewayIP)-1] |= 1 // Set last bit to get .1

	// CRITICAL: With /32 addresses, we must first add a link-scoped route to the gateway
	// Scope: 253 (RT_SCOPE_LINK) tells kernel gateway is directly reachable (no ARP, point-to-point)
	// Without this scope, kernel can't route to gateway when using /32 addresses
	gatewayRoute := &netlink.Route{
		Dst:       &net.IPNet{IP: gatewayIP, Mask: net.CIDRMask(32, 32)},
		LinkIndex: link.Attrs().Index,
		Scope:     netlink.Scope(253), // RT_SCOPE_LINK - CRITICAL for point-to-point links!
	}

	log.Printf("Adding link-scoped route to gateway %s/32 dev %s scope link", gatewayIP.String(), newName)
	if err := netlink.RouteAdd(gatewayRoute); err != nil {
		return fmt.Errorf("failed to add route to gateway: %w", err)
	}

	// Now add route for the network CIDR via gateway (this will work because gateway is now reachable)
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet,
		Gw:        gatewayIP,
	}

	log.Printf("Adding route: %s via %s dev %s", networkCIDR, gatewayIP.String(), newName)
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	// Add default route for eth0 (first network) to enable internet access
	if newName == "eth0" {
		defaultRoute := &netlink.Route{
			Dst:       nil, // nil means default route (0.0.0.0/0)
			Gw:        gatewayIP,
			LinkIndex: link.Attrs().Index,
		}

		log.Printf("Adding default route via gateway %s dev %s (internet access)", gatewayIP.String(), newName)
		if err := netlink.RouteAdd(defaultRoute); err != nil {
			return fmt.Errorf("failed to add default route: %w", err)
		}
	}

	log.Printf("%s renamed to %s successfully with IP %s", oldName, newName, ipAddress)
	return nil
}

// addPeerToInterface adds a peer to a specified WireGuard interface
func addPeerToInterface(ifName, endpoint, publicKeyStr string, allowedIPs []string) error {
	log.Printf("Adding peer to %s: endpoint=%s allowedIPs=%v", ifName, endpoint, allowedIPs)

	// Parse peer public key
	peerKey, err := wgtypes.ParseKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	// Parse endpoint
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint: %w", err)
	}

	// Parse allowed IPs
	allowedIPNets := make([]net.IPNet, 0, len(allowedIPs))
	for _, cidr := range allowedIPs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("failed to parse allowed IP %s: %w", cidr, err)
		}
		allowedIPNets = append(allowedIPNets, *ipnet)
	}

	// Create wgctrl client
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Create peer config
	keepalive := 25 * time.Second
	peerConfig := wgtypes.PeerConfig{
		PublicKey:                   peerKey,
		Endpoint:                    udpAddr,
		AllowedIPs:                  allowedIPNets,
		PersistentKeepaliveInterval: &keepalive,
		ReplaceAllowedIPs:           false, // Append, don't replace
	}

	// Configure device with peer
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := client.ConfigureDevice(ifName, config); err != nil {
		return fmt.Errorf("failed to add peer to %s: %w", ifName, err)
	}

	// Add kernel routes for each allowed IP (so packets route to wg interface)
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get %s interface: %w", ifName, err)
	}

	for _, allowedIP := range allowedIPNets {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &allowedIP,
		}

		log.Printf("Adding route for peer: %s dev %s", allowedIP.String(), ifName)
		if err := netlink.RouteAdd(route); err != nil {
			// Ignore "file exists" errors (route already present)
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route for %s: %w", allowedIP.String(), err)
			}
			log.Printf("Route for %s already exists, skipping", allowedIP.String())
		}
	}

	log.Printf("Peer added to %s successfully: endpoint=%s", ifName, endpoint)
	return nil
}

// removePeerFromInterface removes a peer from a specified WireGuard interface
func removePeerFromInterface(ifName, publicKeyStr string) error {
	log.Printf("Removing peer from %s: publicKey=%s", ifName, publicKeyStr)

	// Parse peer public key
	peerKey, err := wgtypes.ParseKey(publicKeyStr)
	if err != nil {
		return fmt.Errorf("failed to parse peer public key: %w", err)
	}

	// Create wgctrl client
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl client: %w", err)
	}
	defer client.Close()

	// Get current device config to retrieve peer's allowed IPs (before removal)
	device, err := client.Device(ifName)
	if err != nil {
		return fmt.Errorf("failed to get %s device info: %w", ifName, err)
	}

	// Find peer and save its allowed IPs for route cleanup
	var allowedIPs []net.IPNet
	for _, peer := range device.Peers {
		if peer.PublicKey == peerKey {
			allowedIPs = peer.AllowedIPs
			break
		}
	}

	// Create peer config with Remove flag
	peerConfig := wgtypes.PeerConfig{
		PublicKey: peerKey,
		Remove:    true,
	}

	// Configure device to remove peer
	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	if err := client.ConfigureDevice(ifName, config); err != nil {
		return fmt.Errorf("failed to remove peer from %s: %w", ifName, err)
	}

	// Remove kernel routes for the peer's allowed IPs
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		log.Printf("Warning: failed to get %s interface for route cleanup: %v", ifName, err)
		// Continue - peer is already removed from WireGuard
	} else {
		for _, allowedIP := range allowedIPs {
			route := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       &allowedIP,
			}

			log.Printf("Removing route for peer: %s dev %s", allowedIP.String(), ifName)
			if err := netlink.RouteDel(route); err != nil {
				log.Printf("Warning: failed to remove route for %s: %v", allowedIP.String(), err)
				// Continue - best effort cleanup
			}
		}
	}

	log.Printf("Peer removed from %s successfully", ifName)
	return nil
}

// deleteInterfaceInContainerNs deletes an interface in the container namespace
func deleteInterfaceInContainerNs(netnsPath, ifName string) error {
	log.Printf("Deleting interface %s in container namespace", ifName)

	// CRITICAL: Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Get current namespace (root namespace) to return to later
	rootNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get root namespace: %w", err)
	}
	defer rootNs.Close()

	// Open the container namespace
	containerNs, err := netns.GetFromPath(netnsPath)
	if err != nil {
		return fmt.Errorf("failed to get container namespace: %w", err)
	}
	defer containerNs.Close()

	// Ensure we always return to root namespace
	defer func() {
		if err := netns.Set(rootNs); err != nil {
			log.Printf("Warning: failed to return to root namespace: %v", err)
		}
	}()

	// Switch to container namespace
	if err := netns.Set(containerNs); err != nil {
		return fmt.Errorf("failed to switch to container namespace: %w", err)
	}

	// Get interface by name
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		// Interface doesn't exist - not an error, might already be deleted
		log.Printf("Interface %s not found in container namespace (might be already deleted)", ifName)
		return nil
	}

	// Delete interface
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete %s: %w", ifName, err)
	}

	log.Printf("Interface %s deleted successfully from container namespace", ifName)
	return nil
}

