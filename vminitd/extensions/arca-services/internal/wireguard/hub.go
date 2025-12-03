// WireGuard Hub Management
// Manages a WireGuard interface (wg0) for container networking

package wireguard

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Hub represents a multi-network WireGuard hub for a container
// Each network gets its own wgN interface with dedicated veth pair
type Hub struct {
	netnsPath       string                     // Path to container network namespace
	containerID     string                     // Container ID (for /etc/resolv.conf path)
	interfaces      map[string]*Interface      // networkID -> Interface
	mu              sync.RWMutex
	onGatewayReady  func(gateway string)       // Callback when vmnet gateway is discovered
}

// Interface represents a single WireGuard interface (wg0, wg1, wg2, etc.)
type Interface struct {
	networkID     string
	interfaceName string            // wg0, wg1, wg2, etc.
	ethName       string            // eth0, eth1, eth2, etc. (in container namespace)
	vethRootName  string            // veth-root0, veth-root1, etc.
	vethContName  string            // veth-cont0, veth-cont1, etc.
	privateKey    string
	publicKey     string
	listenPort    uint32
	ipAddress     string
	networkCIDR   string
	gateway       string
	peers         map[string]*Peer  // peerPublicKey -> Peer
}

// Peer represents a WireGuard peer on a specific interface
type Peer struct {
	publicKey  string
	endpoint   string
	allowedIPs []string
}

// InterfaceStatus represents the status of a single WireGuard interface
type InterfaceStatus struct {
	NetworkID     string
	InterfaceName string
	EthName       string
	PublicKey     string
	ListenPort    int
	IPAddress     string
	NetworkCIDR   string
	Peers         []PeerStatus
}

// PeerStatus represents peer statistics
type PeerStatus struct {
	InterfaceName       string
	PublicKey           string
	Endpoint            string
	AllowedIPs          []string
	LatestHandshake     uint64
	BytesReceived       uint64
	BytesSent           uint64
	PersistentKeepalive uint32
}

// NewHub creates a new multi-network WireGuard hub for a container
// The hub starts empty; networks are added via AddNetwork()
// containerID is used to create a unique network namespace for this container
func NewHub(containerID string, onGatewayReady func(gateway string)) (*Hub, error) {
	log.Printf("Creating multi-network WireGuard hub for container %s...", containerID)

	// Create a new network namespace for this container
	// The namespace is created upfront so WireGuard can be configured BEFORE the container process starts
	netnsPath, err := createContainerNetNs(containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to create container namespace: %w", err)
	}
	log.Printf("Created container namespace: %s", netnsPath)

	return &Hub{
		netnsPath:      netnsPath,
		containerID:    containerID,
		interfaces:     make(map[string]*Interface),
		onGatewayReady: onGatewayReady,
	}, nil
}

// GetNamespacePath returns the path to the container's network namespace
// This is used by the host to configure the OCI spec to join this namespace
func (h *Hub) GetNamespacePath() string {
	return h.netnsPath
}

// NetworkCount returns the number of networks configured
func (h *Hub) NetworkCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.interfaces)
}

// GetInterfaces returns the interfaces map for counting
func (h *Hub) GetInterfaces() map[string]*Interface {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.interfaces
}

// AddNetwork adds a network to the hub
// AddNetwork creates a new wgN interface and ethN pair for the given network.
// Returns: (wgInterface, ethInterface, publicKey, error)
func (h *Hub) AddNetwork(
	networkID string,
	networkIndex uint32,
	privateKey string,
	listenPort uint32,
	peerEndpoint, peerPublicKey,
	ipAddress, networkCIDR, gateway string,
) (wgInterface, ethInterface, publicKey string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 3.1 Check if network exists
	if _, exists := h.interfaces[networkID]; exists {
		return "", "", "", fmt.Errorf("network %s already exists", networkID)
	}

	// 3.1.1 Write /etc/resolv.conf IMMEDIATELY on first network (before creating interfaces)
	// This prevents race condition where container starts before DNS is configured
	// We write it early so it's ready when container process starts
	if networkIndex == 0 && h.containerID != "" {
		resolvConfPath := fmt.Sprintf("/run/container/%s/rootfs/etc/resolv.conf", h.containerID)
		resolvConfContent := fmt.Sprintf("nameserver %s\n", gateway)
		if err := ioutil.WriteFile(resolvConfPath, []byte(resolvConfContent), 0644); err != nil {
			log.Printf("Warning: failed to write resolv.conf: %v", err)
		} else {
			log.Printf("✓ Wrote /etc/resolv.conf EARLY: nameserver %s (prevents DNS race)", gateway)
		}
	}

	// 3.2 Generate interface names
	wgName := fmt.Sprintf("wg%d", networkIndex)
	ethName := fmt.Sprintf("eth%d", networkIndex)
	vethRootName := fmt.Sprintf("veth-root%d", networkIndex)
	vethContName := fmt.Sprintf("veth-cont%d", networkIndex)

	log.Printf("Creating network: networkID=%s index=%d wg=%s eth=%s", networkID, networkIndex, wgName, ethName)

	// 3.3 Derive public key
	pubKey, err := derivePublicKey(privateKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to derive public key: %w", err)
	}

	// 3.4 Create veth pair in root namespace
	if err := createVethPairWithNames(vethRootName, vethContName); err != nil {
		return "", "", "", fmt.Errorf("failed to create veth pair: %w", err)
	}

	// 3.5 Move veth-contN to container namespace
	if err := moveInterfaceToNetNs(vethContName, h.netnsPath); err != nil {
		// Cleanup veth pair
		if link, getErr := netlink.LinkByName(vethRootName); getErr == nil {
			netlink.LinkDel(link)
		}
		return "", "", "", fmt.Errorf("failed to move %s to container namespace: %w", vethContName, err)
	}

	// 3.6 Create wgN in ROOT namespace
	if err := createWgInterfaceInRootNs(wgName, privateKey, listenPort); err != nil {
		// Cleanup veth pair
		if link, getErr := netlink.LinkByName(vethRootName); getErr == nil {
			netlink.LinkDel(link)
		}
		return "", "", "", fmt.Errorf("failed to create %s: %w", wgName, err)
	}

	// 3.7 Configure veth-rootN with gateway IP and add route for container IP
	if err := configureVethRootWithGateway(vethRootName, gateway, networkCIDR, ipAddress, networkIndex); err != nil {
		// Cleanup wgN
		if link, getErr := netlink.LinkByName(wgName); getErr == nil {
			netlink.LinkDel(link)
		}
		// Cleanup veth pair
		if link, getErr := netlink.LinkByName(vethRootName); getErr == nil {
			netlink.LinkDel(link)
		}
		return "", "", "", fmt.Errorf("failed to configure %s: %w", vethRootName, err)
	}

	// 3.8 Rename veth-contN to ethN in container namespace
	if err := renameVethToEthNInContainerNs(h.netnsPath, vethContName, ethName, ipAddress, networkCIDR); err != nil {
		// Cleanup wgN
		if link, getErr := netlink.LinkByName(wgName); getErr == nil {
			netlink.LinkDel(link)
		}
		// Cleanup veth pair
		if link, getErr := netlink.LinkByName(vethRootName); getErr == nil {
			netlink.LinkDel(link)
		}
		return "", "", "", fmt.Errorf("failed to rename %s to %s: %w", vethContName, ethName, err)
	}

	// 3.9 Setup default route in root namespace (only on first network)
	// This must happen AFTER eth0 has an IP address (which vminitd assigns during boot)
	// The DNS server needs this route to reach upstream DNS via vmnet gateway
	if networkIndex == 0 {
		gatewayIP, err := SetupDefaultRoute()
		if err != nil {
			log.Printf("Warning: failed to setup default route: %v", err)
		}
		// Notify DNS server of discovered gateway (even if route already existed)
		if gatewayIP != "" && h.onGatewayReady != nil {
			h.onGatewayReady(gatewayIP)
		}
		// Note: /etc/resolv.conf is now written EARLY (step 3.1.1) to prevent DNS race condition
	}

	// 3.10 Add initial peer (skip if empty for Phase 2.4 dynamic mesh)
	if peerEndpoint != "" && peerPublicKey != "" {
		if err := addPeerToInterface(wgName, peerEndpoint, peerPublicKey, []string{networkCIDR}); err != nil {
			// Cleanup everything
			if link, getErr := netlink.LinkByName(wgName); getErr == nil {
				netlink.LinkDel(link)
			}
			if link, getErr := netlink.LinkByName(vethRootName); getErr == nil {
				netlink.LinkDel(link)
			}
			return "", "", "", fmt.Errorf("failed to add peer: %w", err)
		}
		log.Printf("Initial peer added to %s: endpoint=%s", wgName, peerEndpoint)
	} else {
		log.Printf("No initial peer specified for %s (Phase 2.4 dynamic mesh)", wgName)
	}

	// 3.11 Create and store Interface object
	iface := &Interface{
		networkID:     networkID,
		interfaceName: wgName,
		ethName:       ethName,
		vethRootName:  vethRootName,
		vethContName:  vethContName,
		privateKey:    privateKey,
		publicKey:     pubKey,
		listenPort:    listenPort,
		ipAddress:     ipAddress,
		networkCIDR:   networkCIDR,
		gateway:       gateway,
		peers:         make(map[string]*Peer),
	}

	// Add initial peer to tracking map (skip if empty for Phase 2.4)
	if peerEndpoint != "" && peerPublicKey != "" {
		iface.peers[peerPublicKey] = &Peer{
			publicKey:  peerPublicKey,
			endpoint:   peerEndpoint,
			allowedIPs: []string{networkCIDR},
		}
	}

	h.interfaces[networkID] = iface

	log.Printf("Network added successfully: networkID=%s wg=%s eth=%s gateway=%s", networkID, wgName, ethName, gateway)

	return wgName, ethName, pubKey, nil
}

// RemoveNetwork removes a network from the hub, deleting wgN and ethN interfaces
func (h *Hub) RemoveNetwork(networkID string, networkIndex uint32) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 4.1 Find interface
	iface, exists := h.interfaces[networkID]
	if !exists {
		return fmt.Errorf("network %s not found", networkID)
	}

	log.Printf("Removing network: networkID=%s wg=%s eth=%s", networkID, iface.interfaceName, iface.ethName)

	// 4.2 Remove all peers from wgN
	for peerPubKey := range iface.peers {
		if err := removePeerFromInterface(iface.interfaceName, peerPubKey); err != nil {
			log.Printf("Warning: failed to remove peer %s: %v", peerPubKey, err)
		}
	}

	// 4.3 Delete ethN in container namespace
	if err := deleteInterfaceInContainerNs(h.netnsPath, iface.ethName); err != nil {
		log.Printf("Warning: failed to delete %s: %v", iface.ethName, err)
	}

	// 4.4 Delete wgN in root namespace
	if link, err := netlink.LinkByName(iface.interfaceName); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			log.Printf("Warning: failed to delete %s: %v", iface.interfaceName, err)
		}
	}

	// 4.5 Delete veth pair (deleting one side deletes both)
	if link, err := netlink.LinkByName(iface.vethRootName); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			log.Printf("Warning: failed to delete %s: %v", iface.vethRootName, err)
		}
	}

	// 4.6 Remove from interfaces map
	delete(h.interfaces, networkID)

	log.Printf("Network removed successfully: networkID=%s interface=%s", networkID, iface.interfaceName)

	return nil
}

// AddPeer adds a peer to a specific WireGuard interface (for full mesh networking)
// Returns the total number of peers on this interface after adding
func (h *Hub) AddPeer(networkID string, networkIndex uint32, peerPublicKey, peerEndpoint, peerIPAddress string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Find interface
	iface, exists := h.interfaces[networkID]
	if !exists {
		return 0, fmt.Errorf("network %s not found", networkID)
	}

	log.Printf("Adding peer to network: networkID=%s wg=%s peerIP=%s endpoint=%s",
		networkID, iface.interfaceName, peerIPAddress, peerEndpoint)

	// Check if peer already exists
	if _, exists := iface.peers[peerPublicKey]; exists {
		log.Printf("Peer %s already exists on %s", peerPublicKey, iface.interfaceName)
		return len(iface.peers), nil
	}

	// For full mesh: each peer gets /32 allowed-ips for routing
	allowedIPs := []string{peerIPAddress + "/32"}

	// Add peer to WireGuard interface using netlink
	if err := addPeerToInterface(iface.interfaceName, peerEndpoint, peerPublicKey, allowedIPs); err != nil {
		return 0, fmt.Errorf("failed to add peer to %s: %w", iface.interfaceName, err)
	}

	// Store peer in interface's peers map
	iface.peers[peerPublicKey] = &Peer{
		publicKey:  peerPublicKey,
		endpoint:   peerEndpoint,
		allowedIPs: allowedIPs,
	}

	log.Printf("Peer added successfully: networkID=%s wg=%s totalPeers=%d",
		networkID, iface.interfaceName, len(iface.peers))

	return len(iface.peers), nil
}

// RemovePeer removes a peer from a specific WireGuard interface
// Returns the remaining number of peers on this interface after removal
func (h *Hub) RemovePeer(networkID string, networkIndex uint32, peerPublicKey string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Find interface
	iface, exists := h.interfaces[networkID]
	if !exists {
		return 0, fmt.Errorf("network %s not found", networkID)
	}

	log.Printf("Removing peer from network: networkID=%s wg=%s peerPubKey=%s",
		networkID, iface.interfaceName, peerPublicKey)

	// Check if peer exists
	if _, exists := iface.peers[peerPublicKey]; !exists {
		log.Printf("Peer %s not found on %s", peerPublicKey, iface.interfaceName)
		return len(iface.peers), nil
	}

	// Remove peer from WireGuard interface using netlink
	if err := removePeerFromInterface(iface.interfaceName, peerPublicKey); err != nil {
		return 0, fmt.Errorf("failed to remove peer from %s: %w", iface.interfaceName, err)
	}

	// Remove peer from interface's peers map
	delete(iface.peers, peerPublicKey)

	log.Printf("Peer removed successfully: networkID=%s wg=%s remainingPeers=%d",
		networkID, iface.interfaceName, len(iface.peers))

	return len(iface.peers), nil
}


// GetStatus returns the current hub status
// GetStatus returns status for all WireGuard interfaces
func (h *Hub) GetStatus() []InterfaceStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	statuses := make([]InterfaceStatus, 0, len(h.interfaces))

	for _, iface := range h.interfaces {
		peers := make([]PeerStatus, 0, len(iface.peers))

		// Query actual WireGuard stats from kernel
		wgClient, err := wgctrl.New()
		if err == nil {
			defer wgClient.Close()

			device, err := wgClient.Device(iface.interfaceName)
			if err == nil {
				for _, peer := range device.Peers {
					pubKey := peer.PublicKey.String()
					allowedIPs := make([]string, len(peer.AllowedIPs))
					for i, ip := range peer.AllowedIPs {
						allowedIPs[i] = ip.String()
					}

					endpoint := ""
					if peer.Endpoint != nil {
						endpoint = peer.Endpoint.String()
					}

					peers = append(peers, PeerStatus{
						InterfaceName:       iface.interfaceName,
						PublicKey:           pubKey,
						Endpoint:            endpoint,
						AllowedIPs:          allowedIPs,
						LatestHandshake:     uint64(peer.LastHandshakeTime.Unix()),
						BytesReceived:       uint64(peer.ReceiveBytes),
						BytesSent:           uint64(peer.TransmitBytes),
						PersistentKeepalive: uint32(peer.PersistentKeepaliveInterval.Seconds()),
					})
				}
			}
		}

		status := InterfaceStatus{
			NetworkID:     iface.networkID,
			InterfaceName: iface.interfaceName,
			EthName:       iface.ethName,
			PublicKey:     iface.publicKey,
			ListenPort:    int(iface.listenPort),
			IPAddress:     iface.ipAddress,
			NetworkCIDR:   iface.networkCIDR,
			Peers:         peers,
		}
		statuses = append(statuses, status)
	}

	return statuses
}

// GetVmnetEndpoint returns the container's vmnet endpoint (eth0 IP:port)
// This is used by peer containers to configure WireGuard peers
// Uses the first interface's listen port, or 51820 if no interfaces exist
func (h *Hub) GetVmnetEndpoint() (string, error) {
	// Get eth0 interface via netlink
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return "", fmt.Errorf("failed to get eth0 interface: %w", err)
	}

	// Get IPv4 addresses on eth0
	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return "", fmt.Errorf("failed to get eth0 addresses: %w", err)
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("no IPv4 addresses found on eth0")
	}

	// Use first IPv4 address
	ip := addrs[0].IP.String()

	// Determine port: use first interface's listen port, or default to 51820
	h.mu.RLock()
	port := uint32(51820) // default
	for _, iface := range h.interfaces {
		port = iface.listenPort
		break // Use first interface's port
	}
	h.mu.RUnlock()

	// Format as IP:port endpoint
	endpoint := fmt.Sprintf("%s:%d", ip, port)

	log.Printf("Vmnet endpoint: %s", endpoint)

	return endpoint, nil
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// derivePublicKey generates a public key from a private key using curve25519
func derivePublicKey(privateKeyStr string) (string, error) {
	// Decode base64 private key
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privateKeyBytes) != 32 {
		return "", fmt.Errorf("invalid private key length: %d (expected 32)", len(privateKeyBytes))
	}

	// Derive public key using curve25519
	var privateKey, publicKey [32]byte
	copy(privateKey[:], privateKeyBytes)
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// Encode public key as base64
	return base64.StdEncoding.EncodeToString(publicKey[:]), nil
}

