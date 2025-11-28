// Arca WireGuard Network Service
// gRPC server for managing WireGuard network interfaces in containers
// Runs over vsock for communication with the host

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	pb "github.com/vas-solutus/arca-wireguard-service/proto"
	"github.com/vas-solutus/arca-wireguard-service/internal/wireguard"
	"github.com/vas-solutus/arca-wireguard-service/internal/dns"
	"google.golang.org/grpc"
)

const (
	WIREGUARD_PORT = 51820 // vsock port for WireGuard control API
	VERSION        = "0.1.0"
)

var startTime = time.Now()

// firewallOnce ensures firewall initialization happens exactly once
var firewallOnce sync.Once

// initializeFirewall sets up vmnet security and NAT rules
// Called lazily on first AddNetwork RPC (not at startup)
// This allows host network containers to skip firewall setup entirely
func initializeFirewall() {
	log.Printf("Initializing firewall rules (lazy init on first network)...")

	// Configure default vmnet security (Phase 4.1)
	// This blocks all vmnet INPUT except WireGuard UDP traffic
	if err := wireguard.ConfigureDefaultVmnetSecurity(); err != nil {
		log.Fatalf("Failed to configure vmnet security: %v", err)
	}
	log.Printf("vmnet security configured (underlay secured, only WireGuard UDP allowed)")

	// Configure NAT for internet access (Phase 3)
	// Creates MASQUERADE rule for eth0 → internet traffic
	if err := wireguard.ConfigureNATForInternet(); err != nil {
		log.Fatalf("Failed to configure NAT for internet: %v", err)
	}
	log.Printf("NAT configured (internet access enabled via eth0 MASQUERADE)")
}

// server implements the WireGuardService gRPC service
type server struct {
	pb.UnimplementedWireGuardServiceServer
	hub         *wireguard.Hub
	dnsResolver *dns.Resolver
	dnsServer   *dns.Server
	mu          sync.RWMutex
}

// AddNetwork adds a network to the container's WireGuard hub
// Creates hub lazily on first network addition
func (s *server) AddNetwork(ctx context.Context, req *pb.AddNetworkRequest) (*pb.AddNetworkResponse, error) {
	log.Printf("AddNetwork: network_id=%s index=%d peer_endpoint=%s ip=%s network=%s",
		req.NetworkId, req.NetworkIndex, req.PeerEndpoint, req.IpAddress, req.NetworkCidr)

	// Initialize firewall on first network addition (thread-safe, runs exactly once)
	// This allows host network containers (no AddNetwork calls) to skip firewall setup
	firewallOnce.Do(initializeFirewall)

	s.mu.Lock()

	// Create hub if it doesn't exist (lazy initialization)
	if s.hub == nil {
		// Pass callback to update DNS server's upstream when gateway is discovered
		hub, err := wireguard.NewHub(func(gatewayIP string) {
			// Update DNS server to use vmnet gateway for upstream DNS
			s.dnsServer.UpdateUpstreamDNS([]string{gatewayIP + ":53"})
			// Register host.docker.internal -> gateway IP for host access (#24)
			s.dnsResolver.AddEntry("_host", "host.docker.internal", "", gatewayIP, nil)
		})
		if err != nil {
			s.mu.Unlock()
			log.Printf("Failed to create hub: %v", err)
			return &pb.AddNetworkResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to create hub: %v", err),
			}, nil
		}
		s.hub = hub
		log.Printf("Hub created successfully")
	}
	s.mu.Unlock()

	// Add network
	wgIface, ethIface, pubKey, err := s.hub.AddNetwork(
		req.NetworkId,
		req.NetworkIndex,
		req.PrivateKey,
		req.ListenPort,
		req.PeerEndpoint,
		req.PeerPublicKey,
		req.IpAddress,
		req.NetworkCidr,
		req.Gateway,
	)

	if err != nil {
		log.Printf("AddNetwork failed: %v", err)
		return &pb.AddNetworkResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	s.mu.RLock()
	totalNetworks := uint32(len(s.hub.GetInterfaces()))
	s.mu.RUnlock()

	return &pb.AddNetworkResponse{
		Success:       true,
		TotalNetworks: totalNetworks,
		WgInterface:   wgIface,
		EthInterface:  ethIface,
		PublicKey:     pubKey,
	}, nil
}

// RemoveNetwork removes a network from the container's WireGuard hub
func (s *server) RemoveNetwork(ctx context.Context, req *pb.RemoveNetworkRequest) (*pb.RemoveNetworkResponse, error) {
	log.Printf("RemoveNetwork: network_id=%s index=%d", req.NetworkId, req.NetworkIndex)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.RemoveNetworkResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	if err := hub.RemoveNetwork(req.NetworkId, req.NetworkIndex); err != nil {
		log.Printf("RemoveNetwork failed: %v", err)
		return &pb.RemoveNetworkResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	s.mu.RLock()
	remaining := uint32(len(hub.GetInterfaces()))
	s.mu.RUnlock()

	return &pb.RemoveNetworkResponse{
		Success:           true,
		RemainingNetworks: remaining,
	}, nil
}

// GetStatus returns WireGuard hub status and statistics
func (s *server) GetStatus(ctx context.Context, req *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.GetStatusResponse{
			Version:      VERSION,
			NetworkCount: 0,
			Interfaces:   nil,
			Peers:        nil,
		}, nil
	}

	interfaces := hub.GetStatus()

	// Convert to protobuf format
	pbInterfaces := make([]*pb.InterfaceStatus, 0, len(interfaces))
	allPeers := make([]*pb.PeerStatus, 0)

	for _, iface := range interfaces {
		pbInterfaces = append(pbInterfaces, &pb.InterfaceStatus{
			NetworkId:   iface.NetworkID,
			Name:        iface.InterfaceName,
			PublicKey:   iface.PublicKey,
			ListenPort:  uint32(iface.ListenPort),
			IpAddresses: []string{iface.IPAddress},
		})

		// Collect all peers from all interfaces
		for _, peer := range iface.Peers {
			allPeers = append(allPeers, &pb.PeerStatus{
				NetworkId:       iface.NetworkID,
				InterfaceName:   peer.InterfaceName,
				PublicKey:       peer.PublicKey,
				Endpoint:        peer.Endpoint,
				AllowedIps:      peer.AllowedIPs,
				LatestHandshake: peer.LatestHandshake,
				Stats: &pb.TransferStats{
					BytesReceived:       peer.BytesReceived,
					BytesSent:           peer.BytesSent,
					PersistentKeepalive: peer.PersistentKeepalive,
				},
			})
		}
	}

	return &pb.GetStatusResponse{
		Version:      VERSION,
		NetworkCount: uint32(len(interfaces)),
		Interfaces:   pbInterfaces,
		Peers:        allPeers,
	}, nil
}

// GetVmnetEndpoint returns the container's vmnet endpoint (eth0 IP:port)
func (s *server) GetVmnetEndpoint(ctx context.Context, req *pb.GetVmnetEndpointRequest) (*pb.GetVmnetEndpointResponse, error) {
	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.GetVmnetEndpointResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	endpoint, err := hub.GetVmnetEndpoint()
	if err != nil {
		log.Printf("GetVmnetEndpoint failed: %v", err)
		return &pb.GetVmnetEndpointResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.GetVmnetEndpointResponse{
		Success:  true,
		Endpoint: endpoint,
	}, nil
}

// AddPeer adds a peer to a WireGuard interface (for full mesh networking)
func (s *server) AddPeer(ctx context.Context, req *pb.AddPeerRequest) (*pb.AddPeerResponse, error) {
	log.Printf("AddPeer: network_id=%s index=%d peer_endpoint=%s peer_ip=%s",
		req.NetworkId, req.NetworkIndex, req.PeerEndpoint, req.PeerIpAddress)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.AddPeerResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	totalPeers, err := hub.AddPeer(
		req.NetworkId,
		req.NetworkIndex,
		req.PeerPublicKey,
		req.PeerEndpoint,
		req.PeerIpAddress,
	)

	if err != nil {
		log.Printf("AddPeer failed: %v", err)
		return &pb.AddPeerResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Add DNS entry for this peer (Phase 3.1)
	s.dnsResolver.AddEntry(
		req.NetworkId,
		req.PeerName,
		req.PeerContainerId,
		req.PeerIpAddress,
		req.PeerAliases,
	)

	return &pb.AddPeerResponse{
		Success:    true,
		TotalPeers: uint32(totalPeers),
	}, nil
}

// RemovePeer removes a peer from a WireGuard interface
func (s *server) RemovePeer(ctx context.Context, req *pb.RemovePeerRequest) (*pb.RemovePeerResponse, error) {
	log.Printf("RemovePeer: network_id=%s index=%d peer_public_key=%s",
		req.NetworkId, req.NetworkIndex, req.PeerPublicKey)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.RemovePeerResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	remainingPeers, err := hub.RemovePeer(
		req.NetworkId,
		req.NetworkIndex,
		req.PeerPublicKey,
	)

	if err != nil {
		log.Printf("RemovePeer failed: %v", err)
		return &pb.RemovePeerResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	// Remove DNS entry for this peer (Phase 3.1)
	s.dnsResolver.RemoveEntry(req.NetworkId, req.PeerName)

	return &pb.RemovePeerResponse{
		Success:        true,
		RemainingPeers: uint32(remainingPeers),
	}, nil
}

// PublishPort publishes a container port on the vmnet interface (Phase 4.1)
// Creates DNAT and INPUT rules to expose container_ip:container_port on vmnet_ip:host_port
func (s *server) PublishPort(ctx context.Context, req *pb.PublishPortRequest) (*pb.PublishPortResponse, error) {
	log.Printf("PublishPort: protocol=%s host_port=%d container_ip=%s container_port=%d",
		req.Protocol, req.HostPort, req.ContainerIp, req.ContainerPort)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.PublishPortResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	if err := wireguard.PublishPort(req.Protocol, req.HostPort, req.ContainerIp, req.ContainerPort); err != nil {
		log.Printf("PublishPort failed: %v", err)
		return &pb.PublishPortResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.PublishPortResponse{
		Success: true,
	}, nil
}

// UnpublishPort removes port mapping rules from vmnet interface (Phase 4.1)
func (s *server) UnpublishPort(ctx context.Context, req *pb.UnpublishPortRequest) (*pb.UnpublishPortResponse, error) {
	log.Printf("UnpublishPort: protocol=%s host_port=%d", req.Protocol, req.HostPort)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &pb.UnpublishPortResponse{
			Success: false,
			Error:   "hub not initialized",
		}, nil
	}

	if err := wireguard.UnpublishPort(req.Protocol, req.HostPort); err != nil {
		log.Printf("UnpublishPort failed: %v", err)
		return &pb.UnpublishPortResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.UnpublishPortResponse{
		Success: true,
	}, nil
}

// DumpNftables returns the full nftables ruleset for debugging
func (s *server) DumpNftables(ctx context.Context, req *pb.DumpNftablesRequest) (*pb.DumpNftablesResponse, error) {
	log.Printf("DumpNftables: dumping full nftables ruleset")

	ruleset, err := wireguard.DumpNftables()
	if err != nil {
		log.Printf("DumpNftables failed: %v", err)
		return &pb.DumpNftablesResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.DumpNftablesResponse{
		Success: true,
		Ruleset: ruleset,
	}, nil
}

func main() {
	log.Printf("Arca WireGuard Service v%s starting...", VERSION)

	// Create DNS resolver (shared across all containers)
	dnsResolver := dns.NewResolver()
	log.Printf("DNS resolver initialized")

	// Create DNS server listening on all interfaces (0.0.0.0:53)
	// This allows it to receive queries on gateway IPs (172.18.0.1, 172.19.0.1, etc.)
	// Security: INPUT chain blocks DNS queries from eth0 (control plane) - see configureNATForInternet
	// Containers query gateway IP directly (e.g., 172.18.0.1:53) - no DNAT needed
	dnsServer := dns.NewServer("0.0.0.0:53", dnsResolver)

	// Start DNS server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := dnsServer.ListenAndServe(ctx); err != nil {
			log.Printf("DNS server error: %v", err)
		}
	}()

	log.Printf("DNS server started on 0.0.0.0:53 (accessible on gateway IPs, blocked from control plane)")

	// Firewall initialization is now lazy (see initializeFirewall function)
	// It will be called on the first AddNetwork RPC, allowing host network containers
	// to skip firewall setup entirely (they never call AddNetwork)

	// Listen on vsock for WireGuard gRPC API
	listener, err := vsock.Listen(WIREGUARD_PORT, nil)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", WIREGUARD_PORT, err)
	}
	defer listener.Close()

	log.Printf("Listening on vsock port %d", WIREGUARD_PORT)

	// Create gRPC server with DNS resolver and DNS server
	grpcServer := grpc.NewServer()
	pb.RegisterWireGuardServiceServer(grpcServer, &server{
		dnsResolver: dnsResolver,
		dnsServer:   dnsServer,
	})

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel() // Stop DNS server
		grpcServer.GracefulStop()
	}()

	// Start serving
	log.Println("WireGuard service ready (with integrated DNS)")
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
