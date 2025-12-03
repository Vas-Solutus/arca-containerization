// Arca Services - Unified container services binary
// Runs all container extension services as goroutines with coordinated startup
//
// Services:
// - WireGuard Network Service (vsock:51820) - Network interface management
// - Filesystem Service (vsock:51821) - Filesystem operations
// - Process Control Service (vsock:51822) - Process lifecycle control
//
// Ready Signal Port (vsock:51819) - Opens ONLY after all services are fully ready

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"

	// Internal packages
	"github.com/vas-solutus/arca-services/internal/dns"
	"github.com/vas-solutus/arca-services/internal/filesystem"
	processcontrol "github.com/vas-solutus/arca-services/internal/process"
	"github.com/vas-solutus/arca-services/internal/wireguard"

	// Proto packages
	fspb "github.com/vas-solutus/arca-services/proto/filesystem"
	procpb "github.com/vas-solutus/arca-services/proto/process"
	wgpb "github.com/vas-solutus/arca-services/proto/wireguard"
)

const (
	READY_PORT      = 51819 // Signals all services ready
	WIREGUARD_PORT  = 51820 // WireGuard network API
	FILESYSTEM_PORT = 51821 // Filesystem operations API
	PROCESS_PORT    = 51822 // Process control API
	VERSION         = "0.2.0"
)

var startTime = time.Now()

// firewallOnce ensures firewall initialization happens exactly once
var firewallOnce sync.Once

// initializeFirewall sets up vmnet security and NAT rules
// Called lazily on first AddNetwork RPC (not at startup)
func initializeFirewall() {
	log.Printf("Initializing firewall rules (lazy init on first network)...")

	if err := wireguard.ConfigureDefaultVmnetSecurity(); err != nil {
		log.Fatalf("Failed to configure vmnet security: %v", err)
	}
	log.Printf("vmnet security configured")

	if err := wireguard.ConfigureNATForInternet(); err != nil {
		log.Fatalf("Failed to configure NAT for internet: %v", err)
	}
	log.Printf("NAT configured")
}

// =============================================================================
// WireGuard Service
// =============================================================================

type wireguardServer struct {
	wgpb.UnimplementedWireGuardServiceServer
	hub         *wireguard.Hub
	dnsResolver *dns.Resolver
	dnsServer   *dns.Server
	mu          sync.RWMutex
}

func (s *wireguardServer) Ready(ctx context.Context, req *wgpb.ReadyRequest) (*wgpb.ReadyResponse, error) {
	return &wgpb.ReadyResponse{
		Ready:    true,
		Version:  VERSION,
		UptimeMs: time.Since(startTime).Milliseconds(),
	}, nil
}

func (s *wireguardServer) AddNetwork(ctx context.Context, req *wgpb.AddNetworkRequest) (*wgpb.AddNetworkResponse, error) {
	log.Printf("AddNetwork: network_id=%s index=%d peer_endpoint=%s ip=%s network=%s",
		req.NetworkId, req.NetworkIndex, req.PeerEndpoint, req.IpAddress, req.NetworkCidr)

	firewallOnce.Do(initializeFirewall)

	s.mu.Lock()
	if s.hub == nil {
		hub, err := wireguard.NewHub(req.ContainerId, func(gatewayIP string) {
			s.dnsServer.UpdateUpstreamDNS([]string{gatewayIP + ":53"})
		})
		if err != nil {
			s.mu.Unlock()
			log.Printf("Failed to create hub: %v", err)
			return &wgpb.AddNetworkResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to create hub: %v", err),
			}, nil
		}
		s.hub = hub
		log.Printf("Hub created successfully")

		if req.HostIp != "" {
			s.dnsResolver.AddEntry("_host", "host.docker.internal", "", req.HostIp, nil)
			log.Printf("Registered host.docker.internal -> %s", req.HostIp)
		}
	}

	// Add extra hosts to DNS resolver (from --add-host flag)
	for _, entry := range req.ExtraHosts {
		// Format: "hostname:ip"
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) == 2 {
			hostname := parts[0]
			ip := parts[1]
			s.dnsResolver.AddEntry("_extra", hostname, "", ip, nil)
			log.Printf("Registered extra host: %s -> %s", hostname, ip)
		}
	}
	s.mu.Unlock()

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
		return &wgpb.AddNetworkResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	s.mu.RLock()
	totalNetworks := uint32(len(s.hub.GetInterfaces()))
	s.mu.RUnlock()

	return &wgpb.AddNetworkResponse{
		Success:       true,
		TotalNetworks: totalNetworks,
		WgInterface:   wgIface,
		EthInterface:  ethIface,
		PublicKey:     pubKey,
		NamespacePath: s.hub.GetNamespacePath(),
	}, nil
}

func (s *wireguardServer) RemoveNetwork(ctx context.Context, req *wgpb.RemoveNetworkRequest) (*wgpb.RemoveNetworkResponse, error) {
	log.Printf("RemoveNetwork: network_id=%s index=%d", req.NetworkId, req.NetworkIndex)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &wgpb.RemoveNetworkResponse{Success: false, Error: "hub not initialized"}, nil
	}

	if err := hub.RemoveNetwork(req.NetworkId, req.NetworkIndex); err != nil {
		log.Printf("RemoveNetwork failed: %v", err)
		return &wgpb.RemoveNetworkResponse{Success: false, Error: err.Error()}, nil
	}

	s.mu.RLock()
	remaining := uint32(len(hub.GetInterfaces()))
	s.mu.RUnlock()

	return &wgpb.RemoveNetworkResponse{Success: true, RemainingNetworks: remaining}, nil
}

func (s *wireguardServer) GetStatus(ctx context.Context, req *wgpb.GetStatusRequest) (*wgpb.GetStatusResponse, error) {
	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &wgpb.GetStatusResponse{Version: VERSION, NetworkCount: 0}, nil
	}

	interfaces := hub.GetStatus()
	pbInterfaces := make([]*wgpb.InterfaceStatus, 0, len(interfaces))
	allPeers := make([]*wgpb.PeerStatus, 0)

	for _, iface := range interfaces {
		pbInterfaces = append(pbInterfaces, &wgpb.InterfaceStatus{
			NetworkId:   iface.NetworkID,
			Name:        iface.InterfaceName,
			PublicKey:   iface.PublicKey,
			ListenPort:  uint32(iface.ListenPort),
			IpAddresses: []string{iface.IPAddress},
		})

		for _, peer := range iface.Peers {
			allPeers = append(allPeers, &wgpb.PeerStatus{
				NetworkId:       iface.NetworkID,
				InterfaceName:   peer.InterfaceName,
				PublicKey:       peer.PublicKey,
				Endpoint:        peer.Endpoint,
				AllowedIps:      peer.AllowedIPs,
				LatestHandshake: peer.LatestHandshake,
				Stats: &wgpb.TransferStats{
					BytesReceived:       peer.BytesReceived,
					BytesSent:           peer.BytesSent,
					PersistentKeepalive: peer.PersistentKeepalive,
				},
			})
		}
	}

	return &wgpb.GetStatusResponse{
		Version:      VERSION,
		NetworkCount: uint32(len(interfaces)),
		Interfaces:   pbInterfaces,
		Peers:        allPeers,
	}, nil
}

func (s *wireguardServer) GetVmnetEndpoint(ctx context.Context, req *wgpb.GetVmnetEndpointRequest) (*wgpb.GetVmnetEndpointResponse, error) {
	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &wgpb.GetVmnetEndpointResponse{Success: false, Error: "hub not initialized"}, nil
	}

	endpoint, err := hub.GetVmnetEndpoint()
	if err != nil {
		log.Printf("GetVmnetEndpoint failed: %v", err)
		return &wgpb.GetVmnetEndpointResponse{Success: false, Error: err.Error()}, nil
	}

	return &wgpb.GetVmnetEndpointResponse{Success: true, Endpoint: endpoint}, nil
}

func (s *wireguardServer) AddPeer(ctx context.Context, req *wgpb.AddPeerRequest) (*wgpb.AddPeerResponse, error) {
	log.Printf("AddPeer: network_id=%s index=%d peer_endpoint=%s peer_ip=%s",
		req.NetworkId, req.NetworkIndex, req.PeerEndpoint, req.PeerIpAddress)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &wgpb.AddPeerResponse{Success: false, Error: "hub not initialized"}, nil
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
		return &wgpb.AddPeerResponse{Success: false, Error: err.Error()}, nil
	}

	s.dnsResolver.AddEntry(
		req.NetworkId,
		req.PeerName,
		req.PeerContainerId,
		req.PeerIpAddress,
		req.PeerAliases,
	)

	return &wgpb.AddPeerResponse{Success: true, TotalPeers: uint32(totalPeers)}, nil
}

func (s *wireguardServer) RemovePeer(ctx context.Context, req *wgpb.RemovePeerRequest) (*wgpb.RemovePeerResponse, error) {
	log.Printf("RemovePeer: network_id=%s index=%d peer_public_key=%s",
		req.NetworkId, req.NetworkIndex, req.PeerPublicKey)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &wgpb.RemovePeerResponse{Success: false, Error: "hub not initialized"}, nil
	}

	remainingPeers, err := hub.RemovePeer(
		req.NetworkId,
		req.NetworkIndex,
		req.PeerPublicKey,
	)

	if err != nil {
		log.Printf("RemovePeer failed: %v", err)
		return &wgpb.RemovePeerResponse{Success: false, Error: err.Error()}, nil
	}

	s.dnsResolver.RemoveEntry(req.NetworkId, req.PeerName)

	return &wgpb.RemovePeerResponse{Success: true, RemainingPeers: uint32(remainingPeers)}, nil
}

func (s *wireguardServer) PublishPort(ctx context.Context, req *wgpb.PublishPortRequest) (*wgpb.PublishPortResponse, error) {
	log.Printf("PublishPort: protocol=%s host_port=%d container_ip=%s container_port=%d",
		req.Protocol, req.HostPort, req.ContainerIp, req.ContainerPort)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &wgpb.PublishPortResponse{Success: false, Error: "hub not initialized"}, nil
	}

	if err := wireguard.PublishPort(req.Protocol, req.HostPort, req.ContainerIp, req.ContainerPort); err != nil {
		log.Printf("PublishPort failed: %v", err)
		return &wgpb.PublishPortResponse{Success: false, Error: err.Error()}, nil
	}

	return &wgpb.PublishPortResponse{Success: true}, nil
}

func (s *wireguardServer) UnpublishPort(ctx context.Context, req *wgpb.UnpublishPortRequest) (*wgpb.UnpublishPortResponse, error) {
	log.Printf("UnpublishPort: protocol=%s host_port=%d", req.Protocol, req.HostPort)

	s.mu.RLock()
	hub := s.hub
	s.mu.RUnlock()

	if hub == nil {
		return &wgpb.UnpublishPortResponse{Success: false, Error: "hub not initialized"}, nil
	}

	if err := wireguard.UnpublishPort(req.Protocol, req.HostPort); err != nil {
		log.Printf("UnpublishPort failed: %v", err)
		return &wgpb.UnpublishPortResponse{Success: false, Error: err.Error()}, nil
	}

	return &wgpb.UnpublishPortResponse{Success: true}, nil
}

func (s *wireguardServer) DumpNftables(ctx context.Context, req *wgpb.DumpNftablesRequest) (*wgpb.DumpNftablesResponse, error) {
	log.Printf("DumpNftables: dumping full nftables ruleset")

	ruleset, err := wireguard.DumpNftables()
	if err != nil {
		log.Printf("DumpNftables failed: %v", err)
		return &wgpb.DumpNftablesResponse{Success: false, Error: err.Error()}, nil
	}

	return &wgpb.DumpNftablesResponse{Success: true, Ruleset: ruleset}, nil
}

// startWireGuardService starts the WireGuard gRPC service
func startWireGuardService(ctx context.Context, ready chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Create DNS resolver
	dnsResolver := dns.NewResolver()
	log.Printf("[wireguard] DNS resolver initialized")

	// Create DNS server on all interfaces
	dnsServer := dns.NewServer("0.0.0.0:53", dnsResolver)

	// Start DNS server in background
	go func() {
		if err := dnsServer.ListenAndServe(ctx); err != nil {
			log.Printf("[wireguard] DNS server error: %v", err)
		}
	}()
	log.Printf("[wireguard] DNS server started on 0.0.0.0:53")

	// Listen on vsock
	listener, err := vsock.Listen(WIREGUARD_PORT, nil)
	if err != nil {
		log.Fatalf("[wireguard] Failed to listen on vsock port %d: %v", WIREGUARD_PORT, err)
	}
	defer listener.Close()

	log.Printf("[wireguard] Listening on vsock port %d", WIREGUARD_PORT)

	// Create gRPC server
	grpcServer := grpc.NewServer()
	wgpb.RegisterWireGuardServiceServer(grpcServer, &wireguardServer{
		dnsResolver: dnsResolver,
		dnsServer:   dnsServer,
	})

	// Signal ready AFTER we start serving (use goroutine to not block)
	go func() {
		// Small delay ensures Serve() has started accepting
		time.Sleep(10 * time.Millisecond)
		ready <- "wireguard"
	}()

	// Serve until context is cancelled
	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("[wireguard] Service ready")
	if err := grpcServer.Serve(listener); err != nil {
		log.Printf("[wireguard] gRPC server error: %v", err)
	}
}

// =============================================================================
// Filesystem Service
// =============================================================================

// startFilesystemService starts the Filesystem gRPC service
func startFilesystemService(ctx context.Context, ready chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Listen on vsock
	listener, err := vsock.Listen(FILESYSTEM_PORT, nil)
	if err != nil {
		log.Fatalf("[filesystem] Failed to listen on vsock port %d: %v", FILESYSTEM_PORT, err)
	}
	defer listener.Close()

	log.Printf("[filesystem] Listening on vsock port %d", FILESYSTEM_PORT)

	// Create gRPC server
	grpcServer := grpc.NewServer()
	filesystemServer := filesystem.NewServer(VERSION, startTime)
	fspb.RegisterFilesystemServiceServer(grpcServer, filesystemServer)

	// Signal ready AFTER we start serving
	go func() {
		time.Sleep(10 * time.Millisecond)
		ready <- "filesystem"
	}()

	// Serve until context is cancelled
	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("[filesystem] Service ready")
	if err := grpcServer.Serve(listener); err != nil {
		log.Printf("[filesystem] gRPC server error: %v", err)
	}
}

// =============================================================================
// Process Control Service
// =============================================================================

// startProcessService starts the Process Control gRPC service
func startProcessService(ctx context.Context, ready chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Listen on vsock
	listener, err := vsock.Listen(PROCESS_PORT, nil)
	if err != nil {
		log.Fatalf("[process] Failed to listen on vsock port %d: %v", PROCESS_PORT, err)
	}
	defer listener.Close()

	log.Printf("[process] Listening on vsock port %d", PROCESS_PORT)

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Placeholder start function - in real usage, vminitd will set this up
	startProcessFn := func() (int32, error) {
		return 0, fmt.Errorf("process service running standalone - no process start function configured")
	}

	processServer := processcontrol.NewServer(startProcessFn, VERSION, startTime)
	procpb.RegisterProcessServiceServer(grpcServer, processServer)

	// Signal ready AFTER we start serving
	go func() {
		time.Sleep(10 * time.Millisecond)
		ready <- "process"
	}()

	// Serve until context is cancelled
	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("[process] Service ready")
	if err := grpcServer.Serve(listener); err != nil {
		log.Printf("[process] gRPC server error: %v", err)
	}
}

// =============================================================================
// Main Entry Point
// =============================================================================

func main() {
	log.SetPrefix("[arca-services] ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	log.Printf("Arca Services v%s starting...", VERSION)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel for services to signal readiness
	ready := make(chan string, 3)
	var wg sync.WaitGroup

	// Start all services as goroutines
	wg.Add(3)
	go startWireGuardService(ctx, ready, &wg)
	go startFilesystemService(ctx, ready, &wg)
	go startProcessService(ctx, ready, &wg)

	// Wait for all 3 services to signal ready
	readyCount := 0
	for readyCount < 3 {
		name := <-ready
		readyCount++
		log.Printf("Service ready: %s (%d/3)", name, readyCount)
	}

	// All services ready - open the ready signal port
	readyListener, err := vsock.Listen(READY_PORT, nil)
	if err != nil {
		log.Fatalf("Failed to listen on ready port %d: %v", READY_PORT, err)
	}
	defer readyListener.Close()

	log.Printf("=== ALL SERVICES READY - listening on vsock:%d ===", READY_PORT)

	// Accept connections on ready port (vminitd connects to confirm ready)
	go func() {
		for {
			conn, err := readyListener.Accept()
			if err != nil {
				return // Listener closed
			}
			conn.Close() // Just accept and close - connection success = ready
		}
	}()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutting down...")
	cancel() // Signal all services to stop

	// Wait for services to exit
	wg.Wait()
	log.Println("Arca Services stopped")
}
