package dns

import (
	"log"
	"sync"
)

// DNSEntry represents a single DNS mapping (name/alias -> IP)
type DNSEntry struct {
	Name        string   // Container name
	ContainerID string   // Docker container ID
	IPAddress   string   // IP address on this network
	Aliases     []string // Additional DNS aliases
}

// Resolver resolves hostnames using local DNS mappings
// Mappings are updated incrementally via AddPeer/RemovePeer RPCs
type Resolver struct {
	// Map of network ID -> map of container name -> DNS entry
	networks map[string]map[string]*DNSEntry
	mu       sync.RWMutex
}

// NewResolver creates a new DNS resolver
func NewResolver() *Resolver {
	return &Resolver{
		networks: make(map[string]map[string]*DNSEntry),
	}
}

// AddEntry adds a DNS entry for a peer on a specific network
// Called by AddPeer RPC handler
func (r *Resolver) AddEntry(networkID, containerName, containerID, ipAddress string, aliases []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Ensure network map exists
	if r.networks[networkID] == nil {
		r.networks[networkID] = make(map[string]*DNSEntry)
	}

	// Add DNS entry
	r.networks[networkID][containerName] = &DNSEntry{
		Name:        containerName,
		ContainerID: containerID,
		IPAddress:   ipAddress,
		Aliases:     aliases,
	}

	log.Printf("[DNS] Added entry: %s -> %s (network %s, aliases: %v)",
		containerName, ipAddress, networkID, aliases)
}

// RemoveEntry removes a DNS entry for a peer on a specific network
// Called by RemovePeer RPC handler
func (r *Resolver) RemoveEntry(networkID, containerName string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.networks[networkID] != nil {
		delete(r.networks[networkID], containerName)
		log.Printf("[DNS] Removed entry: %s (network %s)", containerName, networkID)

		// Clean up empty network map
		if len(r.networks[networkID]) == 0 {
			delete(r.networks, networkID)
		}
	}
}

// Resolve queries the local DNS mappings to resolve a hostname
// Searches across all networks this container is attached to
// Returns IP address and true if found, empty string and false otherwise
func (r *Resolver) Resolve(hostname string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Search all networks for matching container name or alias
	for _, entries := range r.networks {
		// Check if hostname matches a container name
		if entry, ok := entries[hostname]; ok {
			log.Printf("[DNS] Resolved %s -> %s (container name)", hostname, entry.IPAddress)
			return entry.IPAddress, true
		}

		// Check if hostname matches an alias
		for _, entry := range entries {
			for _, alias := range entry.Aliases {
				if alias == hostname {
					log.Printf("[DNS] Resolved %s -> %s (alias for %s)",
						hostname, entry.IPAddress, entry.Name)
					return entry.IPAddress, true
				}
			}
		}
	}

	return "", false
}

// GetNetworkCount returns the number of networks with DNS entries
func (r *Resolver) GetNetworkCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.networks)
}

// GetTotalEntries returns the total number of DNS entries across all networks
func (r *Resolver) GetTotalEntries() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	total := 0
	for _, entries := range r.networks {
		total += len(entries)
	}
	return total
}
