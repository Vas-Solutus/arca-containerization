// Package processcontrol provides process lifecycle control for container init processes
//
// This service runs inside each container's Linux VM and allows external orchestration
// of the container's init process, enabling pre-start setup (rootfs, networking, etc.)
// before the container process begins execution.
package processcontrol

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/vas-solutus/arca-services/proto/process"
)

// Server implements the ProcessService
type Server struct {
	pb.UnimplementedProcessServiceServer

	mu             sync.Mutex
	state          string // "waiting", "running", "exited"
	pid            int32
	exitCode       int32
	processStarted chan struct{}
	startProcessFn func() (int32, error) // Function to actually start the process
	version        string
	startTime      time.Time
}

// NewServer creates a new ProcessService server
//
// The startProcessFn is called when the StartProcess RPC is received.
// It should start the container's init process and return the PID.
func NewServer(startProcessFn func() (int32, error), version string, startTime time.Time) *Server {
	return &Server{
		state:          "waiting",
		processStarted: make(chan struct{}),
		startProcessFn: startProcessFn,
		version:        version,
		startTime:      startTime,
	}
}

// Ready returns service readiness status
// Used by vminitd to verify service is fully initialized before allowing container creation
func (s *Server) Ready(ctx context.Context, req *pb.ReadyRequest) (*pb.ReadyResponse, error) {
	return &pb.ReadyResponse{
		Ready:    true,
		Version:  s.version,
		UptimeMs: time.Since(s.startTime).Milliseconds(),
	}, nil
}

// StartProcess starts the container's init process
//
// This RPC is called by the external orchestrator after all boot-time setup
// (OverlayFS mounting, network configuration, etc.) is complete.
func (s *Server) StartProcess(ctx context.Context, req *pb.StartProcessRequest) (*pb.StartProcessResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if already started
	if s.state != "waiting" {
		return &pb.StartProcessResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("process already in state: %s", s.state),
		}, nil
	}

	log.Printf("StartProcess RPC received - starting container init process...")

	// Call the start function
	pid, err := s.startProcessFn()
	if err != nil {
		log.Printf("Failed to start process: %v", err)
		return &pb.StartProcessResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to start process: %v", err),
		}, nil
	}

	s.state = "running"
	s.pid = pid
	close(s.processStarted)

	log.Printf("Container init process started with PID %d", pid)

	return &pb.StartProcessResponse{
		Success: true,
		Pid:     pid,
	}, nil
}

// GetProcessStatus returns the current process status
func (s *Server) GetProcessStatus(ctx context.Context, req *pb.GetProcessStatusRequest) (*pb.GetProcessStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &pb.GetProcessStatusResponse{
		State:    s.state,
		Pid:      s.pid,
		ExitCode: s.exitCode,
	}, nil
}

// WaitForStart blocks until StartProcess RPC is called
//
// This is used by vminitd to block the boot process until the external
// orchestrator signals that boot-time setup is complete.
func (s *Server) WaitForStart() {
	<-s.processStarted
}

// MarkExited updates state when process exits
//
// This should be called by vminitd when the container process exits.
func (s *Server) MarkExited(exitCode int32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = "exited"
	s.exitCode = exitCode
	log.Printf("Container process exited with code %d", exitCode)
}

// ListProcesses reads /proc to list all running processes
//
// Returns process information in ps-compatible format for Docker top API.
// This avoids the race condition of running /bin/ps inside the container.
//
// IMPORTANT: Filters out root namespace processes (vminitd, services, kernel threads).
// Since we have 1 container per VM, all non-root-namespace processes are container processes.
func (s *Server) ListProcesses(ctx context.Context, req *pb.ListProcessesRequest) (*pb.ListProcessesResponse, error) {
	// List all processes NOT in the root namespace
	// Since we have 1 container per VM, these are all container processes
	processes, err := listContainerProcesses()
	if err != nil {
		return nil, fmt.Errorf("failed to list container processes: %w", err)
	}

	// Return in ps -ef format
	// Columns: UID PID PPID C STIME TTY TIME CMD
	titles := []string{"UID", "PID", "PPID", "C", "STIME", "TTY", "TIME", "CMD"}

	return &pb.ListProcessesResponse{
		Titles:    titles,
		Processes: processes,
	}, nil
}

// listContainerProcesses reads /proc and filters out root namespace processes
// Returns only processes in the container's namespace (since 1 container per VM).
func listContainerProcesses() ([]*pb.ProcessInfo, error) {
	// Get the service's PID namespace (this is the root namespace)
	servicePID := os.Getpid()
	rootNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", servicePID))
	if err != nil {
		return nil, fmt.Errorf("failed to read root PID namespace: %w", err)
	}

	// Read /proc directory to find all PIDs
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	// First pass: build a map of root namespace PID -> container namespace PID
	// This is needed to translate PPIDs correctly
	pidTranslation := make(map[string]string)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// Check if this process is in the root namespace
		procNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
		if err != nil {
			continue
		}

		// Skip root namespace processes
		if procNS == rootNS {
			continue
		}

		// Read NSpid from status to get container-namespace PID
		statusPath := fmt.Sprintf("/proc/%d/status", pid)
		statusData, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "NSpid:") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					rootPID := fields[1]      // Root namespace PID
					containerPID := fields[len(fields)-1]  // Container namespace PID
					pidTranslation[rootPID] = containerPID
				}
				break
			}
		}
	}

	// Second pass: collect process information
	var processes []*pb.ProcessInfo

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pidStr := entry.Name()
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// Check if this process is in the root namespace
		procNS, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid))
		if err != nil {
			continue
		}

		// Skip processes in the root namespace
		if procNS == rootNS {
			continue
		}

		// Read process information with PID translation
		procInfo, err := readProcessInfo(pidStr, pidTranslation)
		if err != nil {
			// Process may have exited or unreadable, skip it
			continue
		}

		processes = append(processes, &pb.ProcessInfo{
			Values: procInfo,
		})
	}

	return processes, nil
}

// readProcessInfo reads process information from /proc/[pid]
// pidTranslation maps root namespace PIDs to container namespace PIDs
func readProcessInfo(pid string, pidTranslation map[string]string) ([]string, error) {
	// Read /proc/[pid]/stat for basic process info
	statPath := filepath.Join("/proc", pid, "stat")
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return nil, err
	}

	// Parse stat file: pid (comm) state ppid ...
	statStr := string(statData)

	// Find the command name (enclosed in parentheses)
	commStart := strings.Index(statStr, "(")
	commEnd := strings.LastIndex(statStr, ")")
	if commStart == -1 || commEnd == -1 {
		return nil, fmt.Errorf("invalid stat format")
	}

	// Split the stat fields (after the command name)
	afterComm := strings.Fields(statStr[commEnd+2:])
	if len(afterComm) < 11 {
		return nil, fmt.Errorf("insufficient stat fields")
	}

	ppid := afterComm[0]  // PPID in root namespace
	// state := afterComm[0] // We could use this if needed
	utime := afterComm[11]
	stime := afterComm[12]

	// Read /proc/[pid]/cmdline for full command
	cmdlinePath := filepath.Join("/proc", pid, "cmdline")
	cmdlineData, err := os.ReadFile(cmdlinePath)
	var cmdline string
	if err == nil && len(cmdlineData) > 0 {
		// cmdline uses null bytes as separators
		cmdline = strings.ReplaceAll(string(cmdlineData), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
	}
	if cmdline == "" {
		// Fall back to comm from stat
		cmdline = statStr[commStart+1 : commEnd]
	}

	// Read /proc/[pid]/status for UID
	statusPath := filepath.Join("/proc", pid, "status")
	statusData, err := os.ReadFile(statusPath)
	uid := "0" // default to root
	if err == nil {
		for _, line := range strings.Split(string(statusData), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					uid = fields[1]
					break
				}
			}
		}
	}

	// Translate PIDs from root namespace to container namespace
	containerPID := pidTranslation[pid]
	if containerPID == "" {
		containerPID = pid // fallback to root namespace PID
	}

	containerPPID := pidTranslation[ppid]
	if containerPPID == "" {
		containerPPID = "0" // Parent not in container namespace (e.g., init's parent)
	}

	// Calculate total CPU time (utime + stime)
	// These are in clock ticks, convert to seconds (assuming 100 ticks/second)
	utimeInt, _ := strconv.ParseInt(utime, 10, 64)
	stimeInt, _ := strconv.ParseInt(stime, 10, 64)
	totalTicks := utimeInt + stimeInt
	totalSeconds := totalTicks / 100

	minutes := totalSeconds / 60
	seconds := totalSeconds % 60
	timeStr := fmt.Sprintf("00:%02d:%02d", minutes, seconds)

	// Build ps -ef format output
	// UID PID PPID C STIME TTY TIME CMD
	return []string{
		uid,            // UID
		containerPID,   // PID (container namespace)
		containerPPID,  // PPID (container namespace)
		"0",            // C (CPU utilization - we could calculate this from stat)
		"?",            // STIME (start time - we could read from /proc/[pid]/stat field 21)
		"?",            // TTY
		timeStr,        // TIME
		cmdline,        // CMD
	}, nil
}
