// Package filesystem provides filesystem services for Arca containers
//
// This service runs inside each container's Linux VM (vsock:51821) and provides:
// - Filesystem sync (flush buffers)
// - OverlayFS upperdir enumeration (for docker diff)
// - Archive operations (tar creation/extraction for buildx)
package filesystem

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	pb "github.com/vas-solutus/arca-services/proto/filesystem"
)

// Server implements the FilesystemService
type Server struct {
	pb.UnimplementedFilesystemServiceServer
	version   string
	startTime time.Time
}

// NewServer creates a new FilesystemService server
func NewServer(version string, startTime time.Time) *Server {
	return &Server{
		version:   version,
		startTime: startTime,
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

// findContainerPID finds the PID of a container by searching /proc for ARCA_CONTAINER_ID
func findContainerPID(containerID string) (int, error) {
	entries, err := ioutil.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is numeric (PID)
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Read /proc/[pid]/environ to find ARCA_CONTAINER_ID
		environPath := filepath.Join("/proc", entry.Name(), "environ")
		environData, err := ioutil.ReadFile(environPath)
		if err != nil {
			continue
		}

		// environ is null-separated key=value pairs
		for _, env := range bytes.Split(environData, []byte{0}) {
			if bytes.HasPrefix(env, []byte("ARCA_CONTAINER_ID=")) {
				foundID := string(bytes.TrimPrefix(env, []byte("ARCA_CONTAINER_ID=")))
				if foundID == containerID {
					return pid, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("container PID not found for ID: %s", containerID)
}

// withMountNamespace executes a function inside a mount namespace
// Pattern similar to WireGuard's netns switching but for mount namespaces
func withMountNamespace(nsPath string, fn func() error) error {
	// Lock goroutine to OS thread for namespace operations
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Open current mount namespace to return to it later
	rootMntFd, err := unix.Open("/proc/self/ns/mnt", unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open root mount namespace: %w", err)
	}
	defer unix.Close(rootMntFd)

	// Open target mount namespace
	targetMntFd, err := unix.Open(nsPath, unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open target mount namespace: %w", err)
	}
	defer unix.Close(targetMntFd)

	// Enter target mount namespace
	if err := unix.Setns(targetMntFd, unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("failed to enter mount namespace: %w", err)
	}

	// Ensure we return to root namespace
	defer func() {
		if err := unix.Setns(rootMntFd, unix.CLONE_NEWNS); err != nil {
			log.Printf("Warning: failed to return to root mount namespace: %v", err)
		}
	}()

	// Execute the function inside the namespace
	return fn()
}

// SyncFilesystem flushes all filesystem buffers to disk
// Calls the sync() syscall to ensure all cached writes are persisted
func (s *Server) SyncFilesystem(ctx context.Context, req *pb.SyncFilesystemRequest) (*pb.SyncFilesystemResponse, error) {
	log.Printf("Syncing filesystem")

	// Call sync() syscall to flush all filesystem buffers
	unix.Sync()

	log.Printf("Filesystem sync complete")
	return &pb.SyncFilesystemResponse{
		Success: true,
	}, nil
}

// EnumerateUpperdir enumerates all files in the OverlayFS upperdir
// Returns added/modified files and whiteouts (deleted files)
// Much faster than full filesystem enumeration
func (s *Server) EnumerateUpperdir(ctx context.Context, req *pb.EnumerateUpperdirRequest) (*pb.EnumerateUpperdirResponse, error) {
	log.Printf("Enumerating OverlayFS upperdir at /mnt/vdb/upper")

	upperdirPath := "/mnt/vdb/upper"

	// Check if upperdir exists
	if _, err := os.Stat(upperdirPath); os.IsNotExist(err) {
		return &pb.EnumerateUpperdirResponse{
			Success: false,
			Error:   fmt.Sprintf("upperdir not found at %s", upperdirPath),
		}, nil
	}

	var entries []*pb.UpperdirEntry

	// Walk the upperdir and collect all entries
	err := filepath.Walk(upperdirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error walking %s: %v", path, err)
			return err
		}

		// Skip the upperdir root itself
		if path == upperdirPath {
			return nil
		}

		// Get path relative to upperdir (this is the container path)
		relPath, err := filepath.Rel(upperdirPath, path)
		if err != nil {
			return err
		}

		// Prepend "/" to make it an absolute container path
		containerPath := "/" + relPath

		// Determine entry type
		var entryType string
		var size int64
		mode := uint32(info.Mode())

		// Check for whiteout (character device 0/0)
		// OverlayFS uses whiteouts to mark deleted files
		if info.Mode()&os.ModeCharDevice != 0 {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && stat.Rdev == 0 {
				entryType = "whiteout"
				size = 0
				log.Printf("Found whiteout: %s", containerPath)
			} else {
				// Regular char device (not a whiteout)
				entryType = "file"
				size = info.Size()
			}
		} else if info.IsDir() {
			entryType = "dir"
			size = 0
		} else if info.Mode()&os.ModeSymlink != 0 {
			entryType = "symlink"
			size = 0
		} else {
			entryType = "file"
			size = info.Size()
		}

		// Add entry
		entries = append(entries, &pb.UpperdirEntry{
			Path:  containerPath,
			Type:  entryType,
			Size:  size,
			Mtime: info.ModTime().Unix(),
			Mode:  mode,
		})

		return nil
	})

	if err != nil {
		return &pb.EnumerateUpperdirResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to enumerate upperdir: %v", err),
		}, nil
	}

	log.Printf("Enumerated upperdir: %d entries", len(entries))
	return &pb.EnumerateUpperdirResponse{
		Success: true,
		Entries: entries,
	}, nil
}

// ReadArchive creates a tar archive of the specified path
// Works universally without requiring tar binary in container
// Used for GET /containers/{id}/archive endpoint (buildx)
func (s *Server) ReadArchive(ctx context.Context, req *pb.ReadArchiveRequest) (*pb.ReadArchiveResponse, error) {
	log.Printf("ReadArchive: container=%s path=%s", req.ContainerId, req.Path)

	// Resolve source path - always relative to container rootfs
	rootfsPath := fmt.Sprintf("/run/container/%s/rootfs", req.ContainerId)
	fullPath := filepath.Join(rootfsPath, req.Path)
	log.Printf("ReadArchive: Using container path: %s", fullPath)

	// Get file info for the path
	info, err := os.Lstat(fullPath)
	if err != nil {
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("path not found: %v", err),
		}, nil
	}

	// Create plain tar archive in memory (Docker CLI expects uncompressed tar)
	var buf bytes.Buffer
	tarWriter := tar.NewWriter(&buf)

	// Add files to tar
	err = addToTar(tarWriter, fullPath, filepath.Base(req.Path), info)
	if err != nil {
		tarWriter.Close()
		return &pb.ReadArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create tar: %v", err),
		}, nil
	}

	tarWriter.Close()

	// Create PathStat for response header
	stat := &pb.PathStat{
		Name:  info.Name(),
		Size:  info.Size(),
		Mode:  uint32(info.Mode()),
		Mtime: info.ModTime().Format(time.RFC3339),
	}

	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		if err == nil {
			stat.LinkTarget = target
		}
	}

	log.Printf("ReadArchive complete: %d bytes", buf.Len())
	return &pb.ReadArchiveResponse{
		Success: true,
		TarData: buf.Bytes(),
		Stat:    stat,
	}, nil
}

// addToTar recursively adds files to a tar archive
func addToTar(tw *tar.Writer, fullPath, nameInTar string, info os.FileInfo) error {
	// Create tar header
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = nameInTar

	// Handle symlinks
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		if err != nil {
			return err
		}
		header.Linkname = target
	}

	// Write header
	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	// If it's a regular file, write contents
	if info.Mode().IsRegular() {
		file, err := os.Open(fullPath)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(tw, file); err != nil {
			return err
		}
	}

	// If it's a directory, recurse
	if info.IsDir() {
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			entryPath := filepath.Join(fullPath, entry.Name())
			entryInfo, err := entry.Info()
			if err != nil {
				return err
			}

			if err := addToTar(tw, entryPath, filepath.Join(nameInTar, entry.Name()), entryInfo); err != nil {
				return err
			}
		}
	}

	return nil
}

// WriteArchive extracts a tar archive to the specified path
// Works universally without requiring tar binary in container
// Used for PUT /containers/{id}/archive endpoint (buildx, k3d/kind)
// Supports both plain tar and gzip-compressed tar archives
func (s *Server) WriteArchive(ctx context.Context, req *pb.WriteArchiveRequest) (*pb.WriteArchiveResponse, error) {
	log.Printf("WriteArchive: container=%s path=%s size=%d", req.ContainerId, req.Path, len(req.TarData))

	// Resolve destination path - always relative to container rootfs
	rootfsPath := fmt.Sprintf("/run/container/%s/rootfs", req.ContainerId)
	destPath := filepath.Join(rootfsPath, req.Path)
	log.Printf("WriteArchive: Using container path: %s", destPath)

	// Ensure destination exists
	if err := os.MkdirAll(destPath, 0755); err != nil {
		return &pb.WriteArchiveResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create destination: %v", err),
		}, nil
	}

	// Create a reader for the tar data
	// Detect if gzip compressed by checking magic bytes (0x1f 0x8b)
	var tarReader *tar.Reader
	if len(req.TarData) >= 2 && req.TarData[0] == 0x1f && req.TarData[1] == 0x8b {
		// Gzip compressed tar
		log.Printf("Detected gzip-compressed tar archive")
		gzReader, err := gzip.NewReader(bytes.NewReader(req.TarData))
		if err != nil {
			return &pb.WriteArchiveResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to decompress gzip: %v", err),
			}, nil
		}
		defer gzReader.Close()
		tarReader = tar.NewReader(gzReader)
	} else {
		// Plain tar (not compressed) - used by Docker CLI and k3d/kind
		log.Printf("Detected plain tar archive (not compressed)")
		tarReader = tar.NewReader(bytes.NewReader(req.TarData))
	}
	filesExtracted := 0
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &pb.WriteArchiveResponse{
				Success: false,
				Error:   fmt.Sprintf("failed to read tar: %v", err),
			}, nil
		}

		// Security: prevent directory traversal
		if strings.Contains(header.Name, "..") {
			log.Printf("WriteArchive: SKIPPING file with '..' in path: %s", header.Name)
			continue
		}

		targetPath := filepath.Join(destPath, header.Name)
		log.Printf("WriteArchive: Processing entry: name=%s type=%d mode=%o size=%d -> targetPath=%s",
			header.Name, header.Typeflag, header.Mode, header.Size, targetPath)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create directory: %v", err),
				}, nil
			}

		case tar.TypeReg:
			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create parent directory: %v", err),
				}, nil
			}

			// Write file
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create file: %v", err),
				}, nil
			}

			bytesWritten, err := io.Copy(outFile, tarReader)
			if err != nil {
				outFile.Close()
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to write file: %v", err),
				}, nil
			}
			outFile.Close()
			filesExtracted++
			log.Printf("WriteArchive: Wrote file: %s (%d bytes, mode=%o)", targetPath, bytesWritten, header.Mode)

		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, targetPath); err != nil && !os.IsExist(err) {
				return &pb.WriteArchiveResponse{
					Success: false,
					Error:   fmt.Sprintf("failed to create symlink: %v", err),
				}, nil
			}
		}
	}

	log.Printf("WriteArchive complete: %d files extracted to %s", filesExtracted, destPath)
	return &pb.WriteArchiveResponse{
		Success: true,
	}, nil
}

// CreateBindMount creates a bind mount from source to target
// Works like "mount --bind /source /target" inside the container
// Used for file bind mounts (VirtioFS only supports directory shares)
func (s *Server) CreateBindMount(ctx context.Context, req *pb.CreateBindMountRequest) (*pb.CreateBindMountResponse, error) {
	log.Printf("CreateBindMount: containerID=%s source=%s target=%s readOnly=%v", req.ContainerId, req.Source, req.Target, req.ReadOnly)

	// Find container PID by searching /proc for ARCA_CONTAINER_ID environment variable
	containerPID, err := findContainerPID(req.ContainerId)
	if err != nil {
		errMsg := fmt.Sprintf("failed to find container PID: %v", err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateBindMountResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}
	log.Printf("✓ Found container PID: %d", containerPID)

	// Resolve target path to absolute VM path
	// Target is container-relative (e.g., "/test.txt"), resolve to VM path (e.g., "/run/container/{id}/rootfs/test.txt")
	targetAbsolute := fmt.Sprintf("/run/container/%s/rootfs%s", req.ContainerId, req.Target)
	log.Printf("Resolved target path: %s -> %s", req.Target, targetAbsolute)

	// All bind mount operations must happen inside the container's mount namespace
	// The source file is mounted via VirtioFS inside the container's mount namespace
	// The target file must be created inside the container's mount namespace
	mntNsPath := fmt.Sprintf("/proc/%d/ns/mnt", containerPID)
	log.Printf("Will perform all operations in container mount namespace: %s", mntNsPath)

	// Perform all operations inside the container's mount namespace
	err = withMountNamespace(mntNsPath, func() error {
		log.Printf("Inside container mount namespace")

		// Validate source exists
		sourceInfo, err := os.Stat(req.Source)
		if err != nil {
			log.Printf("ERROR: source path does not exist: %v", err)
			return fmt.Errorf("source path does not exist: %w", err)
		}
		log.Printf("✓ Source exists: %s (isDir=%v, size=%d)", req.Source, sourceInfo.IsDir(), sourceInfo.Size())

		// Ensure parent directory of target exists
		targetParent := filepath.Dir(targetAbsolute)
		if err := os.MkdirAll(targetParent, 0755); err != nil {
			log.Printf("ERROR: failed to create target parent directory: %v", err)
			return fmt.Errorf("failed to create target parent directory: %w", err)
		}
		log.Printf("✓ Target parent directory exists: %s", targetParent)

		// Check if target exists
		targetInfo, err := os.Stat(targetAbsolute)
		if err != nil {
			if os.IsNotExist(err) {
				// Create target matching source type
				if sourceInfo.IsDir() {
					log.Printf("Creating target directory: %s", targetAbsolute)
					if err := os.Mkdir(targetAbsolute, 0755); err != nil {
						log.Printf("ERROR: failed to create target directory: %v", err)
						return fmt.Errorf("failed to create target directory: %w", err)
					}
					log.Printf("✓ Target directory created")
				} else {
					// Create empty file
					log.Printf("Creating target file: %s", targetAbsolute)
					f, err := os.Create(targetAbsolute)
					if err != nil {
						log.Printf("ERROR: failed to create target file: %v", err)
						return fmt.Errorf("failed to create target file: %w", err)
					}
					f.Close()
					log.Printf("✓ Target file created")
				}
			} else {
				log.Printf("ERROR: failed to stat target: %v", err)
				return fmt.Errorf("failed to stat target: %w", err)
			}
		} else {
			log.Printf("✓ Target already exists: isDir=%v", targetInfo.IsDir())
			// Target exists - verify types match
			if sourceInfo.IsDir() != targetInfo.IsDir() {
				log.Printf("ERROR: source and target type mismatch")
				return fmt.Errorf("source and target must both be files or both be directories")
			}
		}

		// Perform bind mount using syscall (we're already in the namespace)
		log.Printf("Performing bind mount: %s -> %s", req.Source, targetAbsolute)
		if err := unix.Mount(req.Source, targetAbsolute, "", unix.MS_BIND, ""); err != nil {
			log.Printf("ERROR: failed to bind mount: %v", err)
			return fmt.Errorf("failed to bind mount: %w", err)
		}
		log.Printf("✓ Bind mount successful")

		// If read-only, remount with read-only flag
		if req.ReadOnly {
			log.Printf("Remounting as read-only...")
			if err := unix.Mount("", targetAbsolute, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
				log.Printf("ERROR: failed to remount as read-only: %v", err)
				return fmt.Errorf("failed to remount as read-only: %w", err)
			}
			log.Printf("✓ Remounted as read-only")
		}

		log.Printf("Bind mount created successfully: %s -> %s (container path: %s)", req.Source, targetAbsolute, req.Target)
		return nil
	})

	if err != nil {
		return &pb.CreateBindMountResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &pb.CreateBindMountResponse{
		Success: true,
	}, nil
}

// CreateVolumeOverlay creates an OverlayFS mount for a volume
// This overlays an EXT4 upper layer on top of a VirtioFS lower layer
// Provides full POSIX compliance (Unix sockets, chmod) for volumes
// Used for k3d/kind support where volumes need Unix socket support
//
// Note: This is called BEFORE container.start(), so the container process (vmexec)
// doesn't exist yet. We work in the VM's root namespace, where:
// - VirtioFS devices are available but may not be mounted yet
// - EXT4 block devices are already mounted by vminitd
// - /run/container/{id}/rootfs is the prepared rootfs for the container
func (s *Server) CreateVolumeOverlay(ctx context.Context, req *pb.CreateVolumeOverlayRequest) (*pb.CreateVolumeOverlayResponse, error) {
	log.Printf("CreateVolumeOverlay: container=%s lower=%s device=%s target=%s tag=%s",
		req.ContainerId, req.LowerPath, req.UpperDevice, req.Target, req.VirtiofsTag)

	// Use the container's existing writable.ext4 filesystem for overlay upper/work directories
	// This is already mounted by vminitd at /mnt/vdb (or similar path)
	// We create subdirectories there for each volume overlay, avoiding the need for extra block devices

	// Find the writable mount path (look for mounted EXT4 on /dev/vdb)
	writableMountPath, err := findWritableMountPath()
	if err != nil {
		errMsg := fmt.Sprintf("failed to find writable mount path: %v", err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateVolumeOverlayResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}
	log.Printf("Found writable mount at: %s", writableMountPath)

	// Create a unique subdirectory for this volume overlay
	// Use volume name from the request (e.g., k3d-k3s-default-images)
	volumeName := filepath.Base(req.UpperDevice)
	upperBasePath := filepath.Join(writableMountPath, "volume-overlays", volumeName)
	log.Printf("Using upper base path: %s (volume: %s)", upperBasePath, volumeName)

	// Create upper and work directories on the EXT4 filesystem
	upperDir := filepath.Join(upperBasePath, "upper")
	workDir := filepath.Join(upperBasePath, "work")

	if err := os.MkdirAll(upperDir, 0755); err != nil {
		errMsg := fmt.Sprintf("failed to create upper directory: %v", err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateVolumeOverlayResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}
	if err := os.MkdirAll(workDir, 0755); err != nil {
		errMsg := fmt.Sprintf("failed to create work directory: %v", err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateVolumeOverlayResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}
	log.Printf("✓ Created upper=%s work=%s", upperDir, workDir)

	// Resolve target path to absolute VM path
	// /run/container/{id}/rootfs is prepared by vminitd before container starts
	targetAbsolute := fmt.Sprintf("/run/container/%s/rootfs%s", req.ContainerId, req.Target)
	log.Printf("Resolved target path: %s -> %s", req.Target, targetAbsolute)

	// Ensure target directory exists
	if err := os.MkdirAll(targetAbsolute, 0755); err != nil {
		errMsg := fmt.Sprintf("failed to create target directory: %v", err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateVolumeOverlayResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}
	log.Printf("✓ Target directory exists: %s", targetAbsolute)

	// Mount VirtioFS at a SEPARATE path (not in container rootfs)
	// This is called BEFORE container.start(), so vmexec hasn't run yet.
	// We mount VirtioFS ourselves at /mnt/virtiofs-volumes/{tag} and use that as the lower layer.
	// This avoids race conditions with vmexec and EBUSY conflicts.
	virtiofsLowerPath := fmt.Sprintf("/mnt/virtiofs-volumes/%s", req.VirtiofsTag)
	log.Printf("Mounting VirtioFS at separate path: %s (tag: %s)", virtiofsLowerPath, req.VirtiofsTag)

	// Create the mount point directory
	if err := os.MkdirAll(virtiofsLowerPath, 0755); err != nil {
		errMsg := fmt.Sprintf("failed to create VirtioFS mount point: %v", err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateVolumeOverlayResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}

	// Mount VirtioFS using the tag
	// VirtioFS uses the tag as the "device" name for the mount
	if err := unix.Mount(req.VirtiofsTag, virtiofsLowerPath, "virtiofs", 0, ""); err != nil {
		errMsg := fmt.Sprintf("failed to mount VirtioFS (tag=%s): %v", req.VirtiofsTag, err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateVolumeOverlayResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}
	log.Printf("✓ VirtioFS mounted at %s", virtiofsLowerPath)

	// The actual lower path for OverlayFS is within the VirtioFS mount
	// Original lowerPath: /run/container/{id}/rootfs/mnt/arca-volumes/{hash}/data
	// We need: /mnt/virtiofs-volumes/{tag}/data (since VirtioFS root is the volume directory)
	actualLowerPath := filepath.Join(virtiofsLowerPath, "data")
	log.Printf("Using actual lower path for OverlayFS: %s", actualLowerPath)

	// Verify the lower path exists
	if _, err := os.Stat(actualLowerPath); err != nil {
		errMsg := fmt.Sprintf("lower path not accessible after VirtioFS mount: %s: %v", actualLowerPath, err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateVolumeOverlayResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}
	log.Printf("✓ Lower path accessible: %s", actualLowerPath)

	// Build OverlayFS options
	// lowerdir: VirtioFS mount (read-only access to host files)
	// upperdir: EXT4 mount (writable, provides POSIX compliance)
	// workdir: EXT4 mount (required by OverlayFS)
	overlayOpts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
		actualLowerPath, upperDir, workDir)
	log.Printf("OverlayFS options: %s", overlayOpts)

	// Create OverlayFS mount in the VM's root namespace
	// This mount will be visible to the container process when it starts
	log.Printf("Creating OverlayFS mount at %s", targetAbsolute)
	if err := unix.Mount("overlay", targetAbsolute, "overlay", 0, overlayOpts); err != nil {
		errMsg := fmt.Sprintf("failed to mount overlayfs: %v", err)
		log.Printf("ERROR: %s", errMsg)
		return &pb.CreateVolumeOverlayResponse{
			Success: false,
			Error:   errMsg,
		}, nil
	}
	log.Printf("✓ OverlayFS mounted successfully at %s", targetAbsolute)

	log.Printf("CreateVolumeOverlay complete: %s mounted with OverlayFS", req.Target)
	return &pb.CreateVolumeOverlayResponse{
		Success: true,
	}, nil
}

// findWritableMountPath finds where the container's writable.ext4 is mounted
// This is always /dev/vdb, which vminitd mounts at a predictable location
// Returns the mount path (e.g., /mnt/vdb) or an error if not found
func findWritableMountPath() (string, error) {
	// Read /proc/mounts to find where /dev/vdb is mounted
	data, err := ioutil.ReadFile("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("failed to read /proc/mounts: %w", err)
	}

	// Parse mount entries looking for /dev/vdb
	// Format: device mountpoint fstype options dump pass
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mountpoint := fields[1]

		// Look for /dev/vdb specifically - this is the container's writable filesystem
		if device == "/dev/vdb" {
			log.Printf("Found writable device mount: %s at %s", device, mountpoint)
			return mountpoint, nil
		}
	}

	// /dev/vdb not found - this shouldn't happen as vminitd always mounts it
	return "", fmt.Errorf("/dev/vdb not found in /proc/mounts - writable filesystem not mounted")
}

// StatPath checks if a path exists and returns its metadata
// Used for HEAD requests on archive endpoint
func (s *Server) StatPath(ctx context.Context, req *pb.StatPathRequest) (*pb.StatPathResponse, error) {
	log.Printf("StatPath: container=%s path=%s", req.ContainerId, req.Path)

	// Resolve path - always relative to container rootfs
	rootfsPath := fmt.Sprintf("/run/container/%s/rootfs", req.ContainerId)
	fullPath := filepath.Join(rootfsPath, req.Path)
	log.Printf("StatPath: Using container path: %s", fullPath)

	// Get file info
	info, err := os.Lstat(fullPath)
	if err != nil {
		return &pb.StatPathResponse{
			Success: false,
			Error:   fmt.Sprintf("path not found: %v", err),
		}, nil
	}

	// Create PathStat
	stat := &pb.PathStat{
		Name:  info.Name(),
		Size:  info.Size(),
		Mode:  uint32(info.Mode()),
		Mtime: info.ModTime().Format(time.RFC3339),
	}

	// Handle symlinks
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		if err == nil {
			stat.LinkTarget = target
		}
	}

	log.Printf("StatPath complete: %s (mode=%o, size=%d)", fullPath, stat.Mode, stat.Size)
	return &pb.StatPathResponse{
		Success: true,
		Stat:    stat,
	}, nil
}
