package anchor

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AnchorPosition defines the position of an anchor relative to other programs
type AnchorPosition int

const (
	// BeforeCilium positions the anchor before Cilium programs
	BeforeCilium AnchorPosition = iota
	// AfterCilium positions the anchor after Cilium programs
	AfterCilium
	// Generic creates a generic anchor not relative to any specific program
	Generic
)

// AnchorManager manages TCX anchors
type AnchorManager struct {
	mutex sync.RWMutex
}

// NewAnchorManager creates a new anchor manager
func NewAnchorManager() *AnchorManager {
	return &AnchorManager{}
}

// CreateAnchor creates a new TCX anchor
func (am *AnchorManager) CreateAnchor(iface string, direction ebpf.AttachType, position AnchorPosition) (link.Anchor, error) {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Try to create anchor relative to Cilium if requested
	if position == BeforeCilium || position == AfterCilium {
		anchor, err := am.createAnchorRelativeToCilium(iface, direction, position)
		if err == nil {
			return anchor, nil
		}
		log.Printf("Failed to create anchor relative to Cilium: %v, falling back to generic anchor", err)
	}

	// Create generic anchor
	anchor, err := am.createGenericAnchor(iface, direction)
	if err != nil {
		return nil, fmt.Errorf("failed to create generic anchor: %w", err)
	}

	return anchor, nil
}

// AttachToAnchor attaches a program to an anchor
func (am *AnchorManager) AttachToAnchor(anchor link.Anchor, prog *ebpf.Program, iface string, direction ebpf.AttachType) (link.Link, error) {
	// Get interface index
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", iface, err)
	}

	// Attach program to anchor using TCX
	link, err := link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    direction,
		Interface: ifaceObj.Index,
		Anchor:    anchor,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach program to anchor: %w", err)
	}

	return link, nil
}

// createAnchorRelativeToCilium creates an anchor relative to Cilium programs
func (am *AnchorManager) createAnchorRelativeToCilium(iface string, direction ebpf.AttachType, position AnchorPosition) (link.Anchor, error) {
	// This is a simplified implementation
	// In a full implementation, this would:
	// 1. Detect Cilium programs on the interface
	// 2. Create an anchor relative to those programs
	// 3. Return the anchor information

	// For now, we'll return an error to trigger the fallback to generic anchor
	return nil, fmt.Errorf("Cilium integration not fully implemented")
}

// createGenericAnchor creates a generic anchor not relative to any specific program
func (am *AnchorManager) createGenericAnchor(iface string, direction ebpf.AttachType) (link.Anchor, error) {
	// For a generic anchor, we'll use the Head() or Tail() anchor depending on the direction
	// This is a simplified implementation
	if direction == ebpf.AttachTCXIngress || direction == ebpf.AttachTCXEgress {
		// For ingress/egress, we'll use Head() to place our program at the beginning
		return link.Head(), nil
	}

	// Default to Head() anchor
	return link.Head(), nil
}
