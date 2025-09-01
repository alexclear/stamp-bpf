package loader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/reflector"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/stamp"
)

// LoaderConfig holds configuration for the loader
type LoaderConfig struct {
	UseAnchors bool
	Anchor     link.Anchor
}

type fd interface {
	Close() error
}

type senderFD struct {
	Objs  sender.SenderObjects
	Links []link.Link
}

func (s senderFD) Close() {
	for _, l := range s.Links {
		if l != nil {
			l.Close()
		}
	}
	s.Objs.Close()
}

type reflectorFD struct {
	Objs  reflector.ReflectorObjects
	Links []link.Link
}

func (s reflectorFD) Close() {
	for _, l := range s.Links {
		if l != nil {
			l.Close()
		}
	}
	s.Objs.Close()
}

func LoadSender(args stamp.Args) senderFD {
	// Default config - use Head anchor
	config := LoaderConfig{
		UseAnchors: true,
		Anchor:     link.Head(),
	}

	return loadSenderWithConfig(args, config)
}

func loadSenderWithConfig(args stamp.Args, config LoaderConfig) senderFD {
	// Load TCX programs
	var objs sender.SenderObjects
	var opts = ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: 1}}
	err := sender.LoadSenderObjects(&objs, &opts)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("Verifier error: %+v\n", verr)
		}
		log.Fatalf("Error loading programs: %v", err)
	} else {
		fmt.Println("All programs successfully loaded and verified")
		if args.Debug == true {
			log.Print(objs.SenderOut.VerifierLog)
			log.Print(objs.SenderIn.VerifierLog)
		}
	}

	// populate globals
	ip := binary.LittleEndian.Uint32(args.Localaddr.To4())
	objs.Laddr.Set(ip)
	objs.S_port.Set(uint16(args.S_port))

	// Check if we need to adjust TAI
	if checkTAI() == true {
		objs.Tai.Set(uint16(1))
	} else {
		objs.Tai.Set(uint16(0))
	}

	// Check if we have clock syncing
	if checkSync() == false {
		if args.Sync == true || args.PTP == true {
			log.Fatalf("No clock syncing detected with --enforce-sync flag set, aborting")
		}
	} else {
		if checkPTP() == false && args.PTP == true {
			log.Fatalf("No PTP syncing detected with --enforce-ptp flag set, aborting")
		}
	}

	// Attach TCX programs
	var links []link.Link

	// No anchor manager needed - using direct attachment with anchor from config

	// Attach egress program
	var egressLink link.Link
	// Direct attachment with anchor from config
	egressLink, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.SenderOut,
		Attach:    ebpf.AttachTCXEgress,
		Interface: args.Dev.Index,
		Anchor:    config.Anchor,
	})
	if err != nil {
		log.Fatalf("Error attaching egress program: %v", err)
	}
	links = append(links, egressLink)

	// Attach ingress program
	var ingressLink link.Link
	// Direct attachment with anchor from config
	ingressLink, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.SenderIn,
		Attach:    ebpf.AttachTCXIngress,
		Interface: args.Dev.Index,
		Anchor:    config.Anchor,
	})
	if err != nil {
		log.Fatalf("Error attaching ingress program: %v", err)
	}
	links = append(links, ingressLink)

	fmt.Println()
	return senderFD{Objs: objs, Links: links}
}

func LoadReflector(args stamp.Args) reflectorFD {
	// Default config - use Head anchor
	config := LoaderConfig{
		UseAnchors: true,
		Anchor:     link.Head(),
	}

	return loadReflectorWithConfig(args, config)
}

func loadReflectorWithConfig(args stamp.Args, config LoaderConfig) reflectorFD {
	var objs reflector.ReflectorObjects
	var opts = ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: 1}}
	err := reflector.LoadReflectorObjects(&objs, &opts)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("Verifier error: %+v\n", verr)
		}
		log.Fatalf("Error loading programs: %v", err)
	} else {
		fmt.Println("All programs successfully loaded and verified")
		if args.Debug == true {
			log.Print(objs.ReflectorIn.VerifierLog)
			log.Print(objs.ReflectorOut.VerifierLog)
		}
	}

	// populate globals
	ip := binary.LittleEndian.Uint32(args.Localaddr.To4())
	objs.Laddr.Set(ip)
	objs.S_port.Set(uint16(args.S_port))

	// Check if we need to adjust TAI
	if checkTAI() == true {
		objs.Tai.Set(uint16(1))
	} else {
		objs.Tai.Set(uint16(0))
	}
	// Check if we have clock syncing
	if checkSync() == false {
		if args.Sync == true || args.PTP == true {
			log.Fatalf("No clock syncing detected with --enforce-sync flag set, aborting")
		}
	} else {
		if checkPTP() == false && args.PTP == true {
			log.Fatalf("No PTP syncing detected with --enforce-ptp flag set, aborting")
		}
	}

	// Attach TCX programs
	var links []link.Link

	// No anchor manager needed - using direct attachment with anchor from config

	// Attach egress program
	var egressLink link.Link
	// Direct attachment with anchor from config
	egressLink, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.ReflectorOut,
		Attach:    ebpf.AttachTCXEgress,
		Interface: args.Dev.Index,
		Anchor:    config.Anchor,
	})
	if err != nil {
		log.Fatalf("Error attaching egress program: %v", err)
	}
	links = append(links, egressLink)

	// Attach ingress program
	var ingressLink link.Link
	// Direct attachment with anchor from config
	ingressLink, err = link.AttachTCX(link.TCXOptions{
		Program:   objs.ReflectorIn,
		Attach:    ebpf.AttachTCXIngress,
		Interface: args.Dev.Index,
		Anchor:    config.Anchor,
	})
	if err != nil {
		log.Fatalf("Error attaching ingress program: %v", err)
	}
	links = append(links, ingressLink)

	fmt.Println()
	return reflectorFD{Objs: objs, Links: links}
}
