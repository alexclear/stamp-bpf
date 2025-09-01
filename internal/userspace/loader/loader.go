package loader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/reflector"
	"github.com/viktordoronin/stamp-bpf/internal/bpf/sender"
	"github.com/viktordoronin/stamp-bpf/internal/userspace/stamp"
)

const pinPath = "/sys/fs/bpf/stamp-bpf"

type fd interface {
	Close() error
}

type senderFD struct {
	Objs sender.SenderObjects
}

func (s senderFD) Close() {
	s.Objs.Close()
}

type reflectorFD struct {
	Objs reflector.ReflectorObjects
}

func (s reflectorFD) Close() {
	s.Objs.Close()
}

func LoadSender(args stamp.Args) senderFD {
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

	// Create pin directory
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		log.Fatalf("Error creating pin directory: %v", err)
	}

	// Pin TCX programs
	if err := objs.SenderOut.Pin(filepath.Join(pinPath, "sender_out")); err != nil {
		log.Fatalf("Error pinning the egress program: %v", err)
	}
	if err := objs.SenderIn.Pin(filepath.Join(pinPath, "sender_in")); err != nil {
		log.Fatalf("Error pinning the ingress program: %v", err)
	}

	// Programs are pinned, no links to return

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

	// Set disable TAI flag
	if args.DisableTAI {
		objs.Disable_tai.Set(uint16(1))
	} else {
		objs.Disable_tai.Set(uint16(0))
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
	fmt.Println()
	return senderFD{Objs: objs}
}

func LoadReflector(args stamp.Args) reflectorFD {
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

	// Create pin directory
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		log.Fatalf("Error creating pin directory: %v", err)
	}

	// Pin TCX programs
	if err := objs.ReflectorOut.Pin(filepath.Join(pinPath, "reflector_out")); err != nil {
		log.Fatalf("Error pinning the egress program: %v", err)
	}
	if err := objs.ReflectorIn.Pin(filepath.Join(pinPath, "reflector_in")); err != nil {
		log.Fatalf("Error pinning the ingress program: %v", err)
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

	// Set disable TAI flag
	if args.DisableTAI {
		objs.Disable_tai.Set(uint16(1))
	} else {
		objs.Disable_tai.Set(uint16(0))
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
	fmt.Println()
	return reflectorFD{Objs: objs}
}
