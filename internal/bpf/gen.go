//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -go-package reflector -output-dir reflector -target amd64 -verbose Reflector reflector.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -go-package reflector -output-dir reflector -target arm64 -verbose Reflector reflector.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -go-package sender -output-dir sender -target amd64 -verbose Sender sender.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -go-package sender -output-dir sender -target arm64 -verbose Sender sender.bpf.c

package stamp
