OUTPUT = /home/mimika/Desktop/bpf-dev/output/
CLANG = clang
BPFTOOL = $(shell which bpftool || /bin/false)
CFLAGS = -g -O2 -Wall -Wno-unused-variable -Wno-unused-function
# Paths
VMLINUXH = ./include/vmlinux.h
BPF_SRC = ./ebpf/programs/tracers.c
BPF_OBJ = $(OUTPUT)/tracers.o

all: $(OUTPUT) $(BPF_OBJ) go-build

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(VMLINUXH):
	@echo "Generating vmlinux.h from kernel BTF"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUXH)

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(VMLINUXH)
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -I./include -c $(BPF_SRC) -o $(BPF_OBJ)

LOCAL_LIBBPF_DIR = ./libbpf/src

# Build Go program
go-build: $(BPF_OBJ)
	CGO_CFLAGS="-I$(LOCAL_LIBBPF_DIR) " CGO_LDFLAGS="/usr/lib64/libbpf.a" go build -o maltrace ./cmd.go

run:
#	sudo LD_LIBRARY_PATH=/usr/lib64 $(OUTPUT)/main
cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -rf $(OUTPUT)
	rm -f maltrace