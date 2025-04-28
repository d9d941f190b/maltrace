OUTPUT = ./output
CLANG = clang
BPFTOOL = $(shell which bpftool || /bin/false)
CFLAGS = -g -O2 -Wall -Wno-unused-variable -Wno-unused-function
# Paths
VMLINUXH = ./include/vmlinux.h
BPF_SRC = ./ebpf/tracers.c
BPF_OBJ = $(OUTPUT)/tracers.o

all: $(OUTPUT) $(BPF_OBJ) go-build

$(OUTPUT):
	mkdir -p $(OUTPUT)

# Generate vmlinux.h if needed
$(VMLINUXH):
	@echo "Generating vmlinux.h from kernel BTF"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUXH)

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(VMLINUXH)
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -I./include -c $(BPF_SRC) -o $(BPF_OBJ)

# Build Go program
go-build: $(BPF_OBJ)
	CGO_CFLAGS="-I/usr/include" CGO_LDFLAGS="-L/usr/lib64 -lelf -lz -lbpf" go build -o $(OUTPUT)/main ./main.go

run:
	sudo LD_LIBRARY_PATH=/usr/lib64 $(OUTPUT)/main

cat:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -rf $(OUTPUT)