# maltrace
maltrace is an eBPF based malware analysis sandbox.

# Compiling

You need to clone and compile *libbpf v1.5* locally.
```
git clone https://github.com/libbpf/libbpf
git checkout v1.5.0

cd src
make
sudo make install
```
Make sure filepaths in Makefile are correct.


After installing libbpf run:

```
make clean
make
```

then execute the file that is stored at
```
output/cmd
```