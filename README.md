# maltrace
maltrace is an eBPF based malware analysis sandbox.

# Compiling


1. Clone the maltrace directory
2. Install go, follow [the official download page](https://go.dev/doc/install)
3. Install clang and libelf-dev if needed
```
apt install clang && apt install libelf-dev
```
4. In the same directory as maltrace clone *libbpf* from [GIthub](https://github.com/libbpf/libbpf)
```
git clone https://github.com/libbpf/libbpf

cd src
make
sudo make install
```
5. Run maltrace !


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