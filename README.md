# PDM eBPF

eBPF(TC-BPF) implementation of IPv6 PDM extension header([RFC8250](https://www.rfc-editor.org/rfc/rfc8250)). Since we attach the eBPF program to egress interface, this program uses tc-bpf.

## How to use 

1. Compile `pdm_kern.c` to get the BPF object file `pdm_kern.o`. To compile run `make` in the root folder of the project.
2. Attach the bpf object file to a interface.


### Example
1. Create a veth pair using iproute.
   ```bash
   sudo ip link add dev veth0 type veth peer name veth1
   sudo ip link set up dev veth0 
   sudo ip link set up dev veth1
   ```
2. Create a qdisc to attach the BPF object file
   ```bash
   sudo tc qdisc add dev veth0 clsact
   ```
3. Load the program to egress
   ```bash
   sudo tc filter add dev veth0 egress bpf direct-action obj pdm_kern.o sec pdm
   ```
4. check whether the program was attached or not
   ```bash
   sudo tc filter show dev veth0
   sudo tc filter show dev veth0 egress
   ```
   
   This should show something similar to the below snippet
   ```
   filter protocol all pref 49152 bpf chain 0
   filter protocol all pref 49152 bpf chain 0 handle 0x1 pdm_kern.o:[.pdm] direct-action not_in_hw id 11 tag ebe28a8e9a2e747f
   ```