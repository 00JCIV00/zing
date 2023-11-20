# zing

A small Zig tool for crafting datagrams and interacting with networks, based on IETF specifications.

# Overview
This project is an experiment to learn more about the basics of how network datagrams (Frames, Packets, and Segments/UDP Datagrams) work by coding parts of the IETF spec in Zig. This is a continuation of [packt-lib](https://github.com/00JCIV00/packt-lib), a similar project written in Kotlin. I've moved to Zig to help myself understand the lower level intricasies of networking and bit/byte manipulation. Optimally, the tool will allow users to manipulate network directly through the library, a DSL (.json, .toml?, and .zon?), or an interactive shell.

# Goals
- [x] Replicate Basic Networking Headers:
	- [x] IP
	- [x] ICMP
	- [x] UDP
	- [x] TCP
	- [x] Ethernet
- [ ] Replicate Basic Networking Addresses:
	- [x] IPv4
	- [ ] IPv6
	- [x] MAC
- [x] Add data to Networking Headers to create Datagrams
- [x] Craft & Send Datagrams on an interface:

| Datagram | Layer | Craft | Send |
|---|---|---|---|
| Ethernet | 2 | Y | Y |
| WiFi | 2 | Y | N |
| Bluetooth | 2 | N | N |
| IP | 3 | Y | Y |
| ICMP | 3 | Y | Y |
| ARP | 3 | Y | Y |
| UDP | 4 | Y | Y |
| TCP | 4 | Y | Y |

- [ ] Implement Sending a Stream of Datagrams
- [x] Implement Receiving Datagrams
- [x] Implement Basic Connection Protocol Handling
	- [x] ICMP
	- [x] ARP
	- [x] TCP
	
- [x] Network Scanning tools
- [ ] File Transfer tools

# Resources
- [IP](https://datatracker.ietf.org/doc/html/rfc791)
- [ARP](https://datatracker.ietf.org/doc/html/rfc826)
- [ICMP](https://datatracker.ietf.org/doc/html/rfc792)
- [UDP](https://datatracker.ietf.org/doc/html/rfc768)
- [TCP](https://www.ietf.org/rfc/rfc9293.html)
