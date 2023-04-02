# zacket-lib
A small Zig library to build and send basic packets based on IETF specifications.

# Overview
This project is an experiment to learn more about the basics of how packets work by coding parts of the IETF spec in Zig. This is a continuation of [packt-lib](https://github.com/00JCIV00/packt-lib), a similar project written in Kotlin. I've moved to Zig to help myself understand the lower level intricasies of networking and bit/byte manipulation. Optimally, the library will allow users to manipulate packets directly, through a DSL (.zon?), or from an interactive shell.

# Goals
- [ ] Replicate Basic Networking Headers:
	- [x] IP
	- [x] ICMP
	- [x] UDP
	- [x] TCP
	- [x] Ethernet
- [ ] Replicate Basic Networking Addresses:
	- [x] IPv4
	- [ ] IPv6
	- [x] MAC
- [ ] Add data to Networking Headers to create Packets
- [ ] Network Scanning tools
- [ ] File Transfer tools

# Resources
- [IP](https://datatracker.ietf.org/doc/html/rfc791)
- [ICMP](https://datatracker.ietf.org/doc/html/rfc792)
- [UDP](https://datatracker.ietf.org/doc/html/rfc768)
- [TCP](https://www.ietf.org/rfc/rfc9293.html)
