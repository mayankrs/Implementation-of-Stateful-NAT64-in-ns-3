# Implementation of Stateful NAT64 in ns-3.

## Course Code: CO300

## Assignment: #8

### Overview

NAT64 allows IPv6-only clients to connect to IPv4 servers using unicast TCP, UDP and ICMP.

### To do list:
- [X] Binding Information Base implementation
- [X] Session table implementation
- [X] IPv6 packet header conversion to IPv4 and vice-versa (Protocol conversion)
- [X] Translating IPv4 address to IPv6 address and vice-versa
- [X] Routing IPv6 packets within IPv6 only network
- [ ] Routing to IPv6 packets with IPv4 destination address to NAT64
- [ ] Run Nat function for all packets passing through the IPv6 Net Filter


### References
[1] [Stateful NAT64 - RFC 6146](https://tools.ietf.org/html/rfc6146)  
[2] [Google Summer of Code (GSoC) ns-3 project on NAT](https://www.nsnam.org/wiki/GSOC2012NetworkAddressTranslation)
