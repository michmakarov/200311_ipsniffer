// help
package main

//import (
//	"fmt"
//)
var help = `
This console program is IP sniffer.
That is it, by a raw socket of IP4 net (domain=AF_INET), is given copies of all IP packets with a certain destination and a protocol.
It runs infinite loop, in iteration of that arriving of a packet is expected.
When the packet arrives a string representation of the packet's header is showing.
Next a string representation of the packet's payload is showing, wholly or partly.
See the constant showPayLoad.
Next, for some protocols, it is showing the detailed content of the payload.

If the prog is run and number of params less than two it prints this text and ends its work.
Otherwise it expects next params in order of writing:
1. An dotted address of destination of a IP packet . In other word, it is a net interface to which the packet was sent.
For example, 127.1.1.123 or 192.168.1.44
2. A decimal number of IP protocol. For example: 1 for ICMP; 6 - TCP; 17 - UDP.
`
