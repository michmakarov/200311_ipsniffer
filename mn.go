package main

import (
	//"flag"
	"fmt"
	"log"
	"net"
	"os"
	//"time"
)

const (
	showPayLoad = 64 //Maximum number of byte of a packet's payload, that will be shown
)

var (
	git_commit_1 = "no data of building" //set by bg.sh
	ipConn       *net.IPConn
	lAddr        *net.IPAddr
	proto        string //1 for ICMP
	destAddr     string //destination address, like "192.168.1.44" or "127.12.123.1"
)

//Exit codes
//120 200311_ipsniffer: net.ResolveIPAddr err=%v
//120 200311_ipsniffer: net.ListenIP err=%v
func main() {
	var err error
	var iterC int
	var buff = make([]byte, 70000) //a buffer for an entire packet
	var payLoad []byte             //a buffer for payload
	//var payLoadStr string          // payload as string
	var n int
	var nt string
	fmt.Printf("200311_ipsniffer %v; pid=%v\n", git_commit_1, os.Getpid())
	if len(os.Args) < 3 {
		log.Println(help)
		return
	}
	destAddr = os.Args[1]
	proto = os.Args[2]
	nt = "ip:" + proto
	if lAddr, err = net.ResolveIPAddr(nt, destAddr); err != nil {
		err = fmt.Errorf("200311_ipsniffer: net.ResolveIPAddr err=%v", err.Error())
		log.Printf("%v\n", err.Error())
		os.Exit(110)
	} else {
		log.Printf("lAddr=%+v\n", lAddr)
	}

	if ipConn, err = net.ListenIP(nt, lAddr); err != nil {
		err = fmt.Errorf("200311_ipsniffer: net.ListenIP err=%v", err.Error())
		log.Printf("%v\n", err.Error())
		os.Exit(120)
	} else {
		log.Printf("Packet RA=%v;LA=%v", ipConn.RemoteAddr(), ipConn.LocalAddr())
	}

	for {
		var h IPHeader
		iterC++
		fmt.Println("___________________________________")
		log.Printf("Iteration=%v\n", iterC)
		if n, err = ipConn.Read(buff); err != nil { //200526 19:38 May it be stated that if there is not err then all available data was read?
			//It seems reasonable though the documentation does not say it.
			log.Printf("Reading err=%v\n", err.Error())
			continue
		} else {
			buff = buff[:n]
			payLoad = buff[h.HeaderLen*4 : h.FulLen]
			if h, err = extrIPHeader(buff); err == nil {
				fmt.Printf("%v\n", h.String())
				if (h.FulLen - h.HeaderLen*4) <= showPayLoad {
					fmt.Printf("payload=%v\n", string(payLoad))
				} else {
					fmt.Printf("payload=%v ...\n", string(payLoad[:showPayLoad]))
				}
			} else {
				fmt.Printf("Error of parsing header:%v\n", err.Error())
				continue
			}
			switch h.Proto {
			case 1:
				//fmt.Printf("ICMP details: %v\n", parseICMPEchoData(parseICMP(buff[h.HeaderLen:]).Data).String())
				fmt.Printf("ICMP details: %v\n", parseICMP(buff[h.HeaderLen*4:]).String())
			default:
				fmt.Printf("With protocol(%v) the packet cannot be shown in details.\n", h.Proto)

			}

		}

	} //for
	ipConn.Close()
} //main
