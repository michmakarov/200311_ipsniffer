package main

import (
	//"flag"
	"fmt"
	"log"
	"net"
	"os"
	//"time"
)

const ()

var (
	ipConn *net.IPConn
	lAddr  *net.IPAddr
	nt     string //= "ip:1"
	intrf  string //= "192.168.1.44"
)

//Exit codes
//120 200311_ipsniffer: net.ResolveIPAddr err=%v
//120 200311_ipsniffer: net.ListenIP err=%v
func main() {
	var err error
	var iterC int
	var buff = make([]byte, 60000)
	var n int
	if lAddr, err = net.ResolveIPAddr(nt, intrf); err != nil {
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
		iterC++
		log.Printf("Iteration=%v\n", iterC)
		if n, err = ipConn.Read(buff); err != nil {
			log.Printf("Reading err=%v\n", err.Error())
		} else {
			log.Printf("having read(n=%v)=%v\n", n, string(buff[:n]))
		}

	} //for
	ipConn.Close()
} //main
