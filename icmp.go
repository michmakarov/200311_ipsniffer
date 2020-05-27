// icmp
package main

import (
	"fmt"
)

type ICMP struct { //ICMP - internet control message protocol
	Type int //byte
	Code int //byte;
	//TYpe==0,Code==0 - echo answer
	//TYpe==8,Code==0 - echo request
	//Data of both is same in structure
	ChSum int    //two byte
	Data  []byte //It is defined by Type and Code
}

func (m ICMP) String() string {
	return fmt.Sprintf("Type=%v;Code=%v;Data=(%v)", m.Type, m.Code, parseICMPEchoData(m.Data).String())
}

//ParseICMP takes a slice (p) and regards it as ICMP message (see https://ru.wikipedia.org/wiki/ICMP)
func parseICMP(p []byte) (m ICMP) {
	if len(p) < 8 {
		panic("ParseICMP: len(p)<8")
	}
	fmt.Printf("--M--p[0:1]=%v;p[2:1]=%v", p[0:1], p[1:2])
	m = ICMP{}
	m.Type = rngBE(p[0:1], 0, 7)
	m.Code = rngBE(p[1:2], 0, 7)
	m.ChSum = rngBE(p[2:4], 0, 15)
	m.Data = p[4:]
	return
}

type ICMPEchoData struct {
	ID      int    //two byte
	Num     int    //two byte
	Payload string //optional; "" if no
}

func (echo ICMPEchoData) String() string {
	return fmt.Sprintf("ID=%v, Num=%v, Payload=\"%v\"", echo.ID, echo.Num, echo.Payload)
}

func parseICMPEchoData(data []byte) (ed ICMPEchoData) {
	if len(data) < 4 {
		panic("parseICMPEchoData: len(data)<4")
	}
	ed = ICMPEchoData{}
	ed.ID = rngBE(data[0:2], 0, 15)
	ed.Num = rngBE(data[2:4], 0, 15)
	ed.Payload = string(data[4:])
	return
}
