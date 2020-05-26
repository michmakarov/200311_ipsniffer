// header
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

type ICMPEchoData struct {
	ID      int    //two byte
	Num     int    //two byte
	Payload string //optional; "" if no
}

func (echo ICMPEchoData) String() string {
	return fmt.Sprintf("ID=%v, Num=%v, Payload=\"%v\"", echo.ID, echo.Num, echo.Payload)
}

type IPHeader struct {
	Ver            int
	HeaderLen      int
	ECN            int
	FulLen         int
	ID             int
	Flags          int
	FragShift      int
	TTL            int
	Proto          int
	HeaderCheckSum int
	SourceIP       string
	DestIp         string
}

func (h IPHeader) String() string {
	return fmt.Sprintf("Ver=%v,HeaderLen=%v,ECN=%v,FulLen=%v,ID=%v,Flags=%v,FragShift=%v,TTL=%v,Proto=%v,SourceIP=%v,DestIp=%v",
		h.Ver, h.HeaderLen, h.ECN, h.FulLen, h.ID, h.Flags, h.FragShift, h.TTL, h.Proto, h.SourceIP, h.DestIp)
}

//extrHeader extracts a Header structure from a given slice (pack)
//That is it regards the packet as an IP packet and parses it with no care about sense
//It returns an only error when len(pack) < 20
func extrIPHeader(pack []byte) (h IPHeader, err error) {
	h = IPHeader{}
	if len(pack) < 20 {
		err = fmt.Errorf("extrHeader: len(pack)<20")
		return
	}
	h.Ver = rngBE(pack[:1], 0, 3)
	h.HeaderLen = rngBE(pack[:1], 4, 7)
	//200525 16:55 continuation
	h.ECN = rngBE(pack[:1], 6, 7)
	h.FulLen = rngBE(pack[2:4], 0, 15)
	h.ID = rngBE(pack[4:6], 0, 15)
	h.Flags = rngBE(pack[6:7], 0, 2)
	h.FragShift = rngBE(pack[6:8], 3, 15)
	h.TTL = rngBE(pack[8:9], 0, 7)
	h.Proto = rngBE(pack[9:10], 0, 7)
	h.HeaderCheckSum = rngBE(pack[10:12], 0, 15)
	h.SourceIP = addrAsStr(pack[12:16])
	h.DestIp = addrAsStr(pack[16:20])
	return
}

//ParseICMP takes a slice (p) and regards it as ICMP message (see https://ru.wikipedia.org/wiki/ICMP)
func parseICMP(p []byte) (m ICMP) {
	if len(p) < 8 {
		panic("ParseICMP: len(p)<8")
	}
	m = ICMP{}
	m.Type = rngBE(p[0:1], 0, 7)
	m.Code = rngBE(p[1:2], 0, 7)
	m.ChSum = rngBE(p[2:4], 0, 15)
	m.Data = p[4:]
	return
}
func (m ICMP) String() string {
	return fmt.Sprintf("", m.Type, m.Code, parseICMPEchoData(m.Data).String())
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

//rngBE regards a bit range (beg ... end) from a []byte (b) and converts is to integer
//in presumption that the most significant bits go primarily
//It takes only one-byte ot two-bytes slices
//It checks relative sense of beg, end parameters and their sense relatively length of the slice
//If the checks faults it panics.
func rngBE(b []byte, beg, end int) (res int) {
	var bLen = len(b) * 8
	var i8 uint8
	var i16 uint16

	if beg < 0 || beg > bLen-1 {
		panic("func rngBE: beg < 0 || beg > bLen-1")
	}
	if end < 0 || end > bLen-1 {
		panic("func rngBE: end < 0 || end > bLen-1")
	}
	if end < beg {
		panic("func rngBE: end<beg")
	}
	if (end - beg) < 0 {
		panic("func rngBE: (end - beg)<1")
	}

	switch len(b) {
	case 1:
		i8 = uint8(b[0])

		i8 = i8 << beg
		end = end - beg
		i8 = i8 >> (7 - end)

		res = int(i8)
	case 2:
		i16 = uint16(b[0])*256 + uint16(b[1])

		i16 = i16 << beg
		end = end - beg
		i16 = i16 >> (15 - end)
		res = int(i16)
	default:
		panic("func rngBE: only an array  of one or two bytes permitted")
	}

	return
}

func addrAsStr(addr []byte) (str string) {
	if len(addr) != 4 {
		panic("addrAsStr: len(addr)!=4")
	}
	str = fmt.Sprintf("%v.%v.%v.%v", addr[0], addr[1], addr[2], addr[3])
	return
}
