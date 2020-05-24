// header
package main

import (
	"fmt"
)

type Header struct {
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
	SourceIP       []int
	DestIp         []int
}

func extrHeader(pack []byte) (h Header, err error) {
	h = Header{}
	if len(pack) < 20 {
		err = fmt.Errorf("extrHeader: len(pack)<20")
		return
	}
	h.Ver = rngBE(pack[:1], 0, 3)
	h.HeaderLen = rngBE(pack[:1], 4, 7)
	//h = rngBE(pack[:1], 4, 7)
	return
}

//rngBE regards a bit range (beg ... end) from a []byte (b) and converts is to integer
//in presumption that the most significant bits go primarily
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
		i16 = i16 >> (7 - end)
		res = int(i16)
	default:
		panic("func rngBE: only an array  of one or two bytes permitted")
	}

	return
}
