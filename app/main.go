package main

import (
	"fmt"
	"net"
)

type DNSHeader struct {
	ID                 uint16
	Response           bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Reserved           uint8
	ResponseCode       uint8
	QuestionCount      uint16
	AnswerCount        uint16
	AuthorityCount     uint16
	AdditionalCount    uint16
}

func NewDNSHeader() *DNSHeader {
	return &DNSHeader{
		ID:                 0,
		Response:           false,
		Opcode:             0,
		Authoritative:      false,
		Truncated:          false,
		RecursionDesired:   false,
		RecursionAvailable: false,
		Reserved:           0,
		ResponseCode:       0,
		QuestionCount:      0,
		AnswerCount:        0,
		AuthorityCount:     0,
		AdditionalCount:    0,
	}
}

func (h *DNSHeader) MarshallBytes(bytes []byte) {
	h.ID = uint16(bytes[0])<<8 | uint16(bytes[1])
	h.Response = bytes[2]&0x80 != 0
	h.Opcode = (bytes[2] >> 3) & 0x0F
	h.Authoritative = bytes[2]&0x04 != 0
	h.Truncated = bytes[2]&0x02 != 0
	h.RecursionDesired = bytes[2]&0x01 != 0
	h.RecursionAvailable = bytes[3]&0x80 != 0
	h.Reserved = (bytes[3] >> 4) & 0x07
	h.ResponseCode = bytes[3] & 0x0F
	h.QuestionCount = uint16(bytes[4])<<8 | uint16(bytes[5])
	h.AnswerCount = uint16(bytes[6])<<8 | uint16(bytes[7])
	h.AuthorityCount = uint16(bytes[8])<<8 | uint16(bytes[9])
	h.AdditionalCount = uint16(bytes[10])<<8 | uint16(bytes[11])
}

func (h *DNSHeader) UnmarshallBytes() []byte {
	bytes := make([]byte, 12)
	bytes[0] = byte(h.ID >> 8)
	bytes[1] = byte(h.ID)
	bytes[2] = byte(h.Opcode<<3) | byte(h.ResponseCode)
	bytes[3] = byte(h.ResponseCode)
	bytes[4] = byte(h.QuestionCount >> 8)
	bytes[5] = byte(h.QuestionCount)
	bytes[6] = byte(h.AnswerCount >> 8)
	bytes[7] = byte(h.AnswerCount)
	bytes[8] = byte(h.AuthorityCount >> 8)
	bytes[9] = byte(h.AuthorityCount)
	bytes[10] = byte(h.AdditionalCount >> 8)
	bytes[11] = byte(h.AdditionalCount)
	return bytes
}

type DNSMessage struct {
	Header DNSHeader
}

func main() {
	addr := "127.0.0.1:2053"

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("Could not resolve UDP addr:", err)
		return
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer conn.Close()

	fmt.Println("Listening to UDP packets on:", addr)

	for {
		buffer := make([]byte, 1024)
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP socket:", err)
			return
		}

		fmt.Printf("Received %d bytes from %s\n", n, remoteAddr)

		header := NewDNSHeader()
		header.MarshallBytes(buffer[:12])
		header.Response = true

		responseMsg := header.UnmarshallBytes()
		conn.WriteMsgUDP(responseMsg, make([]byte, 0), remoteAddr)
	}
}
