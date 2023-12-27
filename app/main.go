package main

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dns"
)

var defaultDNSResource = dns.MakeResource(
	"codecrafters.io",
	dns.TypeA,
	dns.ClassIN,
	60,
	[]byte{127, 0, 0, 1},
)

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
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP socket:", err)
			return
		}

		fmt.Printf("Received %d bytes from %s\n", n, clientAddr)

		dnsMessage := &dns.DNSMessage{}
		err = dnsMessage.Unmarshal(buffer[:n])
		if err != nil {
			fmt.Println("Error unmarshalling DNS header:", err)
			return
		}
		fmt.Println("Request :", dnsMessage.String())

		dnsMessage.Header.Response = true
		dnsMessage.Header.AnswerCount = 1
		if dnsMessage.Header.Opcode != 0 {
			dnsMessage.Header.ResponseCode = 4
		}

		for _, q := range dnsMessage.Questions {
			qName := q.Name.String()
			qType := q.Type
			if qType == dns.TypeANY {
				qType = dns.TypeA
			}
			qClass := q.Class
			if qClass == dns.ClassANY {
				qClass = dns.ClassIN
			}
			qTTL := uint32(60)
			data := defaultDNSResource.Data
			len := len(data)

			dnsMessage.AddResource(dns.MakeResource(qName, qType, qClass, qTTL, data[:len]))
		}

		fmt.Println("Response:", dnsMessage.String())
		response, err := dnsMessage.Marshal()
		if err != nil {
			fmt.Println("Error marshalling DNS header:", err)
			return
		}
		conn.WriteMsgUDP(response, make([]byte, 0), clientAddr)
	}
}
