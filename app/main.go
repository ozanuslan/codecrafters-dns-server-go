package main

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dns"
)

var defaultDNSResource = dns.ResourceRecord{
	NAME:     "codecrafters.io",
	TYPE:     dns.TypeA,
	CLASS:    dns.ClassIN,
	TTL:      60,
	RDLENGTH: 4,
	RDATA:    dns.ARecord{IP: [4]byte{127, 0, 0, 1}},
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
		buffer := make([]byte, 512)
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from UDP socket:", err)
			return
		}

		fmt.Printf("Received %d bytes from %s\n", n, clientAddr)

		response := handleDNSRequest(buffer[:n])
		conn.WriteMsgUDP(response, make([]byte, 0), clientAddr)
	}
}

func handleDNSRequest(buffer []byte) []byte {
	if len(buffer) < 12 {
		fmt.Println("Invalid DNS request")
		return nil
	}
	dnsMessage := dns.DNSMessage{}
	err := dnsMessage.Unmarshal(buffer)
	if err != nil {
		fmt.Println("Error unmarshalling DNS Message:", err)
		dnsMessage.Header.RCODE = dns.RCodeFormErr
		response, err := dnsMessage.Marshal()
		if err != nil {
			fmt.Println("Error marshalling DNS Message:", err)
			return nil
		}

		return response
	}
	fmt.Println("Request :", dnsMessage.String())

	dnsMessage.Header.QR = true

	if dnsMessage.Header.OPCODE != dns.OPCodeQuery {
		dnsMessage.Header.RCODE = dns.RCodeNotImp
		response, err := dnsMessage.Marshal()
		if err != nil {
			fmt.Println("Error marshalling DNS Message:", err)
			return nil
		}
		return response
	}

	for _, question := range dnsMessage.Questions {
		if question.QTYPE != dns.TypeA || question.QCLASS != dns.ClassIN {
			dnsMessage.Header.RCODE = dns.RCodeNotImp
			response, err := dnsMessage.Marshal()
			if err != nil {
				fmt.Println("Error marshalling DNS Message:", err)
				return nil
			}
			return response
		}

		answer := defaultDNSResource
		queryDomain := dnsMessage.Questions[0].QNAME
		answer.NAME = queryDomain
		dnsMessage.AnswerRRs = []dns.ResourceRecord{answer}
	}
	dnsMessage.Header.ANCOUNT = uint16(len(dnsMessage.AnswerRRs))

	dnsMessage.Header.RCODE = dns.RCodeNoErr
	fmt.Println("Response:", dnsMessage.String())
	response, err := dnsMessage.Marshal()
	if err != nil {
		fmt.Println("Error marshalling DNS Message:", err)
		return nil
	}
	return response
}
