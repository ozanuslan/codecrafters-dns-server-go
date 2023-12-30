package main

import (
	"fmt"
	"net"
	"os"

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

var resolver string = ""

func main() {
	// program run: ./your_server --resolver <address>
	// take the address from the command line and store it in the resolver variable
	if len(os.Args) > 2 {
		if os.Args[1] == "--resolver" {
			resolver = os.Args[2]
			fmt.Println("Resolver:", resolver)
		}
	}

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
		response := dnsMessage.Marshal()
		return response
	}

	fmt.Println("Request :", dnsMessage.String())

	if dnsMessage.Header.RCODE != dns.RCodeNoErr {
		dnsMessage.Header.QR = true
		response := dnsMessage.Marshal()
		return response
	}

	if dnsMessage.Header.OPCODE != dns.OPCodeQuery {
		dnsMessage.Header.RCODE = dns.RCodeNotImp
		dnsMessage.Header.QR = true
		response := dnsMessage.Marshal()
		return response
	}

	var response []byte
	if resolver != "" {
		response, err = forwardToResolver(dnsMessage)
		if err == nil {
			return response
		}
	}

	dnsMessage.Header.QR = true

	for _, question := range dnsMessage.Questions {
		if question.QTYPE != dns.TypeA || question.QCLASS != dns.ClassIN {
			fmt.Printf("Question type not supported: QTYPE=%d, QCLASS=%d\n", question.QTYPE, question.QCLASS)
			dnsMessage.Header.RCODE = dns.RCodeNotImp
			response := dnsMessage.Marshal()
			return response
		}

		answer := defaultDNSResource
		queryDomain := dnsMessage.Questions[0].QNAME
		answer.NAME = queryDomain
		dnsMessage.AnswerRRs = append(dnsMessage.AnswerRRs, answer)
	}
	dnsMessage.Header.ANCOUNT = uint16(len(dnsMessage.AnswerRRs))

	dnsMessage.Header.RCODE = dns.RCodeNoErr
	fmt.Println("Response:", dnsMessage.String())
	response = dnsMessage.Marshal()
	return response
}

func forwardToResolver(originalMessage dns.DNSMessage) ([]byte, error) {
	conn, err := net.Dial("udp", resolver)
	if err != nil {
		fmt.Println("Error connecting to resolver:", err)
		return nil, err
	}
	defer conn.Close()

	resolverResponses := make([]dns.ResourceRecord, 0)
	for i := 0; i < len(originalMessage.Questions); i++ {
		newDnsMessage := dns.DNSMessage{}
		newDnsMessage.Header.ID = uint16(i)
		newDnsMessage.Header.QR = false
		newDnsMessage.Header.OPCODE = dns.OPCodeQuery
		newDnsMessage.Header.AA = false
		newDnsMessage.Header.TC = false
		newDnsMessage.Header.RD = true
		newDnsMessage.Header.RA = false
		newDnsMessage.Header.Z = 0
		newDnsMessage.Header.RCODE = dns.RCodeNoErr
		newDnsMessage.Header.QDCOUNT = 1
		newDnsMessage.Header.ANCOUNT = 0
		newDnsMessage.Header.NSCOUNT = 0
		newDnsMessage.Header.ARCOUNT = 0

		newDnsMessage.Questions = make([]dns.Question, 1)
		newDnsMessage.Questions[0] = originalMessage.Questions[i]

		buffer := newDnsMessage.Marshal()

		_, err = conn.Write(buffer)
		if err != nil {
			fmt.Println("Error writing to resolver:", err)
			return nil, err
		}

		responseBuffer := make([]byte, 512)
		n, err := conn.Read(responseBuffer)
		if err != nil {
			fmt.Println("Error reading from resolver:", err)
			return nil, err
		}

		resolverResponse := dns.DNSMessage{}
		err = resolverResponse.Unmarshal(responseBuffer[:n])
		if err != nil {
			fmt.Println("Error unmarshalling DNS Message:", err)
			return nil, err
		}

		if resolverResponse.Header.RCODE != dns.RCodeNoErr {
			fmt.Println("Resolver returned error:", resolverResponse.Header.RCODE)
			return nil, err
		}

		if len(resolverResponse.AnswerRRs) == 0 {
			fmt.Println("Resolver returned no answers")
			return nil, err
		}

		resolverResponses = append(resolverResponses, resolverResponse.AnswerRRs...)
	}

	originalMessage.AnswerRRs = resolverResponses

	if len(originalMessage.AnswerRRs) != len(originalMessage.Questions) {
		fmt.Println("Invalid response from resolver")
		return nil, err
	}

	originalMessage.Header.ANCOUNT = uint16(len(originalMessage.AnswerRRs))
	originalMessage.Header.QR = true

	response := originalMessage.Marshal()

	return response, nil
}
