package main

import (
	"fmt"
	"net"

	"github.com/codecrafters-io/dns-server-starter-go/app/dns"
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

		dnsMessage.Header.Response = true

		response, err := dnsMessage.Marshal()
		fmt.Printf("Response: %v\n", response)
		if err != nil {
			fmt.Println("Error marshalling DNS header:", err)
			return
		}
		conn.WriteMsgUDP(response, make([]byte, 0), clientAddr)
	}
}
