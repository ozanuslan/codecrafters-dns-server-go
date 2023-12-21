package main

import (
	"fmt"
	"net"
)

const HEADERBYTES = 12

type DNSMessage struct {
	header     []byte
	question   []byte
	answer     []byte
	authority  []byte
	additional []byte
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

		var msg DNSMessage
		msg.header = buffer[:HEADERBYTES]

		conn.WriteMsgUDP(msg.header, make([]byte, 0), remoteAddr)
	}
}
