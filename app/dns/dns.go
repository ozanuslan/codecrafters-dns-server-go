package dns

import (
	"encoding/binary"
	"fmt"
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

func unmarshalDNSHeader(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("insufficient data to unmarshal DNS header")
	}

	header := &DNSHeader{}

	// Unmarshal fields using binary.BigEndian
	header.ID = binary.BigEndian.Uint16(data[:2])
	header.Response = (data[2] & 0x80) != 0
	header.Opcode = (data[2] >> 3) & 0x0F
	header.Authoritative = (data[2] & 0x04) != 0
	header.Truncated = (data[2] & 0x02) != 0
	header.RecursionDesired = (data[2] & 0x01) != 0
	header.RecursionAvailable = (data[3] & 0x80) != 0
	header.Reserved = (data[3] >> 4) & 0x07
	header.ResponseCode = data[3] & 0x0F
	header.QuestionCount = binary.BigEndian.Uint16(data[4:6])
	header.AnswerCount = binary.BigEndian.Uint16(data[6:8])
	header.AuthorityCount = binary.BigEndian.Uint16(data[8:10])
	header.AdditionalCount = binary.BigEndian.Uint16(data[10:12])

	return header, nil
}

func marshalDNSHeader(header *DNSHeader) ([]byte, error) {
	data := make([]byte, 12)

	// Marshal fields using binary.BigEndian
	binary.BigEndian.PutUint16(data[:2], header.ID)

	flags := uint8(0)
	if header.Response {
		flags |= 0x80
	}
	flags |= (header.Opcode & 0x0F) << 3
	if header.Authoritative {
		flags |= 0x04
	}
	if header.Truncated {
		flags |= 0x02
	}
	if header.RecursionDesired {
		flags |= 0x01
	}
	data[2] = flags

	flags2 := uint8(0)
	if header.RecursionAvailable {
		flags2 |= 0x80
	}
	flags2 |= (header.Reserved & 0x07) << 4
	flags2 |= header.ResponseCode & 0x0F
	data[3] = flags2

	binary.BigEndian.PutUint16(data[4:6], header.QuestionCount)
	binary.BigEndian.PutUint16(data[6:8], header.AnswerCount)
	binary.BigEndian.PutUint16(data[8:10], header.AuthorityCount)
	binary.BigEndian.PutUint16(data[10:12], header.AdditionalCount)

	return data, nil
}

type DNSMessage struct {
	Header DNSHeader
}

func (m *DNSMessage) Marshal() ([]byte, error) {
	headerData, err := marshalDNSHeader(&m.Header)
	if err != nil {
		return nil, err
	}

	return headerData, nil
}

func (m *DNSMessage) Unmarshal(data []byte) error {
	header, err := unmarshalDNSHeader(data)
	if err != nil {
		return err
	}

	m.Header = *header

	return nil
}
