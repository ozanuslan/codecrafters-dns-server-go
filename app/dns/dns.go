package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type DNSMessage struct {
	Header    Header
	Questions []Question
	AnswerRRs []ResourceRecord
}

func (d *DNSMessage) Marshal() ([]byte, error) {
	data := make([]byte, 0)

	// Marshal header
	headerBytes := d.Header.Bytes()
	data = append(data, headerBytes...)

	// Marshal questions
	for _, question := range d.Questions {
		questionBytes, err := question.Marshal()
		if err != nil {
			return nil, err
		}
		data = append(data, questionBytes...)
	}

	// Marshal answer RRs
	for _, rr := range d.AnswerRRs {
		rrBytes, err := rr.Marshal()
		if err != nil {
			return nil, err
		}
		data = append(data, rrBytes...)
	}

	return data, nil
}

func (d *DNSMessage) Unmarshal(data []byte) error {
	if len(data) < 12 {
		return fmt.Errorf("header is too short")
	}

	d.Header = Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		QR:      data[2]>>7 == 1,
		OPCODE:  OPCode(data[2]>>3) & 0x0F,
		AA:      data[2]>>2 == 1,
		TC:      data[2]>>1 == 1,
		RD:      data[2]&0x01 == 1,
		RA:      data[3]>>7 == 1,
		Z:       data[3] >> 4 & 0x07,
		RCODE:   RCode(data[3] & 0x0F),
		QDCOUNT: binary.BigEndian.Uint16(data[4:6]),
		ANCOUNT: binary.BigEndian.Uint16(data[6:8]),
		NSCOUNT: binary.BigEndian.Uint16(data[8:10]),
		ARCOUNT: binary.BigEndian.Uint16(data[10:12]),
	}

	offset := 12

	d.Questions = make([]Question, d.Header.QDCOUNT)
	for i := 0; i < int(d.Header.QDCOUNT); i++ {
		// handle QNAME (compression is supported)
		name, o, err := parseName(data, offset, 0)
		if err != nil {
			d.Header.RCODE = RCodeFormErr
			return err
		}
		offset = o + 1

		fmt.Println("offset: ", offset)

		// fmt.Println("NAME: ", name)
		// fmt.Println("OFFSET: ", offset)
		// for j := 0; j < len(data); j++ {
		// 	fmt.Printf("%d: %08b | %c\n", j, data[j], data[j])
		// }

		// unmarshal TYPE
		qtype := Type(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		// unmarshal CLASS
		qclass := Class(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		d.Questions[i] = Question{
			QNAME:  name,
			QTYPE:  qtype,
			QCLASS: qclass,
		}
	}

	d.AnswerRRs = make([]ResourceRecord, d.Header.ANCOUNT)
	for i := 0; i < int(d.Header.ANCOUNT); i++ {
		// unmarshal NAME
		labels := make([]string, 0)
		for {
			labelLength := int(data[offset])
			if labelLength == 0 {
				break
			}
			offset++
			label := string(data[offset : offset+labelLength])
			labels = append(labels, label)
			offset += labelLength
		}
		name := strings.Join(labels, ".")
		offset++

		// unmarshal TYPE
		rrType := Type(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		// unmarshal CLASS
		rrClass := Class(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2

		// unmarshal TTL
		ttl := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		// unmarshal RDLENGTH
		rdLength := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// unmarshal RDATA
		rdata, err := unmarshalRecord(rrType, data, offset)
		if err != nil {
			return err
		}

		d.AnswerRRs[i] = ResourceRecord{
			NAME:     name,
			TYPE:     rrType,
			CLASS:    rrClass,
			TTL:      ttl,
			RDLENGTH: rdLength,
			RDATA:    rdata,
		}
	}

	return nil
}

func parseName(data []byte, offset int, depth int) (string, int, error) {
	if depth > 10 {
		return "", -1, fmt.Errorf("too many compressed labels")
	}

	labels := make([]string, 0)
	for {
		// if 0 octet is found, finished reading labels with compression
		if data[offset] == 0 {
			break
		}

		// if 11000000 (0xC0) is found, handle compression
		if data[offset]>>6 == 3 {
			// pointer layout
			// 1st octet: 11xxxxxx
			// 2nd octet: xxxxxxxx
			// first 2 bits are 11
			// next 14 bits are offset
			// we want to clear the first 2 bits, so the first octet becomes: 00xxxxxx
			// then we merge the first octet with the second octet
			// this gives us the offset: 00xxxxxx xxxxxxxx -> 16 bits
			compressionOffset := int(data[offset]&0x3F)<<8 | int(data[offset+1])
			fmt.Println("compressionOffset: ", compressionOffset)
			offset += 1

			label, o, err := parseName(data, compressionOffset, depth+1)
			if err != nil {
				return "", o, err
			}
			labels = append(labels, label)
			break
		}

		// read labels
		labelLength := int(data[offset])
		offset++
		label := string(data[offset : offset+labelLength])
		labels = append(labels, label)
		offset += labelLength
	}

	return strings.Join(labels, "."), offset, nil
}

func (d DNSMessage) String() string {
	return fmt.Sprintf("Header: %s, Questions: %v, AnswerRRs: %v",
		d.Header, d.Questions, d.AnswerRRs)
}

type Header struct {
	ID      uint16
	QR      bool
	OPCODE  OPCode
	AA      bool
	TC      bool
	RD      bool
	RA      bool
	Z       uint8
	RCODE   RCode
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

func (h Header) String() string {
	return fmt.Sprintf("ID: %d, QR: %v, OPCODE: %s, AA: %v, TC: %v, RD: %v, RA: %v, Z: %v, RCODE: %s, QDCOUNT: %d, ANCOUNT: %d, NSCOUNT: %d, ARCOUNT: %d",
		h.ID, h.QR, h.OPCODE, h.AA, h.TC, h.RD, h.RA, h.Z, h.RCODE, h.QDCOUNT, h.ANCOUNT, h.NSCOUNT, h.ARCOUNT)
}

func (h *Header) Bytes() []byte {
	data := make([]byte, 0)

	data = append(data, []byte{byte(h.ID >> 8), byte(h.ID)}...)
	data = append(data, byte(boolToInt(h.QR)<<7|int(h.OPCODE)<<3|boolToInt(h.AA)<<2|boolToInt(h.TC)<<1|boolToInt(h.RD)))
	data = append(data, byte(boolToInt(h.RA)<<7|int(h.Z)<<4|int(h.RCODE)))
	data = append(data, []byte{byte(h.QDCOUNT >> 8), byte(h.QDCOUNT)}...)
	data = append(data, []byte{byte(h.ANCOUNT >> 8), byte(h.ANCOUNT)}...)
	data = append(data, []byte{byte(h.NSCOUNT >> 8), byte(h.NSCOUNT)}...)
	data = append(data, []byte{byte(h.ARCOUNT >> 8), byte(h.ARCOUNT)}...)

	return data
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

type Question struct {
	QNAME  string
	QTYPE  Type
	QCLASS Class
}

func (q Question) Marshal() ([]byte, error) {
	data := make([]byte, 0)

	// Marshal QNAME
	labels := splitLabels(q.QNAME)
	for _, label := range labels {
		data = append(data, byte(len(label)))
		data = append(data, []byte(label)...)
	}
	data = append(data, 0)

	// Marshal QTYPE
	qtypeBytes := q.QTYPE.Bytes()
	data = append(data, qtypeBytes...)

	// Marshal QCLASS
	qclassBytes := q.QCLASS.Bytes()
	data = append(data, qclassBytes...)

	return data, nil
}

func splitLabels(name string) []string {
	labels := make([]string, 0)
	split := strings.Split(name, ".")
	for _, label := range split {
		if label != "" {
			labels = append(labels, label)
		}
	}
	return labels
}

func (q Question) Len() int {
	return len(q.QNAME) + 1 + 2
}

func (q Question) String() string {
	return fmt.Sprintf("QNAME: %s, QTYPE: %s, QCLASS: %s", q.QNAME, q.QTYPE, q.QCLASS)
}

type ResourceRecord struct {
	NAME     string
	TYPE     Type
	CLASS    Class
	TTL      uint32
	RDLENGTH uint16
	RDATA    Record
}

func (r ResourceRecord) Marshal() ([]byte, error) {
	data := make([]byte, 0)

	// Marshal NAME
	labels := splitLabels(r.NAME)
	for _, label := range labels {
		data = append(data, byte(len(label)))
		data = append(data, []byte(label)...)
	}
	data = append(data, 0)

	// Marshal TYPE
	typeBytes := r.TYPE.Bytes()
	data = append(data, typeBytes...)

	// Marshal CLASS
	classBytes := r.CLASS.Bytes()
	data = append(data, classBytes...)

	// Marshal TTL
	data = append(data, []byte{byte(r.TTL >> 24), byte(r.TTL >> 16), byte(r.TTL >> 8), byte(r.TTL)}...)

	// Marshal RDLENGTH
	rdLengthBytes := []byte{byte(r.RDLENGTH >> 8), byte(r.RDLENGTH)}
	data = append(data, rdLengthBytes...)

	// Marshal RDATA
	rdataBytes := r.RDATA.Bytes()
	data = append(data, rdataBytes...)

	return data, nil
}

func (r ResourceRecord) String() string {
	return fmt.Sprintf("NAME: %s, TYPE: %s, CLASS: %s, TTL: %d, RDLENGTH: %d, RDATA: %v", r.NAME, r.TYPE, r.CLASS, r.TTL, r.RDLENGTH, r.RDATA)
}

func (r ResourceRecord) Len() int {
	return len(r.NAME) + 1 + 2 + 4 + 2 + r.RDATA.Len()
}

type Record interface {
	String() string
	Bytes() []byte
	Len() int
}

func unmarshalRecord(rrType Type, data []byte, offset int) (Record, error) {
	switch rrType {
	case TypeA:
		return unmarshalARecord(data, offset)
	default:
		return nil, fmt.Errorf("unknown record type: %s", rrType)
	}
}

type ARecord struct {
	IP [4]byte
}

func unmarshalARecord(data []byte, offset int) (ARecord, error) {
	if len(data) < offset+4 {
		return ARecord{}, fmt.Errorf("invalid ARecord")
	}
	return ARecord{IP: [4]byte{data[offset], data[offset+1], data[offset+2], data[offset+3]}}, nil
}

func (a ARecord) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", a.IP[0], a.IP[1], a.IP[2], a.IP[3])
}

func (a ARecord) Bytes() []byte {
	return a.IP[:]
}

func (a ARecord) Len() int {
	return 4
}

type Class uint16

const (
	ClassUnknown Class = 0
	ClassIN      Class = 1
)

func (c Class) String() string {
	switch c {
	case ClassIN:
		return "IN"
	default:
		return "UNKNOWN"
	}
}

func (c Class) Bytes() []byte {
	return []byte{byte(c >> 8), byte(c)}
}

type Type uint16

const (
	TypeUnknown Type = 0
	TypeA       Type = 1
)

func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	default:
		return "UNKNOWN"
	}
}

func (t Type) Bytes() []byte {
	return []byte{byte(t >> 8), byte(t)}
}

type OPCode uint8

const (
	OPCodeUnknown OPCode = 255
	OPCodeQuery   OPCode = 0
)

func (o OPCode) String() string {
	switch o {
	case OPCodeQuery:
		return "QUERY"
	default:
		return "UNKNOWN"
	}
}

func (o OPCode) Bytes() []byte {
	return []byte{byte(o)}
}

type RCode uint8

const (
	RCodeUnknown  RCode = 255
	RCodeNoErr    RCode = 0
	RCodeFormErr  RCode = 1
	RCodeServFail RCode = 2
	RCodeNXDomain RCode = 3
	RCodeNotImp   RCode = 4
	RCodeRefused  RCode = 5
)

func (r RCode) String() string {
	switch r {
	case RCodeNoErr:
		return "NOERROR"
	case RCodeFormErr:
		return "FORMERR"
	case RCodeNotImp:
		return "NOTIMP"
	default:
		return "UNKNOWN"
	}
}

func (r RCode) Bytes() []byte {
	return []byte{byte(r)}
}
