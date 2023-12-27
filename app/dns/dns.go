package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type DNSMessage struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Resources []DNSResource
}

func (m *DNSMessage) AddResource(resource DNSResource) {
	m.Resources = append(m.Resources, resource)
	m.Header.AnswerCount = uint16(len(m.Resources))
}

func (m *DNSMessage) Marshal() ([]byte, error) {
	headerData, err := marshalDNSHeader(&m.Header)
	if err != nil {
		return nil, err
	}

	questionData, err := marshallDNSQuestions(m.Questions)
	if err != nil {
		return nil, err
	}

	resourceData, err := marshallDNSResources(m.Resources)
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0)
	data = append(data, headerData...)
	data = append(data, questionData...)
	data = append(data, resourceData...)

	return data, nil
}

func (m *DNSMessage) Unmarshal(data []byte) error {
	header, err := unmarshalDNSHeader(data)
	if err != nil {
		return err
	}
	m.Header = *header

	questions, err := unmarshalDNSQuestions(data[12:], int(m.Header.QuestionCount))
	if err != nil {
		return err
	}
	m.Questions = questions

	resources, err := unmarshalDNSResources(data[12:], int(m.Header.AnswerCount))
	if err != nil {
		return err
	}
	m.Resources = resources

	return nil
}

func (m *DNSMessage) questionsString() []string {
	questions := make([]string, 0)
	for _, question := range m.Questions {
		questions = append(questions, question.String())
	}
	return questions
}

func (m *DNSMessage) String() string {
	return fmt.Sprintf(
		"DNSMessage{Header: %s, Questions: [%s]}",
		m.Header.String(),
		strings.Join(m.questionsString(), ", "),
	)
}

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

func (h *DNSHeader) String() string {
	return fmt.Sprintf(
		"DNSHeader{ID: %d, Response: %t, Opcode: %d, Authoritative: %t, Truncated: %t, RecursionDesired: %t, RecursionAvailable: %t, Reserved: %d, ResponseCode: %d, QuestionCount: %d, AnswerCount: %d, AuthorityCount: %d, AdditionalCount: %d}",
		h.ID,
		h.Response,
		h.Opcode,
		h.Authoritative,
		h.Truncated,
		h.RecursionDesired,
		h.RecursionAvailable,
		h.Reserved,
		h.ResponseCode,
		h.QuestionCount,
		h.AnswerCount,
		h.AuthorityCount,
		h.AdditionalCount,
	)
}

type DNSQuestion struct {
	Name  DomainName
	Type  DNSResourceType
	Class uint16
}

func unmarshalDNSQuestions(data []byte, questionCount int) ([]DNSQuestion, error) {
	questions := make([]DNSQuestion, 0)

	for i := 0; i < questionCount; i++ {
		domainName, err := unmarshalDomainName(data)
		if err != nil {
			return nil, err
		}
		data = data[domainName.Len()+1:]

		// Unmarshal type and class
		typeData := data[:2]
		data = data[2:]
		classData := data[:2]
		data = data[2:]

		questions = append(questions, DNSQuestion{
			Name:  *domainName,
			Type:  DNSResourceType(binary.BigEndian.Uint16(typeData)),
			Class: binary.BigEndian.Uint16(classData),
		})
	}

	return questions, nil
}

func marshallDNSQuestions(questions []DNSQuestion) ([]byte, error) {
	data := make([]byte, 0)

	for _, question := range questions {
		nameData, err := marshalDomainName(&question.Name)
		if err != nil {
			return nil, err
		}

		// Marshal type and class
		typeData := make([]byte, 2)
		binary.BigEndian.PutUint16(typeData, uint16(question.Type))
		classData := make([]byte, 2)
		binary.BigEndian.PutUint16(classData, question.Class)

		data = append(data, nameData...)
		data = append(data, typeData...)
		data = append(data, classData...)
	}

	return data, nil
}

func (q *DNSQuestion) String() string {
	return fmt.Sprintf(
		"DNSQuestion{Name: %s, Type: %d, Class: %d}",
		q.Name,
		q.Type,
		q.Class,
	)
}

type DomainName struct {
	Labels []string
}

func (d *DomainName) Len() int {
	length := 0
	for _, label := range d.Labels {
		length += len(label) + 1
	}
	return length
}

func unmarshalDomainName(data []byte) (*DomainName, error) {
	labels := make([]string, 0)

	for i := 0; i < len(data); {
		labelLength := int(data[i])
		i++

		if labelLength == 0 {
			break
		}

		if labelLength > 63 {
			return nil, fmt.Errorf("label too long: %d", labelLength)
		}

		label := string(data[i : i+labelLength])
		labels = append(labels, label)
		i += labelLength
	}

	return &DomainName{Labels: labels}, nil
}

func marshalDomainName(domainName *DomainName) ([]byte, error) {
	data := make([]byte, 0)

	for _, label := range domainName.Labels {
		labelLength := len(label)
		if labelLength > 63 {
			return nil, fmt.Errorf("label too long: %s", label)
		}

		data = append(data, byte(labelLength))
		data = append(data, []byte(label)...)
	}

	data = append(data, 0)

	return data, nil
}

func (d *DomainName) String() string {
	return strings.Join(d.Labels, ".")
}

type DNSResourceType uint16

const (
	TypeA     DNSResourceType = 1
	TypeNS    DNSResourceType = 2
	TypeCNAME DNSResourceType = 5
	TypeSOA   DNSResourceType = 6
	TypePTR   DNSResourceType = 12
	TypeMX    DNSResourceType = 15
	TypeTXT   DNSResourceType = 16
	TypeAAAA  DNSResourceType = 28
	TypeSRV   DNSResourceType = 33
	TypeOPT   DNSResourceType = 41
)

func (t DNSResourceType) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

type DNSClass uint16

const (
	ClassIN DNSClass = 1
)

type DNSResource struct {
	Name     DomainName
	Type     DNSResourceType
	Class    DNSClass
	TTL      uint32
	Data     []byte
	DataName DomainName
}

func (r *DNSResource) String() string {
	return fmt.Sprintf(
		"DNSResource{Name: %s, Type: %s, Class: %d, TTL: %d, Data: %s, DataName: %s}",
		r.Name,
		r.Type,
		r.Class,
		r.TTL,
		r.Data,
		r.DataName,
	)
}

func unmarshalDNSResources(data []byte, resourceCount int) ([]DNSResource, error) {
	resources := make([]DNSResource, 0)

	for i := 0; i < resourceCount; i++ {
		domainName, err := unmarshalDomainName(data)
		if err != nil {
			return nil, err
		}
		data = data[domainName.Len()+1:]

		// Unmarshal type, class and ttl
		typeData := data[:2]
		data = data[2:]
		classData := data[:2]
		data = data[2:]
		ttlData := data[:4]
		data = data[4:]

		// Unmarshal data length and data
		dataLength := int(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
		resourceData := data[:dataLength]
		data = data[dataLength:]

		resources = append(resources, DNSResource{
			Name:  *domainName,
			Type:  DNSResourceType(binary.BigEndian.Uint16(typeData)),
			Class: DNSClass(binary.BigEndian.Uint16(classData)),
			TTL:   binary.BigEndian.Uint32(ttlData),
			Data:  resourceData,
		})
	}

	return resources, nil
}

func marshallDNSResources(resources []DNSResource) ([]byte, error) {
	data := make([]byte, 0)

	for _, resource := range resources {
		nameData, err := marshalDomainName(&resource.Name)
		if err != nil {
			return nil, err
		}

		// Marshal type, class and ttl
		typeData := make([]byte, 2)
		binary.BigEndian.PutUint16(typeData, uint16(resource.Type))
		classData := make([]byte, 2)
		binary.BigEndian.PutUint16(classData, uint16(resource.Class))
		ttlData := make([]byte, 4)
		binary.BigEndian.PutUint32(ttlData, resource.TTL)

		// Marshal data length and data
		dataLengthData := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLengthData, uint16(len(resource.Data)))

		data = append(data, nameData...)
		data = append(data, typeData...)
		data = append(data, classData...)
		data = append(data, ttlData...)
		data = append(data, dataLengthData...)
		data = append(data, resource.Data...)
	}

	return data, nil
}

func MakeResource(name string, resourceType DNSResourceType, class DNSClass, ttl uint32, data []byte) DNSResource {
	return DNSResource{
		Name:  DomainName{Labels: strings.Split(name, ".")},
		Type:  resourceType,
		Class: 1,
		TTL:   ttl,
		Data:  data,
	}
}
