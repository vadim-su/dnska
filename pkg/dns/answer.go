package dns

import "fmt"

type DNSAnswer struct {
	name  DomainName
	class [2]byte
	type_ [2]byte
	ttl   [4]byte
	data  []byte // RDATA
}

func NewDNSAnswer(name []byte, class DNSClass, type_ DNSType, ttl uint32, data []byte) (*DNSAnswer, error) {
	dnsName, _, err := NewDomainName(name)
	if err != nil {
		return nil, fmt.Errorf("Can't create DNS answer: %s", err)
	}

	return &DNSAnswer{
		name:  *dnsName,
		class: dnsTypeClassToBytes(class),
		type_: dnsTypeClassToBytes(type_),
		ttl:   [4]byte{byte(ttl >> 24), byte(ttl >> 16), byte(ttl >> 8), byte(ttl)},
		data:  data,
	}, nil
}

func NewDNSAnswers(data []byte, count uint16, originalMessage []byte) ([]DNSAnswer, uint16, error) {
	resultAnswers := make([]DNSAnswer, 0)
	answersDataSize := uint16(0)
	for range count {
		dnsName, domainDataSize, err := NewDomainNameWithDecompression(data, originalMessage)
		if err != nil {
			return nil, 0, fmt.Errorf("Can't create DNS question: %s", err)
		}
		answersDataSize += domainDataSize

		data = data[domainDataSize:] // Remove domain name data

		class := [2]byte{data[0], data[1]}
		type_ := [2]byte{data[2], data[3]}
		ttl := [4]byte{data[4], data[5], data[6], data[7]}

		dataLength := uint16(data[8])<<8 | uint16(data[9])
		answersDataSize += 10 + dataLength
		data := data[10 : 10+dataLength]

		resultAnswers = append(resultAnswers, DNSAnswer{
			*dnsName,
			class,
			type_,
			ttl,
			data,
		})
	}

	return resultAnswers, answersDataSize, nil
}

func (d *DNSAnswer) ToBytes() []byte {
	question := d.name.ToBytes()
	data_length := []byte{byte(len(d.data) >> 8), byte(len(d.data) & 0xFF)}

	question = append(question, d.class[:]...)
	question = append(question, d.type_[:]...)
	question = append(question, d.ttl[:]...)
	question = append(question, data_length...)
	question = append(question, d.data...)

	return question
}

func (d *DNSAnswer) ToBytesWithCompression(
	compressionMap *CompressionMap,
	currentOffset uint16,
) []byte {
	nameBytes := d.name.ToBytesWithCompression(compressionMap, currentOffset)
	data_length := []byte{byte(len(d.data) >> 8), byte(len(d.data) & 0xFF)}

	result := append(nameBytes, d.class[:]...)
	result = append(result, d.type_[:]...)
	result = append(result, d.ttl[:]...)
	result = append(result, data_length...)
	result = append(result, d.data...)

	return result
}
