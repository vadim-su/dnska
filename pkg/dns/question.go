package dns

import "fmt"

type DNSQuestion struct {
	Name  DomainName
	Class [2]byte
	Type  [2]byte
}

func NewDNSQuestion(name []byte, class DNSClass, type_ DNSType) (*DNSQuestion, error) {
	dnsName, _, err := NewDomainName(name)
	if err != nil {
		return nil, fmt.Errorf("can't create DNS question: %s", err)
	}

	return &DNSQuestion{
		Name:  *dnsName,
		Class: dnsTypeClassToBytes(class),
		Type:  dnsTypeClassToBytes(type_),
	}, nil
}

func NewDNSQuestionFromBytes(data []byte) (*DNSQuestion, error) {
	dnsName, size, err := NewDomainName(data)
	if err != nil {
		return nil, fmt.Errorf("can't create DNS question: %s", err)
	}

	data = data[size:] // Remove domain name data

	class := [2]byte{data[0], data[1]}
	type_ := [2]byte{data[2], data[3]}

	return &DNSQuestion{
		*dnsName,
		class,
		type_,
	}, err
}

func NewDNSQuestions(data []byte, count uint16, originalMessage []byte) ([]DNSQuestion, uint16, error) {
	resultQuestions := make([]DNSQuestion, 0)
	questionsDataSize := uint16(0)

	for range count {
		dnsName, domainDataSize, err := NewDomainNameWithDecompression(data, originalMessage)
		if err != nil {
			return nil, 0, fmt.Errorf("can't create DNS question: %s", err)
		}
		questionsDataSize += domainDataSize

		if len(data[domainDataSize:]) < 4 {
			return nil, 0, fmt.Errorf("not enough bytes for class and type")
		}

		data = data[domainDataSize:] // Remove domain name data

		class := [2]byte{data[0], data[1]}
		type_ := [2]byte{data[2], data[3]}
		questionsDataSize += 4 // Add 4 bytes for class and type

		resultQuestions = append(resultQuestions, DNSQuestion{
			*dnsName,
			class,
			type_,
		})

		data = data[4:] // Move past class and type bytes
	}

	return resultQuestions, questionsDataSize, nil
}

func (d *DNSQuestion) ToBytes() []byte {
	question := d.Name.ToBytes()

	question = append(question, d.Class[:]...)
	question = append(question, d.Type[:]...)

	return question
}

func (d *DNSQuestion) ToBytesWithCompression(
	compressionMap *CompressionMap,
	currentOffset uint16,
) []byte {
	nameBytes := d.Name.ToBytesWithCompression(compressionMap, currentOffset)
	result := append(nameBytes, d.Class[:]...)
	result = append(result, d.Type[:]...)
	return result
}
