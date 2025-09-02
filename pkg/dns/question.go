package dns

import "fmt"

type DNSQuestion struct {
	Name  DomainName
	Class [2]byte
	Type  [2]byte
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
