package message

import (
	"fmt"

	"github.com/vadim-su/dnska/pkg/dns/utils"
)

// DNSQuestion represents a DNS question record.
type DNSQuestion struct {
	Name  utils.DomainName
	Class [2]byte
	Type  [2]byte
}

// Create a new DNS question
func NewDNSQuestions(data []byte, count uint16, originalMessage []byte) ([]DNSQuestion, uint16, error) {
	resultQuestions := make([]DNSQuestion, 0)
	questionsDataSize := uint16(0)

	for range count {
		dnsName, domainDataSize, err := utils.NewDomainNameWithDecompression(data, originalMessage)
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

// Convert the DNS question to its byte representation
func (d *DNSQuestion) ToBytes() []byte {
	question := d.Name.ToBytes()

	question = append(question, d.Class[:]...)
	question = append(question, d.Type[:]...)

	return question
}

// Convert the DNS question to its byte representation with compression
func (d *DNSQuestion) ToBytesWithCompression(
	compressionMap *utils.CompressionMap,
	currentOffset uint16,
) []byte {
	nameBytes := d.Name.ToBytesWithCompression(compressionMap, currentOffset)
	result := append(nameBytes, d.Class[:]...)
	result = append(result, d.Type[:]...)
	return result
}
