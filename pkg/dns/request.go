package dns

import "fmt"

// DNSRequest represents a full DNS request message.
type DNSRequest struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

// Create a new DNS request from raw byte data
func NewDNSRequest(data []byte) (*DNSRequest, error) {
	header := DNSHeader{
		ID:                    uint16(data[0])<<8 | uint16(data[1]),
		Flags:                 DNSFlag(uint16(data[2])<<8 | uint16(data[3])),
		QuestionCount:         uint16(data[4])<<8 | uint16(data[5]),
		AnswerRecordCount:     uint16(data[6])<<8 | uint16(data[7]),
		AuthorityRecordCount:  uint16(data[8])<<8 | uint16(data[9]),
		AdditionalRecordCount: uint16(data[10])<<8 | uint16(data[11]),
	}

	originalMessage := data
	data = data[12:]
	questions, size, err := NewDNSQuestions(data, header.QuestionCount, originalMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to create dns request: %s", err)
	}

	data = data[size:]

	answers, _, err := NewDNSAnswers(data, header.AnswerRecordCount, originalMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to create dns request: %s", err)
	}

	return &DNSRequest{
		header,
		questions,
		answers,
	}, err
}
