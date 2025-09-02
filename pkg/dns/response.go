package dns

import "fmt"

// DNSResponse represents a full DNS response message.
type DNSResponse struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

// Create a new DNS response from raw byte data
func NewDNSResponse(data []byte) (*DNSResponse, error) {
	// Validate minimum required length for DNS header (12 bytes)
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid DNS response: empty data provided")
	}

	if len(data) < 12 {
		return nil, fmt.Errorf(
			"invalid DNS response: data too short (%d bytes, need at least 12 for header)",
			len(data),
		)
	}

	originalMessage := data // Keep reference to original message for decompression

	header := NewDNSHeader(
		uint16(data[0])<<8|uint16(data[1]),
		DNSFlag(uint16(data[2])<<8|uint16(data[3])),
		uint16(data[4])<<8|uint16(data[5]),
		uint16(data[6])<<8|uint16(data[7]),
		uint16(data[8])<<8|uint16(data[9]),
		uint16(data[10])<<8|uint16(data[11]),
	)

	data = data[12:] // Remove header data

	questions, questionsDataSize, err := NewDNSQuestions(data, header.QuestionCount, originalMessage)
	if err != nil {
		return nil, err
	}

	data = data[questionsDataSize:] // Remove questions data

	answers, _, err := NewDNSAnswers(data, header.AnswerRecordCount, originalMessage)
	if err != nil {
		return nil, err
	}

	return &DNSResponse{
		*header,
		questions,
		answers,
	}, nil
}

// Generate a DNS response based on the request flags and provided questions and answers
func GenerateDNSResponse(id uint16, reqFlags DNSFlag, questions []DNSQuestion, answers []DNSAnswer) *DNSResponse {
	flags := PrepareResponseFlags(reqFlags)
	return &DNSResponse{
		DNSHeader{
			id,
			flags,
			uint16(len(questions)),
			uint16(len(answers)),
			0,
			0,
		},
		questions,
		answers,
	}
}

// Generate a DNS query with the given ID and questions
func GenerateDNSQuery(id uint16, questions []DNSQuestion) *DNSResponse {
	// Create proper query flags: standard query with recursion desired
	flags := FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED
	return &DNSResponse{
		DNSHeader{
			id,
			flags,
			uint16(len(questions)),
			0, // No answers in a query
			0,
			0,
		},
		questions,
		nil,
	}
}

// PrepareResponseFlags prepares the response flags based on the request flags
func PrepareResponseFlags(reqFlags DNSFlag) DNSFlag {
	respFlags := reqFlags | FLAG_QR_RESPONSE

	if ((reqFlags >> BIT_OPCODE_START) & 0xF) == 0 {
		respFlags = respFlags | FLAG_RCODE_NO_ERROR
	} else {
		respFlags = respFlags | FLAG_RCODE_NOT_IMPLEMENTED
	}

	return respFlags
}

// Convert DNSResponse to byte array
func (d *DNSResponse) ToBytes() []byte {
	resp := d.Header.ToBytes()

	for _, question := range d.Questions {
		resp = append(resp, question.ToBytes()...)
	}

	for _, answer := range d.Answers {
		resp = append(resp, answer.ToBytes()...)
	}

	return resp
}

// Convert DNSResponse to byte array with name compression
func (d *DNSResponse) ToBytesWithCompression() []byte {
	compressionMap := NewCompressionMap()
	result := make([]byte, 0, 512)

	headerBytes := d.Header.ToBytes()
	result = append(result, headerBytes...)
	currentOffset := uint16(12)

	// Add questions with compression
	for _, question := range d.Questions {
		questionBytes := question.ToBytesWithCompression(compressionMap, currentOffset)
		result = append(result, questionBytes...)
		currentOffset += uint16(len(questionBytes))
	}

	// Add answers with compression
	for _, answer := range d.Answers {
		answerBytes := answer.ToBytesWithCompression(compressionMap, currentOffset)
		result = append(result, answerBytes...)
		currentOffset += uint16(len(answerBytes))
	}

	return result
}
