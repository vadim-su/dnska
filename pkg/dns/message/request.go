package message

import (
	"fmt"

	"github.com/vadim-su/dnska/pkg/dns/types"
	"github.com/vadim-su/dnska/pkg/dns/utils"
)

// DNSRequest represents a full DNS request message.
type DNSRequest struct {
	Header            DNSHeader
	Questions         []DNSQuestion
	Answers           []DNSAnswer
	AuthorityRecords  []DNSAnswer
	AdditionalRecords []DNSAnswer
}

// NewDNSRequest creates a new DNS request from raw byte data with comprehensive
// validation and error handling.
//
// Args:
//
//	data: Raw DNS packet bytes to parse.
//
// Returns:
//
//	Parsed DNSRequest struct and any parsing error.
func NewDNSRequest(data []byte) (*DNSRequest, error) {
	// Validate minimum required length for DNS header (12 bytes)
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid DNS request: empty data provided")
	}

	if len(data) < 12 {
		return nil, fmt.Errorf(
			"invalid DNS request: data too short (%d bytes, need at least 12 for header)",
			len(data),
		)
	}

	// Parse DNS header
	header, headerParseError := parseHeaderFromBytes(data[:12])
	if headerParseError != nil {
		return nil, fmt.Errorf("failed to parse DNS header: %w", headerParseError)
	}

	// Calculate total expected records for validation
	totalExpectedRecords := header.QuestionCount + header.AnswerRecordCount +
		header.AuthorityRecordCount + header.AdditionalRecordCount

	// Validate reasonable limits to prevent memory exhaustion
	const maxReasonableRecords = 10000
	if totalExpectedRecords > maxReasonableRecords {
		return nil, fmt.Errorf(
			"invalid DNS request: unreasonable number of total records (%d), maximum allowed: %d",
			totalExpectedRecords,
			maxReasonableRecords,
		)
	}

	originalMessage := data
	remainingData := data[12:]
	currentOffset := uint16(12)

	// Parse questions section
	questions, questionsSize, questionsError := parseQuestionsSection(
		remainingData,
		header.QuestionCount,
		originalMessage,
	)
	if questionsError != nil {
		return nil, fmt.Errorf("failed to parse questions section: %w", questionsError)
	}

	remainingData = advanceDataPointer(remainingData, questionsSize)
	currentOffset += questionsSize

	// Parse answers section
	answers, answersSize, answersError := parseAnswersSection(
		remainingData,
		header.AnswerRecordCount,
		originalMessage,
	)
	if answersError != nil {
		return nil, fmt.Errorf("failed to parse answers section: %w", answersError)
	}

	remainingData = advanceDataPointer(remainingData, answersSize)
	currentOffset += answersSize

	// Parse authority records section
	authorityRecords, authoritySize, authorityError := parseAnswersSection(
		remainingData,
		header.AuthorityRecordCount,
		originalMessage,
	)
	if authorityError != nil {
		return nil, fmt.Errorf("failed to parse authority records section: %w", authorityError)
	}

	remainingData = advanceDataPointer(remainingData, authoritySize)
	currentOffset += authoritySize

	// Parse additional records section
	additionalRecords, _, additionalError := parseAnswersSection(
		remainingData,
		header.AdditionalRecordCount,
		originalMessage,
	)
	if additionalError != nil {
		return nil, fmt.Errorf("failed to parse additional records section: %w", additionalError)
	}

	return &DNSRequest{
		Header:            header,
		Questions:         questions,
		Answers:           answers,
		AuthorityRecords:  authorityRecords,
		AdditionalRecords: additionalRecords,
	}, nil
}

// parseHeaderFromBytes parses DNS header from exactly 12 bytes of data.
func parseHeaderFromBytes(headerData []byte) (DNSHeader, error) {
	if len(headerData) != 12 {
		return DNSHeader{}, fmt.Errorf(
			"invalid header data length: expected 12 bytes, got %d",
			len(headerData),
		)
	}

	header := DNSHeader{
		ID:                    uint16(headerData[0])<<8 | uint16(headerData[1]),
		Flags:                 types.DNSFlag(uint16(headerData[2])<<8 | uint16(headerData[3])),
		QuestionCount:         uint16(headerData[4])<<8 | uint16(headerData[5]),
		AnswerRecordCount:     uint16(headerData[6])<<8 | uint16(headerData[7]),
		AuthorityRecordCount:  uint16(headerData[8])<<8 | uint16(headerData[9]),
		AdditionalRecordCount: uint16(headerData[10])<<8 | uint16(headerData[11]),
	}

	return header, nil
}

// parseQuestionsSection parses the questions section of a DNS message.
func parseQuestionsSection(
	data []byte,
	questionCount uint16,
	originalMessage []byte,
) ([]DNSQuestion, uint16, error) {
	if questionCount == 0 {
		return []DNSQuestion{}, 0, nil
	}

	if len(data) == 0 {
		return nil, 0, fmt.Errorf(
			"no data remaining for %d expected questions",
			questionCount,
		)
	}

	// Safely call NewDNSQuestions with panic recovery
	var questions []DNSQuestion
	var size uint16
	var parseError error

	func() {
		defer func() {
			if recovery := recover(); recovery != nil {
				parseError = fmt.Errorf("panic during questions parsing: %v", recovery)
			}
		}()
		questions, size, parseError = NewDNSQuestions(data, questionCount, originalMessage)
	}()

	if parseError != nil {
		return nil, 0, parseError
	}

	// Validate that we consumed the expected amount of data
	if uint16(len(data)) < size {
		return nil, 0, fmt.Errorf(
			"insufficient data for questions: need %d bytes, have %d",
			size,
			len(data),
		)
	}

	return questions, size, nil
}

// parseAnswersSection parses answer, authority, or additional records section.
func parseAnswersSection(
	data []byte,
	recordCount uint16,
	originalMessage []byte,
) ([]DNSAnswer, uint16, error) {
	if recordCount == 0 {
		return []DNSAnswer{}, 0, nil
	}

	if len(data) == 0 {
		return nil, 0, fmt.Errorf(
			"no data remaining for %d expected records",
			recordCount,
		)
	}

	// Safely call NewDNSAnswers with panic recovery
	var answers []DNSAnswer
	var size uint16
	var parseError error

	func() {
		defer func() {
			if recovery := recover(); recovery != nil {
				parseError = fmt.Errorf("panic during records parsing: %v", recovery)
			}
		}()
		answers, size, parseError = NewDNSAnswers(data, recordCount, originalMessage)
	}()

	if parseError != nil {
		return nil, 0, parseError
	}

	return answers, size, nil
}

// advanceDataPointer safely advances the data slice by the specified number of bytes.
func advanceDataPointer(data []byte, bytesToAdvance uint16) []byte {
	if uint16(len(data)) < bytesToAdvance {
		return []byte{}
	}
	return data[bytesToAdvance:]
}

// ToBytes converts the DNSRequest to its byte representation.
func (request *DNSRequest) ToBytes() []byte {
	result := request.Header.ToBytes()

	for _, question := range request.Questions {
		result = append(result, question.ToBytes()...)
	}

	for _, answer := range request.Answers {
		result = append(result, answer.ToBytes()...)
	}

	for _, authorityRecord := range request.AuthorityRecords {
		result = append(result, authorityRecord.ToBytes()...)
	}

	for _, additionalRecord := range request.AdditionalRecords {
		result = append(result, additionalRecord.ToBytes()...)
	}

	return result
}

// ToBytesWithCompression converts the DNSRequest to bytes using DNS name compression.
func (request *DNSRequest) ToBytesWithCompression() []byte {
	compressionMap := utils.NewCompressionMap()
	result := request.Header.ToBytes()
	currentOffset := uint16(12) // Header is always 12 bytes

	for _, question := range request.Questions {
		questionBytes := question.ToBytesWithCompression(compressionMap, currentOffset)
		result = append(result, questionBytes...)
		currentOffset += uint16(len(questionBytes))
	}

	for _, answer := range request.Answers {
		answerBytes := answer.ToBytesWithCompression(compressionMap, currentOffset)
		result = append(result, answerBytes...)
		currentOffset += uint16(len(answerBytes))
	}

	for _, authorityRecord := range request.AuthorityRecords {
		authorityBytes := authorityRecord.ToBytesWithCompression(compressionMap, currentOffset)
		result = append(result, authorityBytes...)
		currentOffset += uint16(len(authorityBytes))
	}

	for _, additionalRecord := range request.AdditionalRecords {
		additionalBytes := additionalRecord.ToBytesWithCompression(compressionMap, currentOffset)
		result = append(result, additionalBytes...)
		currentOffset += uint16(len(additionalBytes))
	}

	return result
}

// String returns a human-readable representation of the DNS request.
func (request *DNSRequest) String() string {
	return fmt.Sprintf(
		"DNSRequest{ID: %d, Questions: %d, Answers: %d, Authority: %d, Additional: %d}",
		request.Header.ID,
		len(request.Questions),
		len(request.Answers),
		len(request.AuthorityRecords),
		len(request.AdditionalRecords),
	)
}
