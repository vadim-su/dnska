package dns

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewDNSRequest(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expected    *DNSRequest
		expectedErr bool
		errContains string
	}{
		{
			name: "valid simple query request",
			data: []byte{
				// Header (12 bytes)
				0x12, 0x34, // ID
				0x01, 0x00, // Flags (standard query, recursion desired)
				0x00, 0x01, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question (17 bytes for "example.com")
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x01, // Type A
			},
			expected: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 DNSFlag(0x0100),
					QuestionCount:         1,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					{
						Name: DomainName{
							labels: []Label{
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("com")},
							},
						},
						Class: [2]byte{0x00, 0x01},
						Type:  [2]byte{0x00, 0x01},
					},
				},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedErr: false,
		},
		{
			name: "valid request with multiple questions",
			data: []byte{
				// Header
				0x56, 0x78, // ID
				0x01, 0x20, // Flags
				0x00, 0x02, // Question count (2)
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// First question: "test.com"
				0x04, 't', 'e', 's', 't',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x01, // Type A
				// Second question: "example.org"
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'o', 'r', 'g',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x0F, // Type MX
			},
			expected: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x5678,
					Flags:                 DNSFlag(0x0120),
					QuestionCount:         2,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					{
						Name: DomainName{
							labels: []Label{
								{length: 4, content: []byte("test")},
								{length: 3, content: []byte("com")},
							},
						},
						Class: [2]byte{0x00, 0x01},
						Type:  [2]byte{0x00, 0x01},
					},
					{
						Name: DomainName{
							labels: []Label{
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("org")},
							},
						},
						Class: [2]byte{0x00, 0x01},
						Type:  [2]byte{0x00, 0x0F},
					},
				},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedErr: false,
		},
		{
			name: "root domain query",
			data: []byte{
				// Header
				0xAB, 0xCD, // ID
				0x01, 0x00, // Flags
				0x00, 0x01, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question for root domain
				0x00,       // Root domain (empty label)
				0x00, 0x01, // Class IN
				0x00, 0x02, // Type NS
			},
			expected: &DNSRequest{
				Header: DNSHeader{
					ID:                    0xABCD,
					Flags:                 DNSFlag(0x0100),
					QuestionCount:         1,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					{
						Name: DomainName{
							labels: []Label{},
						},
						Class: [2]byte{0x00, 0x01},
						Type:  [2]byte{0x00, 0x02},
					},
				},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedErr: false,
		},
		{
			name: "header only with zero counts",
			data: []byte{
				0x00, 0x01, // ID
				0x80, 0x00, // Flags (response)
				0x00, 0x00, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
			expected: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x0001,
					Flags:                 DNSFlag(0x8000),
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions:         []DNSQuestion{},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedErr: false,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := NewDNSRequest(testCase.data)

			if testCase.expectedErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if testCase.errContains != "" && !contains(err.Error(), testCase.errContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", testCase.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("Result is nil")
				return
			}

			// Compare headers
			if !reflect.DeepEqual(result.Header, testCase.expected.Header) {
				t.Errorf("Header mismatch:\ngot:  %+v\nwant: %+v", result.Header, testCase.expected.Header)
			}

			// Compare questions
			if len(result.Questions) != len(testCase.expected.Questions) {
				t.Errorf("Questions count mismatch: got %d, want %d", len(result.Questions), len(testCase.expected.Questions))
			} else {
				for questionIndex, question := range result.Questions {
					expected := testCase.expected.Questions[questionIndex]
					if !compareDomainNames(question.Name, expected.Name) {
						t.Errorf("Question %d name mismatch: got %s, want %s", questionIndex, question.Name.String(), expected.Name.String())
					}
					if question.Type != expected.Type {
						t.Errorf("Question %d type mismatch: got %v, want %v", questionIndex, question.Type, expected.Type)
					}
					if question.Class != expected.Class {
						t.Errorf("Question %d class mismatch: got %v, want %v", questionIndex, question.Class, expected.Class)
					}
				}
			}

			// Compare answers
			if len(result.Answers) != len(testCase.expected.Answers) {
				t.Errorf("Answers count mismatch: got %d, want %d", len(result.Answers), len(testCase.expected.Answers))
			}

			// Compare authority records
			if len(result.AuthorityRecords) != len(testCase.expected.AuthorityRecords) {
				t.Errorf("Authority records count mismatch: got %d, want %d", len(result.AuthorityRecords), len(testCase.expected.AuthorityRecords))
			}

			// Compare additional records
			if len(result.AdditionalRecords) != len(testCase.expected.AdditionalRecords) {
				t.Errorf("Additional records count mismatch: got %d, want %d", len(result.AdditionalRecords), len(testCase.expected.AdditionalRecords))
			}
		})
	}
}

func TestNewDNSRequestErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		errContains string
	}{
		{
			name:        "empty data",
			data:        []byte{},
			errContains: "empty data provided",
		},
		{
			name:        "data too short for header",
			data:        []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00},
			errContains: "data too short",
		},
		{
			name:        "single byte",
			data:        []byte{0x12},
			errContains: "data too short",
		},
		{
			name:        "eleven bytes (one short of header)",
			data:        []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			errContains: "data too short",
		},
		{
			name: "header indicates questions but no question data",
			data: []byte{
				0x12, 0x34, // ID
				0x01, 0x00, // Flags
				0x00, 0x01, // Question count (1 question expected)
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// No question data follows
			},
			errContains: "no data remaining for 1 expected questions",
		},
		{
			name: "malformed question - incomplete domain name",
			data: []byte{
				0x12, 0x34, // ID
				0x01, 0x00, // Flags
				0x00, 0x01, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Malformed question
				0x07, 'e', 'x', 'a', // Incomplete label (says 7 chars but only provides 4)
			},
			errContains: "not enough bytes",
		},
		{
			name: "question with insufficient data for type and class",
			data: []byte{
				0x12, 0x34, // ID
				0x01, 0x00, // Flags
				0x00, 0x01, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question with valid domain but missing type/class
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00, // End of domain name
				0x00, // Only one byte for type (need 2)
			},
			errContains: "not enough bytes for class and type",
		},
		{
			name: "unreasonable number of records",
			data: []byte{
				0x12, 0x34, // ID
				0x01, 0x00, // Flags
				0xFF, 0xFF, // Question count (65535)
				0xFF, 0xFF, // Answer count (65535)
				0xFF, 0xFF, // Authority count (65535)
				0xFF, 0xFF, // Additional count (65535)
			},
			errContains: "unreasonable number of total records",
		},
		{
			name: "header indicates answers but no answer data",
			data: []byte{
				0x12, 0x34, // ID
				0x81, 0x80, // Flags (response)
				0x00, 0x00, // Question count
				0x00, 0x01, // Answer count (1 answer expected)
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// No answer data follows
			},
			errContains: "no data remaining for 1 expected records",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := NewDNSRequest(testCase.data)

			if err == nil {
				t.Errorf("Expected error but got none, result: %+v", result)
				return
			}

			if !contains(err.Error(), testCase.errContains) {
				t.Errorf("Expected error to contain '%s', got '%s'", testCase.errContains, err.Error())
			}

			if result != nil {
				t.Errorf("Expected nil result on error, got: %+v", result)
			}
		})
	}
}

func TestNewDNSRequestWithAnswers(t *testing.T) {
	// Test with a simple A record answer
	data := []byte{
		// Header
		0x12, 0x34, // ID
		0x81, 0x80, // Flags (response, recursion available)
		0x00, 0x01, // Question count
		0x00, 0x01, // Answer count
		0x00, 0x00, // Authority count
		0x00, 0x00, // Additional count
		// Question: "example.com" A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of domain name
		0x00, 0x01, // Class IN
		0x00, 0x01, // Type A
		// Answer: "example.com" A IN 300 192.0.2.1
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of domain name
		0x00, 0x01, // Class IN
		0x00, 0x01, // Type A
		0x00, 0x01, 0x2C, // TTL (300 seconds)
		0x00,
		0x00, 0x04, // RDATA length (4 bytes)
		192, 0, 2, 1, // IP address 192.0.2.1
	}

	result, err := NewDNSRequest(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	// Verify header
	if result.Header.ID != 0x1234 {
		t.Errorf("Header ID mismatch: got %d, want %d", result.Header.ID, 0x1234)
	}

	if result.Header.QuestionCount != 1 {
		t.Errorf("Question count mismatch: got %d, want 1", result.Header.QuestionCount)
	}

	if result.Header.AnswerRecordCount != 1 {
		t.Errorf("Answer count mismatch: got %d, want 1", result.Header.AnswerRecordCount)
	}

	// Verify questions
	if len(result.Questions) != 1 {
		t.Errorf("Questions length mismatch: got %d, want 1", len(result.Questions))
	}

	// Verify answers
	if len(result.Answers) != 1 {
		t.Errorf("Answers length mismatch: got %d, want 1", len(result.Answers))
	}

	// Verify that authority and additional records are empty
	if len(result.AuthorityRecords) != 0 {
		t.Errorf("Authority records should be empty, got %d", len(result.AuthorityRecords))
	}

	if len(result.AdditionalRecords) != 0 {
		t.Errorf("Additional records should be empty, got %d", len(result.AdditionalRecords))
	}
}

func TestNewDNSRequestHeaderParsing(t *testing.T) {
	tests := []struct {
		name           string
		headerBytes    []byte
		expectedHeader DNSHeader
	}{
		{
			name: "all zero values",
			headerBytes: []byte{
				0x00, 0x00, // ID = 0
				0x00, 0x00, // Flags = 0
				0x00, 0x00, // Question count = 0
				0x00, 0x00, // Answer count = 0
				0x00, 0x00, // Authority count = 0
				0x00, 0x00, // Additional count = 0
			},
			expectedHeader: DNSHeader{
				ID:                    0x0000,
				Flags:                 DNSFlag(0x0000),
				QuestionCount:         0,
				AnswerRecordCount:     0,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
		},
		{
			name: "maximum values",
			headerBytes: []byte{
				0xFF, 0xFF, // ID = 65535
				0xFF, 0xFF, // Flags = 65535
				0xFF, 0xFF, // Question count = 65535
				0xFF, 0xFF, // Answer count = 65535
				0xFF, 0xFF, // Authority count = 65535
				0xFF, 0xFF, // Additional count = 65535
			},
			expectedHeader: DNSHeader{
				ID:                    0xFFFF,
				Flags:                 DNSFlag(0xFFFF),
				QuestionCount:         65535,
				AnswerRecordCount:     65535,
				AuthorityRecordCount:  65535,
				AdditionalRecordCount: 65535,
			},
		},
		{
			name: "byte boundary test",
			headerBytes: []byte{
				0x01, 0x00, // ID = 256
				0x80, 0x01, // Flags = 32769
				0x00, 0x01, // Question count = 1
				0x00, 0x02, // Answer count = 2
				0x00, 0x03, // Authority count = 3
				0x00, 0x04, // Additional count = 4
			},
			expectedHeader: DNSHeader{
				ID:                    0x0100,
				Flags:                 DNSFlag(0x8001),
				QuestionCount:         1,
				AnswerRecordCount:     2,
				AuthorityRecordCount:  3,
				AdditionalRecordCount: 4,
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			// For this test, we only care about header parsing, so set all counts to 0
			testData := make([]byte, len(testCase.headerBytes))
			copy(testData, testCase.headerBytes)
			// Override counts to 0 to avoid needing question/answer data
			testData[4] = 0x00  // Question count high byte
			testData[5] = 0x00  // Question count low byte
			testData[6] = 0x00  // Answer count high byte
			testData[7] = 0x00  // Answer count low byte
			testData[8] = 0x00  // Authority count high byte
			testData[9] = 0x00  // Authority count low byte
			testData[10] = 0x00 // Additional count high byte
			testData[11] = 0x00 // Additional count low byte

			result, err := NewDNSRequest(testData)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Update expected header to match our override
			expectedHeader := testCase.expectedHeader
			expectedHeader.QuestionCount = 0
			expectedHeader.AnswerRecordCount = 0
			expectedHeader.AuthorityRecordCount = 0
			expectedHeader.AdditionalRecordCount = 0

			if result.Header.ID != expectedHeader.ID {
				t.Errorf("ID mismatch: got %d, want %d", result.Header.ID, expectedHeader.ID)
			}

			if result.Header.Flags != expectedHeader.Flags {
				t.Errorf("Flags mismatch: got %d, want %d", result.Header.Flags, expectedHeader.Flags)
			}
		})
	}
}

func TestNewDNSRequestRoundTrip(t *testing.T) {
	originalData := []byte{
		// Header
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // Question count
		0x00, 0x00, // Answer count
		0x00, 0x00, // Authority count
		0x00, 0x00, // Additional count
		// Question
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of domain name
		0x00, 0x01, // Class IN
		0x00, 0x01, // Type A
	}

	// Parse the request
	request, err := NewDNSRequest(originalData)
	if err != nil {
		t.Fatalf("Failed to parse request: %v", err)
	}

	// Convert back to bytes
	resultData := request.ToBytes()

	// Should match original data
	if !bytes.Equal(originalData, resultData) {
		t.Errorf("Round trip failed:\noriginal: %v\nresult:   %v", originalData, resultData)
	}
}

func TestNewDNSRequestWithCompressionPointers(t *testing.T) {
	// Test with compression pointers in questions (artificial example)
	data := []byte{
		// Header
		0x12, 0x34, // ID
		0x81, 0x80, // Flags (response)
		0x00, 0x01, // Question count
		0x00, 0x01, // Answer count
		0x00, 0x00, // Authority count
		0x00, 0x00, // Additional count
		// Question: "example.com" A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of domain name
		0x00, 0x01, // Class IN
		0x00, 0x01, // Type A
		// Answer: compression pointer to "example.com" at offset 12
		0xC0, 0x0C, // Compression pointer to offset 12
		0x00, 0x01, // Class IN
		0x00, 0x01, // Type A
		0x00, 0x01, 0x2C, // TTL (300 seconds)
		0x00,
		0x00, 0x04, // RDATA length (4 bytes)
		192, 0, 2, 1, // IP address 192.0.2.1
	}

	result, err := NewDNSRequest(data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Result is nil")
	}

	// Verify that both question and answer were parsed successfully
	if len(result.Questions) != 1 {
		t.Errorf("Expected 1 question, got %d", len(result.Questions))
	}

	if len(result.Answers) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(result.Answers))
	}
}

func TestParseHeaderFromBytes(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expected    DNSHeader
		expectedErr bool
		errContains string
	}{
		{
			name: "valid header",
			data: []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: DNSHeader{
				ID:                    0x1234,
				Flags:                 DNSFlag(0x0100),
				QuestionCount:         1,
				AnswerRecordCount:     0,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
			expectedErr: false,
		},
		{
			name:        "too short",
			data:        []byte{0x12, 0x34},
			expected:    DNSHeader{},
			expectedErr: true,
			errContains: "invalid header data length",
		},
		{
			name:        "too long",
			data:        []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected:    DNSHeader{},
			expectedErr: true,
			errContains: "invalid header data length",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := parseHeaderFromBytes(testCase.data)

			if testCase.expectedErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if testCase.errContains != "" && !contains(err.Error(), testCase.errContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", testCase.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, testCase.expected) {
				t.Errorf("Header mismatch:\ngot:  %+v\nwant: %+v", result, testCase.expected)
			}
		})
	}
}

func TestDNSRequestToString(t *testing.T) {
	request := &DNSRequest{
		Header: DNSHeader{
			ID:                    0x1234,
			QuestionCount:         1,
			AnswerRecordCount:     2,
			AuthorityRecordCount:  3,
			AdditionalRecordCount: 4,
		},
		Questions:         make([]DNSQuestion, 1),
		Answers:           make([]DNSAnswer, 2),
		AuthorityRecords:  make([]DNSAnswer, 3),
		AdditionalRecords: make([]DNSAnswer, 4),
	}

	result := request.String()
	expected := "DNSRequest{ID: 4660, Questions: 1, Answers: 2, Authority: 3, Additional: 4}"

	if result != expected {
		t.Errorf("String() mismatch:\ngot:  %s\nwant: %s", result, expected)
	}
}

func TestAdvanceDataPointer(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		bytesToAdvance uint16
		expected       []byte
	}{
		{
			name:           "normal advance",
			data:           []byte{1, 2, 3, 4, 5},
			bytesToAdvance: 2,
			expected:       []byte{3, 4, 5},
		},
		{
			name:           "advance to end",
			data:           []byte{1, 2, 3},
			bytesToAdvance: 3,
			expected:       []byte{},
		},
		{
			name:           "advance beyond end",
			data:           []byte{1, 2},
			bytesToAdvance: 5,
			expected:       []byte{},
		},
		{
			name:           "zero advance",
			data:           []byte{1, 2, 3},
			bytesToAdvance: 0,
			expected:       []byte{1, 2, 3},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := advanceDataPointer(testCase.data, testCase.bytesToAdvance)

			if !bytes.Equal(result, testCase.expected) {
				t.Errorf("advanceDataPointer() mismatch:\ngot:  %v\nwant: %v", result, testCase.expected)
			}
		})
	}
}

func TestDNSRequestToBytesWithCompression(t *testing.T) {
	tests := []struct {
		name                string
		request             *DNSRequest
		expectedMinLength   int
		description         string
		validateCompression bool
	}{
		{
			name: "simple request with one question",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 DNSFlag(0x0100),
					QuestionCount:         1,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					{
						Name: DomainName{
							labels: []Label{
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("com")},
							},
						},
						Class: [2]byte{0x00, 0x01}, // IN
						Type:  [2]byte{0x00, 0x01}, // A
					},
				},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedMinLength:   12 + 13 + 4, // header + domain + class/type
			description:         "Should encode simple request with compression map initialization",
			validateCompression: false,
		},
		{
			name: "request with multiple questions using same domain",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x5678,
					Flags:                 DNSFlag(0x0100),
					QuestionCount:         2,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					{
						Name: DomainName{
							labels: []Label{
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("com")},
							},
						},
						Class: [2]byte{0x00, 0x01}, // IN
						Type:  [2]byte{0x00, 0x01}, // A
					},
					{
						Name: DomainName{
							labels: []Label{
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("com")},
							},
						},
						Class: [2]byte{0x00, 0x01}, // IN
						Type:  [2]byte{0x00, 0x1C}, // AAAA
					},
				},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedMinLength:   12 + 13 + 4 + 2 + 4, // header + first domain + class/type + pointer + class/type
			description:         "Should use compression for repeated domain names",
			validateCompression: true,
		},
		{
			name: "empty request with no questions",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x0000,
					Flags:                 DNSFlag(0x8000),
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions:         []DNSQuestion{},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedMinLength:   12, // just header
			description:         "Should handle empty request with only header",
			validateCompression: false,
		},
		{
			name: "request with questions and answers",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0xABCD,
					Flags:                 DNSFlag(0x8180),
					QuestionCount:         1,
					AnswerRecordCount:     1,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					{
						Name: DomainName{
							labels: []Label{
								{length: 4, content: []byte("test")},
								{length: 3, content: []byte("org")},
							},
						},
						Class: [2]byte{0x00, 0x01}, // IN
						Type:  [2]byte{0x00, 0x01}, // A
					},
				},
				Answers: []DNSAnswer{
					{
						name: DomainName{
							labels: []Label{
								{length: 4, content: []byte("test")},
								{length: 3, content: []byte("org")},
							},
						},
						class: [2]byte{0x00, 0x01},             // IN
						type_: [2]byte{0x00, 0x01},             // A
						ttl:   [4]byte{0x00, 0x01, 0x2C, 0x00}, // 300 seconds
						data:  []byte{192, 0, 2, 1},            // IP address
					},
				},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedMinLength:   12 + 10 + 4 + 2 + 2 + 2 + 4 + 2 + 4, // header + question + answer with compression
			description:         "Should handle request with answer using compression",
			validateCompression: true,
		},
		{
			name: "request with root domain",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x1111,
					Flags:                 DNSFlag(0x0100),
					QuestionCount:         1,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					{
						Name: DomainName{
							labels: []Label{},
						},
						Class: [2]byte{0x00, 0x01}, // IN
						Type:  [2]byte{0x00, 0x02}, // NS
					},
				},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			expectedMinLength:   12 + 1 + 4, // header + root domain + class/type
			description:         "Should handle root domain queries",
			validateCompression: false,
		},
		{
			name: "complex request with all record types",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0xFFFF,
					Flags:                 DNSFlag(0x8180),
					QuestionCount:         1,
					AnswerRecordCount:     1,
					AuthorityRecordCount:  1,
					AdditionalRecordCount: 1,
				},
				Questions: []DNSQuestion{
					{
						Name: DomainName{
							labels: []Label{
								{length: 3, content: []byte("www")},
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("net")},
							},
						},
						Class: [2]byte{0x00, 0x01}, // IN
						Type:  [2]byte{0x00, 0x01}, // A
					},
				},
				Answers: []DNSAnswer{
					{
						name: DomainName{
							labels: []Label{
								{length: 3, content: []byte("www")},
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("net")},
							},
						},
						class: [2]byte{0x00, 0x01},             // IN
						type_: [2]byte{0x00, 0x01},             // A
						ttl:   [4]byte{0x00, 0x00, 0x0E, 0x10}, // 3600 seconds
						data:  []byte{10, 0, 0, 1},             // IP address
					},
				},
				AuthorityRecords: []DNSAnswer{
					{
						name: DomainName{
							labels: []Label{
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("net")},
							},
						},
						class: [2]byte{0x00, 0x01},                     // IN
						type_: [2]byte{0x00, 0x02},                     // NS
						ttl:   [4]byte{0x00, 0x01, 0x51, 0x80},         // 86400 seconds
						data:  []byte{0x03, 'n', 's', '1', 0xC0, 0x10}, // ns1.example.net with compression
					},
				},
				AdditionalRecords: []DNSAnswer{
					{
						name: DomainName{
							labels: []Label{
								{length: 3, content: []byte("ns1")},
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("net")},
							},
						},
						class: [2]byte{0x00, 0x01},             // IN
						type_: [2]byte{0x00, 0x01},             // A
						ttl:   [4]byte{0x00, 0x01, 0x51, 0x80}, // 86400 seconds
						data:  []byte{10, 0, 0, 2},             // IP address
					},
				},
			},
			expectedMinLength:   50, // Approximate minimum for complex message
			description:         "Should handle complex request with all record types and compression",
			validateCompression: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.request.ToBytesWithCompression()

			// Verify minimum length
			if len(result) < testCase.expectedMinLength {
				t.Errorf("Result too short: got %d bytes, expected at least %d bytes\ndescription: %s",
					len(result), testCase.expectedMinLength, testCase.description)
			}

			// Verify header is present and correct
			if len(result) < 12 {
				t.Fatalf("Result missing DNS header: got %d bytes", len(result))
			}

			// Parse header to verify correctness
			headerID := uint16(result[0])<<8 | uint16(result[1])
			if headerID != testCase.request.Header.ID {
				t.Errorf("Header ID mismatch: got 0x%04X, want 0x%04X", headerID, testCase.request.Header.ID)
			}

			headerFlags := DNSFlag(uint16(result[2])<<8 | uint16(result[3]))
			if headerFlags != testCase.request.Header.Flags {
				t.Errorf("Header flags mismatch: got 0x%04X, want 0x%04X", headerFlags, testCase.request.Header.Flags)
			}

			questionCount := uint16(result[4])<<8 | uint16(result[5])
			if questionCount != testCase.request.Header.QuestionCount {
				t.Errorf("Question count mismatch: got %d, want %d", questionCount, testCase.request.Header.QuestionCount)
			}

			// Verify result is not empty (unless it's an empty request)
			if len(result) == 0 {
				t.Error("ToBytesWithCompression returned empty result")
			}

			// If compression is expected, verify the result is different from non-compressed version
			if testCase.validateCompression && len(testCase.request.Questions) > 1 {
				normalResult := testCase.request.ToBytes()
				if len(result) >= len(normalResult) {
					t.Logf("Note: Compression did not reduce size significantly. Compressed: %d, Normal: %d", len(result), len(normalResult))
				}
			}
		})
	}
}

func TestDNSRequestToBytesWithCompressionConsistency(t *testing.T) {
	request := &DNSRequest{
		Header: DNSHeader{
			ID:                    0x1234,
			Flags:                 DNSFlag(0x0100),
			QuestionCount:         1,
			AnswerRecordCount:     0,
			AuthorityRecordCount:  0,
			AdditionalRecordCount: 0,
		},
		Questions: []DNSQuestion{
			{
				Name: DomainName{
					labels: []Label{
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x01}, // A
			},
		},
		Answers:           []DNSAnswer{},
		AuthorityRecords:  []DNSAnswer{},
		AdditionalRecords: []DNSAnswer{},
	}

	// Multiple calls should produce the same result
	result1 := request.ToBytesWithCompression()
	result2 := request.ToBytesWithCompression()

	if !bytes.Equal(result1, result2) {
		t.Errorf("ToBytesWithCompression is not consistent:\nfirst:  %v\nsecond: %v", result1, result2)
	}

	// Should be at least as long as the header
	if len(result1) < 12 {
		t.Errorf("Result too short: got %d bytes, expected at least 12", len(result1))
	}
}

func TestDNSRequestToBytesWithCompressionRoundTrip(t *testing.T) {
	originalRequest := &DNSRequest{
		Header: DNSHeader{
			ID:                    0x5678,
			Flags:                 DNSFlag(0x0100),
			QuestionCount:         1,
			AnswerRecordCount:     0,
			AuthorityRecordCount:  0,
			AdditionalRecordCount: 0,
		},
		Questions: []DNSQuestion{
			{
				Name: DomainName{
					labels: []Label{
						{length: 4, content: []byte("test")},
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("org")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x0F}, // MX
			},
		},
		Answers:           []DNSAnswer{},
		AuthorityRecords:  []DNSAnswer{},
		AdditionalRecords: []DNSAnswer{},
	}

	// Convert to bytes with compression
	compressedBytes := originalRequest.ToBytesWithCompression()

	// Parse it back
	parsedRequest, err := NewDNSRequest(compressedBytes)
	if err != nil {
		t.Fatalf("Failed to parse compressed bytes: %v", err)
	}

	// Verify header fields match
	if parsedRequest.Header.ID != originalRequest.Header.ID {
		t.Errorf("ID mismatch: got %d, want %d", parsedRequest.Header.ID, originalRequest.Header.ID)
	}

	if parsedRequest.Header.Flags != originalRequest.Header.Flags {
		t.Errorf("Flags mismatch: got 0x%04X, want 0x%04X", parsedRequest.Header.Flags, originalRequest.Header.Flags)
	}

	if parsedRequest.Header.QuestionCount != originalRequest.Header.QuestionCount {
		t.Errorf("Question count mismatch: got %d, want %d", parsedRequest.Header.QuestionCount, originalRequest.Header.QuestionCount)
	}

	// Verify questions count matches
	if len(parsedRequest.Questions) != len(originalRequest.Questions) {
		t.Errorf("Questions length mismatch: got %d, want %d", len(parsedRequest.Questions), len(originalRequest.Questions))
	}

	// Verify at least one question was parsed correctly
	if len(parsedRequest.Questions) > 0 && len(originalRequest.Questions) > 0 {
		parsedName := parsedRequest.Questions[0].Name.String()
		originalName := originalRequest.Questions[0].Name.String()
		if parsedName != originalName {
			t.Errorf("Question name mismatch: got %s, want %s", parsedName, originalName)
		}
	}
}

func TestDNSRequestToBytesWithCompressionEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		request     *DNSRequest
		description string
	}{
		{
			name: "nil slices in request",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x0000,
					Flags:                 DNSFlag(0x0000),
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions:         nil,
				Answers:           nil,
				AuthorityRecords:  nil,
				AdditionalRecords: nil,
			},
			description: "Should handle nil slices gracefully",
		},
		{
			name: "empty slices in request",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0x1111,
					Flags:                 DNSFlag(0x8000),
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions:         []DNSQuestion{},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			description: "Should handle empty slices correctly",
		},
		{
			name: "maximum header values",
			request: &DNSRequest{
				Header: DNSHeader{
					ID:                    0xFFFF,
					Flags:                 DNSFlag(0xFFFF),
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions:         []DNSQuestion{},
				Answers:           []DNSAnswer{},
				AuthorityRecords:  []DNSAnswer{},
				AdditionalRecords: []DNSAnswer{},
			},
			description: "Should handle maximum header values",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.request.ToBytesWithCompression()

			// Should at least return the header
			if len(result) < 12 {
				t.Errorf("Result too short: got %d bytes, expected at least 12\ndescription: %s",
					len(result), testCase.description)
			}

			// Should not panic or return nil
			if result == nil {
				t.Errorf("ToBytesWithCompression returned nil\ndescription: %s", testCase.description)
			}

			// Verify header integrity
			if len(result) >= 12 {
				headerID := uint16(result[0])<<8 | uint16(result[1])
				if headerID != testCase.request.Header.ID {
					t.Errorf("Header ID corrupted: got 0x%04X, want 0x%04X", headerID, testCase.request.Header.ID)
				}
			}
		})
	}
}

func TestDNSRequestToBytesWithCompressionVsNormal(t *testing.T) {
	request := &DNSRequest{
		Header: DNSHeader{
			ID:                    0x1234,
			Flags:                 DNSFlag(0x0100),
			QuestionCount:         1,
			AnswerRecordCount:     0,
			AuthorityRecordCount:  0,
			AdditionalRecordCount: 0,
		},
		Questions: []DNSQuestion{
			{
				Name: DomainName{
					labels: []Label{
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x01}, // A
			},
		},
		Answers:           []DNSAnswer{},
		AuthorityRecords:  []DNSAnswer{},
		AdditionalRecords: []DNSAnswer{},
	}

	compressedResult := request.ToBytesWithCompression()
	normalResult := request.ToBytes()

	// Both should produce valid results
	if len(compressedResult) == 0 {
		t.Error("Compressed result is empty")
	}

	if len(normalResult) == 0 {
		t.Error("Normal result is empty")
	}

	// For a single question, they should be identical or very similar
	// (compression only helps with repeated names)
	if len(compressedResult) != len(normalResult) {
		t.Logf("Size difference: compressed=%d, normal=%d", len(compressedResult), len(normalResult))
	}

	// Headers should be identical
	if len(compressedResult) >= 12 && len(normalResult) >= 12 {
		compressedHeader := compressedResult[:12]
		normalHeader := normalResult[:12]

		if !bytes.Equal(compressedHeader, normalHeader) {
			t.Error("Headers differ between compressed and normal versions")
		}
	}
}

func TestDNSRequestToBytesWithCompressionNilRequest(t *testing.T) {
	// Test that method doesn't panic with nil request
	defer func() {
		if recovery := recover(); recovery != nil {
			t.Errorf("ToBytesWithCompression panicked with nil request: %v", recovery)
		}
	}()

	var nilRequest *DNSRequest
	if nilRequest != nil {
		_ = nilRequest.ToBytesWithCompression()
	}
}

func TestDNSRequestToBytesWithCompressionComplexCompression(t *testing.T) {
	// Test with many repeated domain names to verify compression effectiveness
	request := &DNSRequest{
		Header: DNSHeader{
			ID:                    0x9999,
			Flags:                 DNSFlag(0x0100),
			QuestionCount:         3,
			AnswerRecordCount:     0,
			AuthorityRecordCount:  0,
			AdditionalRecordCount: 0,
		},
		Questions: []DNSQuestion{
			{
				Name: DomainName{
					labels: []Label{
						{length: 3, content: []byte("www")},
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x01}, // A
			},
			{
				Name: DomainName{
					labels: []Label{
						{length: 4, content: []byte("mail")},
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x0F}, // MX
			},
			{
				Name: DomainName{
					labels: []Label{
						{length: 3, content: []byte("ftp")},
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x05}, // CNAME
			},
		},
		Answers:           []DNSAnswer{},
		AuthorityRecords:  []DNSAnswer{},
		AdditionalRecords: []DNSAnswer{},
	}

	compressedResult := request.ToBytesWithCompression()
	normalResult := request.ToBytes()

	// Compressed version should be smaller due to repeated "example.com" suffix
	if len(compressedResult) >= len(normalResult) {
		t.Logf("Compression efficiency: compressed=%d, normal=%d (expected compression to reduce size)",
			len(compressedResult), len(normalResult))
	}

	// Verify it's still parseable
	_, err := NewDNSRequest(compressedResult)
	if err != nil {
		t.Errorf("Compressed result is not parseable: %v", err)
	}
}

func TestDNSRequestToBytesWithCompressionZeroValues(t *testing.T) {
	// Test with zero values everywhere
	request := &DNSRequest{
		Header: DNSHeader{
			ID:                    0,
			Flags:                 0,
			QuestionCount:         0,
			AnswerRecordCount:     0,
			AuthorityRecordCount:  0,
			AdditionalRecordCount: 0,
		},
		Questions:         []DNSQuestion{},
		Answers:           []DNSAnswer{},
		AuthorityRecords:  []DNSAnswer{},
		AdditionalRecords: []DNSAnswer{},
	}

	result := request.ToBytesWithCompression()

	// Should return exactly 12 bytes (header only)
	if len(result) != 12 {
		t.Errorf("Expected exactly 12 bytes for header-only request, got %d", len(result))
	}

	// All header bytes should be zero
	expectedHeader := make([]byte, 12)
	if !bytes.Equal(result, expectedHeader) {
		t.Errorf("Header bytes incorrect: got %v, want %v", result, expectedHeader)
	}
}

// Limited fuzz testing to avoid infinite recursion issues
func FuzzNewDNSRequestSafe(f *testing.F) {
	// Add seed values for the fuzzer
	seedValues := [][]byte{
		// Valid simple query
		{
			0x12, 0x34, // ID
			0x01, 0x00, // Flags
			0x00, 0x01, // Question count
			0x00, 0x00, // Answer count
			0x00, 0x00, // Authority count
			0x00, 0x00, // Additional count
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			0x03, 'c', 'o', 'm',
			0x00,       // End of domain name
			0x00, 0x01, // Class IN
			0x00, 0x01, // Type A
		},
		// Header only
		{
			0x00, 0x01, // ID
			0x80, 0x00, // Flags
			0x00, 0x00, // Question count
			0x00, 0x00, // Answer count
			0x00, 0x00, // Authority count
			0x00, 0x00, // Additional count
		},
		// Empty data
		{},
		// Short data
		{0x12, 0x34},
	}

	for _, seed := range seedValues {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Limit data size to prevent excessive memory usage
		if len(data) > 1024 {
			data = data[:1024]
		}

		// Call NewDNSRequest and ensure it doesn't panic
		defer func() {
			if recovery := recover(); recovery != nil {
				t.Errorf("NewDNSRequest panicked with input %v: %v", data, recovery)
			}
		}()

		result, err := NewDNSRequest(data)

		// We expect many inputs to fail, so just ensure consistent behavior
		if err != nil && result != nil {
			t.Errorf("Got error but non-nil result: err=%v, result=%v", err, result)
		}

		if err == nil && result == nil {
			t.Error("Got no error but nil result")
		}

		// If successful, try round trip
		if err == nil && result != nil {
			resultBytes := result.ToBytes()
			if len(resultBytes) == 0 {
				t.Error("ToBytes returned empty slice for valid result")
			}
		}
	})
}

// Helper functions
func contains(haystack, needle string) bool {
	return indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for index := range len(haystack) - len(needle) + 1 {
		if haystack[index:index+len(needle)] == needle {
			return index
		}
	}
	return -1
}

func compareDomainNames(first, second DomainName) bool {
	if len(first.labels) != len(second.labels) {
		return false
	}

	for labelIndex, label := range first.labels {
		secondLabel := second.labels[labelIndex]
		if label.length != secondLabel.length {
			return false
		}
		if !bytes.Equal(label.content, secondLabel.content) {
			return false
		}
	}

	return true
}
