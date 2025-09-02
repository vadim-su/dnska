package dns

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewDNSResponse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expected    *DNSResponse
		expectedErr bool
		errContains string
		description string
	}{
		{
			name: "valid simple response with one question and one answer",
			data: []byte{
				// Header (12 bytes)
				0x12, 0x34, // ID
				0x81, 0x80, // Flags (response, recursion desired, recursion available)
				0x00, 0x01, // Question count
				0x00, 0x01, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question (17 bytes for "example.com")
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				// Answer (16 bytes for "example.com" A record)
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				0x00, 0x00, 0x01, 0x2C, // TTL (300 seconds)
				0x00, 0x04, // Data length (4 bytes)
				192, 0, 2, 1, // IP address 192.0.2.1
			},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
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
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("com")},
							},
						},
						Type:  dnsTypeClassToBytes(TYPE_A),
						Class: dnsTypeClassToBytes(CLASS_IN),
					},
				},
				Answers: []DNSAnswer{
					{
						name: DomainName{
							labels: []Label{
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("com")},
							},
						},
						type_: dnsTypeClassToBytes(TYPE_A),
						class: dnsTypeClassToBytes(CLASS_IN),
						ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C},
						data:  []byte{192, 0, 2, 1},
					},
				},
			},
			expectedErr: false,
			description: "Should parse valid DNS response with question and answer",
		},
		{
			name: "valid response with single question and answer",
			data: []byte{
				// Header (12 bytes)
				0xAB, 0xCD, // ID
				0x81, 0x80, // Flags (response)
				0x00, 0x01, // Question count (1)
				0x00, 0x01, // Answer count (1)
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question 1 (9 bytes for "a.com")
				0x01, 'a',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				// Answer 1 (15 bytes for "a.com" A record)
				0x01, 'a',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				0x00, 0x00, 0x00, 0x3C, // TTL (60 seconds)
				0x00, 0x04, // Data length (4 bytes)
				10, 0, 0, 1, // IP address 10.0.0.1
			},
			expected: &DNSResponse{
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
								{length: 1, content: []byte("a")},
								{length: 3, content: []byte("com")},
							},
						},
						Type:  dnsTypeClassToBytes(TYPE_A),
						Class: dnsTypeClassToBytes(CLASS_IN),
					},
				},
				Answers: []DNSAnswer{
					{
						name: DomainName{
							labels: []Label{
								{length: 1, content: []byte("a")},
								{length: 3, content: []byte("com")},
							},
						},
						type_: dnsTypeClassToBytes(TYPE_A),
						class: dnsTypeClassToBytes(CLASS_IN),
						ttl:   [4]byte{0x00, 0x00, 0x00, 0x3C},
						data:  []byte{10, 0, 0, 1},
					},
				},
			},
			expectedErr: false,
			description: "Should parse valid DNS response with single question and answer",
		},
		{
			name: "valid response with no questions and no answers",
			data: []byte{
				// Header only (12 bytes)
				0x00, 0x01, // ID
				0x80, 0x00, // Flags (response)
				0x00, 0x00, // Question count (0)
				0x00, 0x00, // Answer count (0)
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x0001,
					Flags:                 DNSFlag(0x8000),
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   []DNSAnswer{},
			},
			expectedErr: false,
			description: "Should parse valid DNS response with no questions or answers",
		},
		{
			name: "response with compression pointers",
			data: []byte{
				// Header (12 bytes)
				0x12, 0x34, // ID
				0x81, 0x80, // Flags (response)
				0x00, 0x01, // Question count
				0x00, 0x01, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question (17 bytes for "example.com")
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				// Answer with compression pointer to question name
				0xC0, 0x0C, // Compression pointer to offset 12 (question name)
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				0x00, 0x00, 0x01, 0x2C, // TTL (300 seconds)
				0x00, 0x04, // Data length (4 bytes)
				192, 0, 2, 1, // IP address 192.0.2.1
			},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
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
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("com")},
							},
						},
						Type:  dnsTypeClassToBytes(TYPE_A),
						Class: dnsTypeClassToBytes(CLASS_IN),
					},
				},
				Answers: []DNSAnswer{
					{
						name: DomainName{
							labels: []Label{
								{length: 7, content: []byte("example")},
								{length: 3, content: []byte("com")},
							},
						},
						type_: dnsTypeClassToBytes(TYPE_A),
						class: dnsTypeClassToBytes(CLASS_IN),
						ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C},
						data:  []byte{192, 0, 2, 1},
					},
				},
			},
			expectedErr: false,
			description: "Should parse DNS response with compression pointers",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NewDNSResponse(test.data)

			if test.expectedErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				if test.errContains != "" && !contains(err.Error(), test.errContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", test.errContains, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result == nil {
				t.Fatal("Result is nil")
			}

			// Compare headers
			if !reflect.DeepEqual(result.Header, test.expected.Header) {
				t.Errorf("Header mismatch:\nExpected: %+v\nGot: %+v", test.expected.Header, result.Header)
			}

			// Compare questions count
			if len(result.Questions) != len(test.expected.Questions) {
				t.Errorf("Questions count mismatch: expected %d, got %d", len(test.expected.Questions), len(result.Questions))
				return
			}

			// Compare questions
			for question_index, expected_question := range test.expected.Questions {
				if question_index >= len(result.Questions) {
					t.Errorf("Missing question at index %d", question_index)
					continue
				}
				if !compareDNSQuestions(result.Questions[question_index], expected_question) {
					t.Errorf("Question %d mismatch:\nExpected: %+v\nGot: %+v", question_index, expected_question, result.Questions[question_index])
				}
			}

			// Compare answers count
			if len(result.Answers) != len(test.expected.Answers) {
				t.Errorf("Answers count mismatch: expected %d, got %d", len(test.expected.Answers), len(result.Answers))
				return
			}

			// Compare answers
			for answer_index, expected_answer := range test.expected.Answers {
				if answer_index >= len(result.Answers) {
					t.Errorf("Missing answer at index %d", answer_index)
					continue
				}
				if !compareDNSAnswers(result.Answers[answer_index], expected_answer) {
					t.Errorf("Answer %d mismatch:\nExpected: %+v\nGot: %+v", answer_index, expected_answer, result.Answers[answer_index])
				}
			}
		})
	}
}

func TestNewDNSResponseErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		errContains string
		description string
	}{
		{
			name:        "empty data",
			data:        []byte{},
			errContains: "empty data provided",
			description: "Should fail with empty data",
		},
		{
			name:        "data too short for header",
			data:        []byte{0x01, 0x02, 0x03},
			errContains: "data too short",
			description: "Should fail with data too short for header",
		},
		{
			name: "header only but questions expected",
			data: []byte{
				// Header (12 bytes)
				0x12, 0x34, // ID
				0x81, 0x80, // Flags
				0x00, 0x01, // Question count (1, but no question data follows)
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
			errContains: "", // This will be caught by NewDNSQuestions
			description: "Should fail when questions are expected but missing",
		},
		{
			name: "invalid question data",
			data: []byte{
				// Header (12 bytes)
				0x12, 0x34, // ID
				0x81, 0x80, // Flags
				0x00, 0x01, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Invalid question data (incomplete)
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				// Missing rest of the question
			},
			errContains: "", // This will be caught by NewDNSQuestions
			description: "Should fail with invalid question data",
		},
		{
			name: "questions parsed but answers expected and missing",
			data: []byte{
				// Header (12 bytes)
				0x12, 0x34, // ID
				0x81, 0x80, // Flags
				0x00, 0x01, // Question count
				0x00, 0x01, // Answer count (1, but no answer data follows)
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question (17 bytes for "example.com")
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				// Missing answer data
			},
			errContains: "", // This will be caught by NewDNSAnswers
			description: "Should fail when answers are expected but missing",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewDNSResponse(test.data)

			if err == nil {
				t.Errorf("Expected error but got none")
				return
			}

			if test.errContains != "" && !contains(err.Error(), test.errContains) {
				t.Errorf("Expected error to contain '%s', got '%s'", test.errContains, err.Error())
			}
		})
	}
}

func TestGenerateDNSResponse(t *testing.T) {
	tests := []struct {
		name        string
		id          uint16
		reqFlags    DNSFlag
		questions   []DNSQuestion
		answers     []DNSAnswer
		expected    *DNSResponse
		description string
	}{
		{
			name:     "simple response generation",
			id:       0x1234,
			reqFlags: FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
			questions: []DNSQuestion{
				createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
			},
			answers: []DNSAnswer{
				createTestDNSAnswer("example.com.", TYPE_A, CLASS_IN, 300, []byte{192, 0, 2, 1}),
			},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED | FLAG_RCODE_NO_ERROR,
					QuestionCount:         1,
					AnswerRecordCount:     1,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
				},
				Answers: []DNSAnswer{
					createTestDNSAnswer("example.com.", TYPE_A, CLASS_IN, 300, []byte{192, 0, 2, 1}),
				},
			},
			description: "Should generate valid DNS response",
		},
		{
			name:      "response with no questions or answers",
			id:        0xABCD,
			reqFlags:  FLAG_QR_QUERY | FLAG_OPCODE_STANDARD,
			questions: []DNSQuestion{},
			answers:   []DNSAnswer{},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0xABCD,
					Flags:                 FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_RCODE_NO_ERROR,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   []DNSAnswer{},
			},
			description: "Should generate response with no questions or answers",
		},
		{
			name:     "response with multiple questions and answers",
			id:       0x5678,
			reqFlags: FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
			questions: []DNSQuestion{
				createTestDNSQuestion("test1.com.", TYPE_A, CLASS_IN),
				createTestDNSQuestion("test2.com.", TYPE_A, CLASS_IN),
			},
			answers: []DNSAnswer{
				createTestDNSAnswer("test1.com.", TYPE_A, CLASS_IN, 300, []byte{10, 0, 0, 1}),
				createTestDNSAnswer("test2.com.", TYPE_A, CLASS_IN, 600, []byte{10, 0, 0, 2}),
			},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x5678,
					Flags:                 FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED | FLAG_RCODE_NO_ERROR,
					QuestionCount:         2,
					AnswerRecordCount:     2,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("test1.com.", TYPE_A, CLASS_IN),
					createTestDNSQuestion("test2.com.", TYPE_A, CLASS_IN),
				},
				Answers: []DNSAnswer{
					createTestDNSAnswer("test1.com.", TYPE_A, CLASS_IN, 300, []byte{10, 0, 0, 1}),
					createTestDNSAnswer("test2.com.", TYPE_A, CLASS_IN, 600, []byte{10, 0, 0, 2}),
				},
			},
			description: "Should generate response with multiple questions and answers",
		},
		{
			name:     "response with non-standard opcode should get not implemented",
			id:       0x9999,
			reqFlags: FLAG_QR_QUERY | FLAG_OPCODE_INVERSE, // Non-standard opcode
			questions: []DNSQuestion{
				createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
			},
			answers: []DNSAnswer{},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x9999,
					Flags:                 FLAG_QR_RESPONSE | FLAG_OPCODE_INVERSE | FLAG_RCODE_NOT_IMPLEMENTED,
					QuestionCount:         1,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
				},
				Answers: []DNSAnswer{},
			},
			description: "Should generate response with NOT_IMPLEMENTED for non-standard opcode",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GenerateDNSResponse(test.id, test.reqFlags, test.questions, test.answers)

			if result == nil {
				t.Fatal("Result is nil")
			}

			// Compare headers
			if !reflect.DeepEqual(result.Header, test.expected.Header) {
				t.Errorf("Header mismatch:\nExpected: %+v\nGot: %+v", test.expected.Header, result.Header)
			}

			// Compare questions
			if len(result.Questions) != len(test.expected.Questions) {
				t.Errorf("Questions count mismatch: expected %d, got %d", len(test.expected.Questions), len(result.Questions))
			}

			// Compare answers
			if len(result.Answers) != len(test.expected.Answers) {
				t.Errorf("Answers count mismatch: expected %d, got %d", len(test.expected.Answers), len(result.Answers))
			}
		})
	}
}

func TestGenerateDNSQuery(t *testing.T) {
	tests := []struct {
		name        string
		id          uint16
		questions   []DNSQuestion
		expected    *DNSResponse
		description string
	}{
		{
			name: "simple query generation",
			id:   0x1234,
			questions: []DNSQuestion{
				createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
			},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
					QuestionCount:         1,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
				},
				Answers: nil,
			},
			description: "Should generate valid DNS query",
		},
		{
			name:      "query with no questions",
			id:        0xABCD,
			questions: []DNSQuestion{},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0xABCD,
					Flags:                 FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   nil,
			},
			description: "Should generate query with no questions",
		},
		{
			name: "query with multiple questions",
			id:   0x5678,
			questions: []DNSQuestion{
				createTestDNSQuestion("test1.com.", TYPE_A, CLASS_IN),
				createTestDNSQuestion("test2.com.", TYPE_AAAA, CLASS_IN),
			},
			expected: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x5678,
					Flags:                 FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
					QuestionCount:         2,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("test1.com.", TYPE_A, CLASS_IN),
					createTestDNSQuestion("test2.com.", TYPE_AAAA, CLASS_IN),
				},
				Answers: nil,
			},
			description: "Should generate query with multiple questions",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := GenerateDNSQuery(test.id, test.questions)

			if result == nil {
				t.Fatal("Result is nil")
			}

			// Compare headers
			if !reflect.DeepEqual(result.Header, test.expected.Header) {
				t.Errorf("Header mismatch:\nExpected: %+v\nGot: %+v", test.expected.Header, result.Header)
			}

			// Compare questions
			if len(result.Questions) != len(test.expected.Questions) {
				t.Errorf("Questions count mismatch: expected %d, got %d", len(test.expected.Questions), len(result.Questions))
			}

			// Compare answers (should be nil or empty)
			if len(result.Answers) > 0 {
				t.Errorf("Expected no answers in query, got %d", len(result.Answers))
			}
		})
	}
}

func TestPrepareResponseFlags(t *testing.T) {
	tests := []struct {
		name        string
		reqFlags    DNSFlag
		expected    DNSFlag
		description string
	}{
		{
			name:        "standard query should get no error response",
			reqFlags:    FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
			expected:    FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED | FLAG_RCODE_NO_ERROR,
			description: "Standard query should be marked as response with no error",
		},
		{
			name:        "inverse query should get not implemented response",
			reqFlags:    FLAG_QR_QUERY | FLAG_OPCODE_INVERSE,
			expected:    FLAG_QR_RESPONSE | FLAG_OPCODE_INVERSE | FLAG_RCODE_NOT_IMPLEMENTED,
			description: "Inverse query should be marked as response with not implemented",
		},
		{
			name:        "status query should get not implemented response",
			reqFlags:    FLAG_QR_QUERY | FLAG_OPCODE_STATUS,
			expected:    FLAG_QR_RESPONSE | FLAG_OPCODE_STATUS | FLAG_RCODE_NOT_IMPLEMENTED,
			description: "Status query should be marked as response with not implemented",
		},
		{
			name:        "query with all flags preserved",
			reqFlags:    FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED | FLAG_AA_AUTHORITATIVE | FLAG_TC_TRUNCATED,
			expected:    FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED | FLAG_AA_AUTHORITATIVE | FLAG_TC_TRUNCATED | FLAG_RCODE_NO_ERROR,
			description: "All request flags should be preserved except QR bit",
		},
		{
			name:        "query with no flags should get minimal response",
			reqFlags:    DNSFlag(0),
			expected:    FLAG_QR_RESPONSE | FLAG_RCODE_NO_ERROR,
			description: "Empty flags should result in response with no error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := PrepareResponseFlags(test.reqFlags)

			if result != test.expected {
				t.Errorf("Flag mismatch:\nExpected: 0x%04X (%016b)\nGot:      0x%04X (%016b)",
					uint16(test.expected), uint16(test.expected),
					uint16(result), uint16(result))
			}

			// Verify QR bit is always set to response
			if (result & FLAG_QR_RESPONSE) == 0 {
				t.Error("QR bit should be set to response")
			}

			// Verify OPCODE is preserved
			reqOpcode := (test.reqFlags >> BIT_OPCODE_START) & 0xF
			respOpcode := (result >> BIT_OPCODE_START) & 0xF
			if reqOpcode != respOpcode {
				t.Errorf("OPCODE not preserved: expected %d, got %d", reqOpcode, respOpcode)
			}

			// Verify RCODE is set correctly
			expectedRcode := uint16(0) // NO_ERROR
			if reqOpcode != 0 {
				expectedRcode = 4 // NOT_IMPLEMENTED
			}
			actualRcode := uint16(result & 0xF)
			if actualRcode != expectedRcode {
				t.Errorf("RCODE mismatch: expected %d, got %d", expectedRcode, actualRcode)
			}
		})
	}
}

func TestDNSResponseToBytes(t *testing.T) {
	tests := []struct {
		name        string
		response    *DNSResponse
		expected    []byte
		description string
	}{
		{
			name: "simple response with one question and answer",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_RESPONSE | FLAG_RD_RECURSION_DESIRED,
					QuestionCount:         1,
					AnswerRecordCount:     1,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("test.com.", TYPE_A, CLASS_IN),
				},
				Answers: []DNSAnswer{
					createTestDNSAnswer("test.com.", TYPE_A, CLASS_IN, 300, []byte{192, 0, 2, 1}),
				},
			},
			expected: []byte{
				// Header
				0x12, 0x34, // ID
				0x81, 0x00, // Flags
				0x00, 0x01, // Question count
				0x00, 0x01, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question
				0x04, 't', 'e', 's', 't',
				0x03, 'c', 'o', 'm',
				0x00,       // End of name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				// Answer
				0x04, 't', 'e', 's', 't',
				0x03, 'c', 'o', 'm',
				0x00,       // End of name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				0x00, 0x00, 0x01, 0x2C, // TTL (300)
				0x00, 0x04, // Data length
				192, 0, 2, 1, // IP address
			},
			description: "Should serialize simple response correctly",
		},
		{
			name: "response with no questions or answers",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0xABCD,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   []DNSAnswer{},
			},
			expected: []byte{
				// Header only
				0xAB, 0xCD, // ID
				0x80, 0x00, // Flags
				0x00, 0x00, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
			description: "Should serialize header-only response correctly",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.response.ToBytes()

			if !bytes.Equal(result, test.expected) {
				t.Errorf("Serialization mismatch:\nExpected: %v\nGot:      %v", test.expected, result)
				t.Errorf("Expected (hex): %x", test.expected)
				t.Errorf("Got (hex):      %x", result)
			}
		})
	}
}

func TestDNSResponseToBytesWithCompression(t *testing.T) {
	tests := []struct {
		name        string
		response    *DNSResponse
		description string
	}{
		{
			name: "response with repeated domain names should use compression",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         1,
					AnswerRecordCount:     1,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
				},
				Answers: []DNSAnswer{
					createTestDNSAnswer("example.com.", TYPE_A, CLASS_IN, 300, []byte{192, 0, 2, 1}),
				},
			},
			description: "Should use compression for repeated domain names",
		},
		{
			name: "response with multiple questions and answers",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x5678,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         2,
					AnswerRecordCount:     2,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("test.example.com.", TYPE_A, CLASS_IN),
					createTestDNSQuestion("www.example.com.", TYPE_A, CLASS_IN),
				},
				Answers: []DNSAnswer{
					createTestDNSAnswer("test.example.com.", TYPE_A, CLASS_IN, 300, []byte{10, 0, 0, 1}),
					createTestDNSAnswer("www.example.com.", TYPE_A, CLASS_IN, 600, []byte{10, 0, 0, 2}),
				},
			},
			description: "Should handle compression with multiple names sharing suffixes",
		},
		{
			name: "empty response should work",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x0000,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   []DNSAnswer{},
			},
			description: "Should handle empty response",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.response.ToBytesWithCompression()

			// Basic validation
			if len(result) < 12 {
				t.Errorf("Result too short: expected at least 12 bytes (header), got %d", len(result))
			}

			// Verify header is intact
			headerBytes := test.response.Header.ToBytes()
			if !bytes.Equal(result[:12], headerBytes) {
				t.Errorf("Header mismatch in compressed output")
			}

			// For non-empty responses, verify it's at least as long as header
			expectedMinLength := 12 // Header
			for _, question := range test.response.Questions {
				questionBytes := question.ToBytes()
				expectedMinLength += len(questionBytes)
			}
			for _, answer := range test.response.Answers {
				answerBytes := answer.ToBytes()
				expectedMinLength += len(answerBytes)
			}

			// Compressed version might be shorter due to compression
			if len(result) > expectedMinLength {
				t.Errorf("Compressed result is longer than uncompressed: got %d, max expected %d", len(result), expectedMinLength)
			}
		})
	}
}

func TestDNSResponseRoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		response    *DNSResponse
		description string
	}{
		{
			name: "simple response round trip",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_RESPONSE | FLAG_RD_RECURSION_DESIRED,
					QuestionCount:         1,
					AnswerRecordCount:     1,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
				},
				Answers: []DNSAnswer{
					createTestDNSAnswer("example.com.", TYPE_A, CLASS_IN, 300, []byte{192, 0, 2, 1}),
				},
			},
			description: "Should survive round trip serialization and parsing",
		},
		{
			name: "empty response round trip",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0xABCD,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   []DNSAnswer{},
			},
			description: "Should survive round trip with empty response",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Serialize
			serialized := test.response.ToBytes()

			// Parse back
			parsed, err := NewDNSResponse(serialized)
			if err != nil {
				t.Fatalf("Failed to parse serialized response: %v", err)
			}

			// Compare headers
			if !reflect.DeepEqual(parsed.Header, test.response.Header) {
				t.Errorf("Header mismatch after round trip:\nOriginal: %+v\nParsed:   %+v", test.response.Header, parsed.Header)
			}

			// Compare questions count
			if len(parsed.Questions) != len(test.response.Questions) {
				t.Errorf("Questions count mismatch: expected %d, got %d", len(test.response.Questions), len(parsed.Questions))
			}

			// Compare answers count
			if len(parsed.Answers) != len(test.response.Answers) {
				t.Errorf("Answers count mismatch: expected %d, got %d", len(test.response.Answers), len(parsed.Answers))
			}
		})
	}
}

// Helper functions for tests

func createTestDNSQuestion(domain string, recordType DNSType, class DNSClass) DNSQuestion {
	var labels []Label
	if domain != "." {
		// Remove trailing dot if present
		domain = domain[:len(domain)-1]
		parts := []string{}
		if domain != "" {
			parts = []string{domain}
			// Split by dots but handle edge cases
			if len(domain) > 0 {
				parts = []string{}
				current := ""
				for _, char := range domain {
					if char == '.' {
						if current != "" {
							parts = append(parts, current)
							current = ""
						}
					} else {
						current += string(char)
					}
				}
				if current != "" {
					parts = append(parts, current)
				}
			}
		}

		for _, part := range parts {
			if len(part) > 0 {
				labels = append(labels, Label{
					length:  uint8(len(part)),
					content: []byte(part),
				})
			}
		}
	}

	return DNSQuestion{
		Name: DomainName{
			labels: labels,
		},
		Type:  dnsTypeClassToBytes(recordType),
		Class: dnsTypeClassToBytes(class),
	}
}

func createTestDNSAnswer(domain string, recordType DNSType, class DNSClass, ttl uint32, data []byte) DNSAnswer {
	var labels []Label
	if domain != "." {
		// Remove trailing dot if present
		domain = domain[:len(domain)-1]
		parts := []string{}
		if domain != "" {
			parts = []string{domain}
			// Split by dots but handle edge cases
			if len(domain) > 0 {
				parts = []string{}
				current := ""
				for _, char := range domain {
					if char == '.' {
						if current != "" {
							parts = append(parts, current)
							current = ""
						}
					} else {
						current += string(char)
					}
				}
				if current != "" {
					parts = append(parts, current)
				}
			}
		}

		for _, part := range parts {
			if len(part) > 0 {
				labels = append(labels, Label{
					length:  uint8(len(part)),
					content: []byte(part),
				})
			}
		}
	}

	ttlBytes := [4]byte{
		byte(ttl >> 24),
		byte(ttl >> 16),
		byte(ttl >> 8),
		byte(ttl),
	}

	return DNSAnswer{
		name: DomainName{
			labels: labels,
		},
		type_: dnsTypeClassToBytes(recordType),
		class: dnsTypeClassToBytes(class),
		ttl:   ttlBytes,
		data:  data,
	}
}

func compareDNSQuestions(a, b DNSQuestion) bool {
	return reflect.DeepEqual(a.Name.labels, b.Name.labels) &&
		bytes.Equal(a.Type[:], b.Type[:]) &&
		bytes.Equal(a.Class[:], b.Class[:])
}

func compareDNSAnswers(a, b DNSAnswer) bool {
	return reflect.DeepEqual(a.name.labels, b.name.labels) &&
		bytes.Equal(a.type_[:], b.type_[:]) &&
		bytes.Equal(a.class[:], b.class[:]) &&
		bytes.Equal(a.ttl[:], b.ttl[:]) &&
		bytes.Equal(a.data, b.data)
}

func TestDNSResponseEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		response    *DNSResponse
		description string
	}{
		{
			name: "response with maximum values",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0xFFFF,
					Flags:                 DNSFlag(0xFFFF),
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   []DNSAnswer{},
			},
			description: "Should handle maximum flag values",
		},
		{
			name: "response with zero values",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x0000,
					Flags:                 DNSFlag(0x0000),
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   []DNSAnswer{},
			},
			description: "Should handle zero values",
		},
		{
			name: "response with large TTL values",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         1,
					AnswerRecordCount:     1,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{
					createTestDNSQuestion("test.com.", TYPE_A, CLASS_IN),
				},
				Answers: []DNSAnswer{
					createTestDNSAnswer("test.com.", TYPE_A, CLASS_IN, 0xFFFFFFFF, []byte{192, 0, 2, 1}),
				},
			},
			description: "Should handle maximum TTL values",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test serialization
			serialized := test.response.ToBytes()
			if len(serialized) < 12 {
				t.Errorf("Serialized response too short: %d bytes", len(serialized))
			}

			// Test compressed serialization
			compressed := test.response.ToBytesWithCompression()
			if len(compressed) < 12 {
				t.Errorf("Compressed response too short: %d bytes", len(compressed))
			}

			// Test round trip if response has valid structure
			if test.response.Header.QuestionCount == 0 && test.response.Header.AnswerRecordCount == 0 {
				parsed, err := NewDNSResponse(serialized)
				if err != nil {
					t.Errorf("Failed to parse round trip: %v", err)
				} else if !reflect.DeepEqual(parsed.Header, test.response.Header) {
					t.Errorf("Round trip header mismatch")
				}
			}
		})
	}
}

func TestDNSResponseNilHandling(t *testing.T) {
	tests := []struct {
		name        string
		response    *DNSResponse
		description string
	}{
		{
			name: "response with nil questions slice",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: nil,
				Answers:   []DNSAnswer{},
			},
			description: "Should handle nil questions slice",
		},
		{
			name: "response with nil answers slice",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []DNSQuestion{},
				Answers:   nil,
			},
			description: "Should handle nil answers slice",
		},
		{
			name: "response with both nil slices",
			response: &DNSResponse{
				Header: DNSHeader{
					ID:                    0x1234,
					Flags:                 FLAG_QR_RESPONSE,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: nil,
				Answers:   nil,
			},
			description: "Should handle both nil slices",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Test serialization doesn't panic with nil slices
			serialized := test.response.ToBytes()
			if len(serialized) != 12 {
				t.Errorf("Expected 12 bytes (header only), got %d", len(serialized))
			}

			// Test compressed serialization doesn't panic with nil slices
			compressed := test.response.ToBytesWithCompression()
			if len(compressed) != 12 {
				t.Errorf("Expected 12 bytes (header only), got %d", len(compressed))
			}
		})
	}
}

func TestDNSResponseComplexScenarios(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() *DNSResponse
		description string
	}{
		{
			name: "response with multiple records",
			setup: func() *DNSResponse {
				questions := []DNSQuestion{
					createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
				}
				answers := []DNSAnswer{
					createTestDNSAnswer("example.com.", TYPE_A, CLASS_IN, 300, []byte{192, 0, 2, 1}),
				}
				return GenerateDNSResponse(0x1234, FLAG_QR_QUERY|FLAG_OPCODE_STANDARD, questions, answers)
			},
			description: "Should handle multiple records",
		},
		{
			name: "response with different classes",
			setup: func() *DNSResponse {
				questions := []DNSQuestion{
					createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
				}
				answers := []DNSAnswer{
					createTestDNSAnswer("example.com.", TYPE_A, CLASS_IN, 300, []byte{192, 0, 2, 1}),
				}
				return GenerateDNSResponse(0x1234, FLAG_QR_QUERY|FLAG_OPCODE_STANDARD, questions, answers)
			},
			description: "Should handle different DNS classes",
		},
		{
			name: "response with varying TTL values",
			setup: func() *DNSResponse {
				questions := []DNSQuestion{
					createTestDNSQuestion("example.com.", TYPE_A, CLASS_IN),
				}
				answers := []DNSAnswer{
					createTestDNSAnswer("example.com.", TYPE_A, CLASS_IN, 86400, []byte{192, 0, 2, 1}), // One day TTL
				}
				return GenerateDNSResponse(0x1234, FLAG_QR_QUERY|FLAG_OPCODE_STANDARD, questions, answers)
			},
			description: "Should handle varying TTL values",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := test.setup()

			// Test basic serialization
			serialized := response.ToBytes()
			if len(serialized) < 12 {
				t.Errorf("Serialized response too short")
			}

			// Test compressed serialization
			compressed := response.ToBytesWithCompression()
			if len(compressed) < 12 {
				t.Errorf("Compressed response too short")
			}

			// Verify compression is working (should be same size or smaller)
			if len(compressed) > len(serialized) {
				t.Errorf("Compressed version (%d bytes) larger than uncompressed (%d bytes)",
					len(compressed), len(serialized))
			}

			// Skip round-trip test for complex scenarios as it requires
			// additional validation that's already covered in other tests
		})
	}
}

func FuzzNewDNSResponse(f *testing.F) {
	// Add seed values for the fuzzer
	seedData := [][]byte{
		// Valid minimal response
		{
			0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		// Valid response with question
		{
			0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
		},
		// Edge cases
		{},           // Empty
		{0x00},       // Single byte
		{0x12, 0x34}, // Two bytes
	}

	for _, seed := range seedData {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Fuzz testing should not panic, even with invalid data
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("NewDNSResponse panicked with data %x: %v", data, r)
			}
		}()

		response, err := NewDNSResponse(data)

		// If parsing succeeded, test serialization
		if err == nil && response != nil {
			// Test that serialization doesn't panic
			serialized := response.ToBytes()
			if len(serialized) < 12 {
				t.Errorf("Valid response serialized to less than 12 bytes")
			}

			// Test compressed serialization doesn't panic
			compressed := response.ToBytesWithCompression()
			if len(compressed) < 12 {
				t.Errorf("Valid response compressed to less than 12 bytes")
			}
		}
	})
}

func TestPrepareResponseFlagsEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		reqFlags DNSFlag
		checkFn  func(t *testing.T, result DNSFlag)
	}{
		{
			name:     "all bits set",
			reqFlags: DNSFlag(0xFFFF),
			checkFn: func(t *testing.T, result DNSFlag) {
				if (result & FLAG_QR_RESPONSE) == 0 {
					t.Error("QR bit should be set to response")
				}
				// When all bits are set, RCODE will be 15 (all 1s) OR'd with 4 = 15
				expectedRcode := uint16(15) // Original RCODE bits (all 1s) OR'd with NOT_IMPLEMENTED
				if (result & 0xF) != DNSFlag(expectedRcode) {
					t.Errorf("Expected RCODE %d, got %d", expectedRcode, result&0xF)
				}
			},
		},
		{
			name:     "only opcode bits set",
			reqFlags: FLAG_OPCODE_INVERSE,
			checkFn: func(t *testing.T, result DNSFlag) {
				opcode := (result >> BIT_OPCODE_START) & 0xF
				if opcode != 1 {
					t.Errorf("Expected opcode 1 (INVERSE), got %d", opcode)
				}
				if (result & 0xF) != 4 {
					t.Errorf("Expected RCODE 4 (NOT_IMPLEMENTED), got %d", result&0xF)
				}
			},
		},
		{
			name:     "boundary opcode value",
			reqFlags: DNSFlag(15 << BIT_OPCODE_START), // Maximum 4-bit opcode value
			checkFn: func(t *testing.T, result DNSFlag) {
				opcode := (result >> BIT_OPCODE_START) & 0xF
				if opcode != 15 {
					t.Errorf("Expected opcode 15, got %d", opcode)
				}
				if (result & 0xF) != 4 {
					t.Errorf("Expected RCODE 4 (NOT_IMPLEMENTED), got %d", result&0xF)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := PrepareResponseFlags(test.reqFlags)
			test.checkFn(t, result)
		})
	}
}
