package dns

import (
	"reflect"
	"testing"
)

func TestNewDNSHeader(t *testing.T) {
	tests := []struct {
		name                  string
		id                    uint16
		flags                 DNSFlag
		questionCount         uint16
		answerRecordCount     uint16
		authorityRecordCount  uint16
		additionalRecordCount uint16
		expected              *DNSHeader
	}{
		{
			name:                  "basic header creation",
			id:                    0x1234,
			flags:                 FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
			questionCount:         1,
			answerRecordCount:     0,
			authorityRecordCount:  0,
			additionalRecordCount: 0,
			expected: &DNSHeader{
				ID:                    0x1234,
				Flags:                 FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
				QuestionCount:         1,
				AnswerRecordCount:     0,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
		},
		{
			name:                  "response header with records",
			id:                    0x5678,
			flags:                 FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_AA_AUTHORITATIVE | FLAG_RD_RECURSION_DESIRED | FLAG_RA_RECURSION_AVAILABLE,
			questionCount:         1,
			answerRecordCount:     2,
			authorityRecordCount:  1,
			additionalRecordCount: 1,
			expected: &DNSHeader{
				ID:                    0x5678,
				Flags:                 FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_AA_AUTHORITATIVE | FLAG_RD_RECURSION_DESIRED | FLAG_RA_RECURSION_AVAILABLE,
				QuestionCount:         1,
				AnswerRecordCount:     2,
				AuthorityRecordCount:  1,
				AdditionalRecordCount: 1,
			},
		},
		{
			name:                  "zero values",
			id:                    0,
			flags:                 0,
			questionCount:         0,
			answerRecordCount:     0,
			authorityRecordCount:  0,
			additionalRecordCount: 0,
			expected: &DNSHeader{
				ID:                    0,
				Flags:                 0,
				QuestionCount:         0,
				AnswerRecordCount:     0,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
		},
		{
			name:                  "maximum values",
			id:                    0xFFFF,
			flags:                 0xFFFF,
			questionCount:         0xFFFF,
			answerRecordCount:     0xFFFF,
			authorityRecordCount:  0xFFFF,
			additionalRecordCount: 0xFFFF,
			expected: &DNSHeader{
				ID:                    0xFFFF,
				Flags:                 0xFFFF,
				QuestionCount:         0xFFFF,
				AnswerRecordCount:     0xFFFF,
				AuthorityRecordCount:  0xFFFF,
				AdditionalRecordCount: 0xFFFF,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := NewDNSHeader(
				test.id,
				test.flags,
				test.questionCount,
				test.answerRecordCount,
				test.authorityRecordCount,
				test.additionalRecordCount,
			)

			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("got %+v, want %+v", result, test.expected)
			}
		})
	}
}

func TestDNSHeaderToBytes(t *testing.T) {
	tests := []struct {
		name     string
		header   *DNSHeader
		expected []byte
	}{
		{
			name: "basic query header",
			header: &DNSHeader{
				ID:                    0x1234,
				Flags:                 FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
				QuestionCount:         1,
				AnswerRecordCount:     0,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
			expected: []byte{
				0x12, 0x34, // ID
				0x01, 0x00, // Flags (RD=1, others=0)
				0x00, 0x01, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
		},
		{
			name: "response header with all flags",
			header: &DNSHeader{
				ID: 0x5678,
				Flags: FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_AA_AUTHORITATIVE |
					FLAG_TC_TRUNCATED | FLAG_RD_RECURSION_DESIRED | FLAG_RA_RECURSION_AVAILABLE,
				QuestionCount:         1,
				AnswerRecordCount:     2,
				AuthorityRecordCount:  1,
				AdditionalRecordCount: 1,
			},
			expected: []byte{
				0x56, 0x78, // ID
				0x87, 0x80, // Flags (QR=1, AA=1, TC=1, RD=1, RA=1)
				0x00, 0x01, // Question count
				0x00, 0x02, // Answer count
				0x00, 0x01, // Authority count
				0x00, 0x01, // Additional count
			},
		},
		{
			name: "header with error code",
			header: &DNSHeader{
				ID:                    0xABCD,
				Flags:                 FLAG_QR_RESPONSE | FLAG_OPCODE_STANDARD | FLAG_RCODE_NAME_ERROR,
				QuestionCount:         1,
				AnswerRecordCount:     0,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
			expected: []byte{
				0xAB, 0xCD, // ID
				0x80, 0x03, // Flags (QR=1, RCODE=3)
				0x00, 0x01, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
		},
		{
			name: "zero header",
			header: &DNSHeader{
				ID:                    0,
				Flags:                 0,
				QuestionCount:         0,
				AnswerRecordCount:     0,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
			expected: []byte{
				0x00, 0x00, // ID
				0x00, 0x00, // Flags
				0x00, 0x00, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
		},
		{
			name: "maximum values header",
			header: &DNSHeader{
				ID:                    0xFFFF,
				Flags:                 0xFFFF,
				QuestionCount:         0xFFFF,
				AnswerRecordCount:     0xFFFF,
				AuthorityRecordCount:  0xFFFF,
				AdditionalRecordCount: 0xFFFF,
			},
			expected: []byte{
				0xFF, 0xFF, // ID
				0xFF, 0xFF, // Flags
				0xFF, 0xFF, // Question count
				0xFF, 0xFF, // Answer count
				0xFF, 0xFF, // Authority count
				0xFF, 0xFF, // Additional count
			},
		},
		{
			name: "inverse query header",
			header: &DNSHeader{
				ID:                    0x1111,
				Flags:                 FLAG_QR_QUERY | FLAG_OPCODE_INVERSE,
				QuestionCount:         0,
				AnswerRecordCount:     1,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
			expected: []byte{
				0x11, 0x11, // ID
				0x08, 0x00, // Flags (OPCODE=1)
				0x00, 0x00, // Question count
				0x00, 0x01, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
		},
		{
			name: "status request header",
			header: &DNSHeader{
				ID:                    0x2222,
				Flags:                 FLAG_QR_QUERY | FLAG_OPCODE_STATUS,
				QuestionCount:         0,
				AnswerRecordCount:     0,
				AuthorityRecordCount:  0,
				AdditionalRecordCount: 0,
			},
			expected: []byte{
				0x22, 0x22, // ID
				0x10, 0x00, // Flags (OPCODE=2)
				0x00, 0x00, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.header.ToBytes()

			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("got %v, want %v", result, test.expected)
			}

			// Verify the length is always 12 bytes
			if len(result) != 12 {
				t.Errorf("header length: got %d, want 12", len(result))
			}
		})
	}
}

func TestDNSHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		header *DNSHeader
	}{
		{
			name: "standard query",
			header: NewDNSHeader(
				0x1234,
				FLAG_QR_QUERY|FLAG_OPCODE_STANDARD|FLAG_RD_RECURSION_DESIRED,
				1, 0, 0, 0,
			),
		},
		{
			name: "authoritative response",
			header: NewDNSHeader(
				0x5678,
				FLAG_QR_RESPONSE|FLAG_OPCODE_STANDARD|FLAG_AA_AUTHORITATIVE|FLAG_RD_RECURSION_DESIRED|FLAG_RA_RECURSION_AVAILABLE,
				1, 3, 2, 1,
			),
		},
		{
			name: "error response",
			header: NewDNSHeader(
				0xABCD,
				FLAG_QR_RESPONSE|FLAG_OPCODE_STANDARD|FLAG_RCODE_SERVER_FAILURE,
				1, 0, 0, 0,
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Convert to bytes
			bytes := test.header.ToBytes()

			// Manually reconstruct header from bytes to verify round-trip
			// (Since there's no FromBytes method, we'll verify the byte layout)
			reconstructed := &DNSHeader{
				ID:                    uint16(bytes[0])<<8 | uint16(bytes[1]),
				Flags:                 DNSFlag(bytes[2])<<8 | DNSFlag(bytes[3]),
				QuestionCount:         uint16(bytes[4])<<8 | uint16(bytes[5]),
				AnswerRecordCount:     uint16(bytes[6])<<8 | uint16(bytes[7]),
				AuthorityRecordCount:  uint16(bytes[8])<<8 | uint16(bytes[9]),
				AdditionalRecordCount: uint16(bytes[10])<<8 | uint16(bytes[11]),
			}

			if !reflect.DeepEqual(reconstructed, test.header) {
				t.Errorf("round trip failed: got %+v, want %+v", reconstructed, test.header)
			}
		})
	}
}

func TestDNSFlagValues(t *testing.T) {
	tests := []struct {
		name     string
		flag     DNSFlag
		expected uint16
	}{
		{"QR Response", FLAG_QR_RESPONSE, 0x8000},
		{"QR Query", FLAG_QR_QUERY, 0x0000},
		{"OPCODE Standard", FLAG_OPCODE_STANDARD, 0x0000},
		{"OPCODE Inverse", FLAG_OPCODE_INVERSE, 0x0800},
		{"OPCODE Status", FLAG_OPCODE_STATUS, 0x1000},
		{"AA Authoritative", FLAG_AA_AUTHORITATIVE, 0x0400},
		{"TC Truncated", FLAG_TC_TRUNCATED, 0x0200},
		{"RD Recursion Desired", FLAG_RD_RECURSION_DESIRED, 0x0100},
		{"RA Recursion Available", FLAG_RA_RECURSION_AVAILABLE, 0x0080},
		{"RCODE No Error", FLAG_RCODE_NO_ERROR, 0x0000},
		{"RCODE Format Error", FLAG_RCODE_FORMAT_ERROR, 0x0001},
		{"RCODE Server Failure", FLAG_RCODE_SERVER_FAILURE, 0x0002},
		{"RCODE Name Error", FLAG_RCODE_NAME_ERROR, 0x0003},
		{"RCODE Not Implemented", FLAG_RCODE_NOT_IMPLEMENTED, 0x0004},
		{"RCODE Refused", FLAG_RCODE_REFUSED, 0x0005},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if uint16(test.flag) != test.expected {
				t.Errorf("flag value: got 0x%04X, want 0x%04X", uint16(test.flag), test.expected)
			}
		})
	}
}

func TestDNSFlagCombinations(t *testing.T) {
	tests := []struct {
		name          string
		flags         DNSFlag
		expectedBytes []byte
	}{
		{
			name:          "standard query with recursion",
			flags:         FLAG_QR_QUERY | FLAG_OPCODE_STANDARD | FLAG_RD_RECURSION_DESIRED,
			expectedBytes: []byte{0x01, 0x00}, // RD=1
		},
		{
			name:          "authoritative response with recursion available",
			flags:         FLAG_QR_RESPONSE | FLAG_AA_AUTHORITATIVE | FLAG_RD_RECURSION_DESIRED | FLAG_RA_RECURSION_AVAILABLE,
			expectedBytes: []byte{0x85, 0x80}, // QR=1, AA=1, RD=1, RA=1
		},
		{
			name:          "truncated response",
			flags:         FLAG_QR_RESPONSE | FLAG_TC_TRUNCATED,
			expectedBytes: []byte{0x82, 0x00}, // QR=1, TC=1
		},
		{
			name:          "inverse query",
			flags:         FLAG_QR_QUERY | FLAG_OPCODE_INVERSE,
			expectedBytes: []byte{0x08, 0x00}, // OPCODE=1
		},
		{
			name:          "server failure response",
			flags:         FLAG_QR_RESPONSE | FLAG_RCODE_SERVER_FAILURE,
			expectedBytes: []byte{0x80, 0x02}, // QR=1, RCODE=2
		},
		{
			name:          "refused response",
			flags:         FLAG_QR_RESPONSE | FLAG_RCODE_REFUSED,
			expectedBytes: []byte{0x80, 0x05}, // QR=1, RCODE=5
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := &DNSHeader{
				ID:    0x0000,
				Flags: test.flags,
			}

			bytes := header.ToBytes()
			flagBytes := bytes[2:4] // Extract flag bytes

			if !reflect.DeepEqual(flagBytes, test.expectedBytes) {
				t.Errorf("flag bytes: got [0x%02X, 0x%02X], want [0x%02X, 0x%02X]",
					flagBytes[0], flagBytes[1], test.expectedBytes[0], test.expectedBytes[1])
			}
		})
	}
}

func TestDNSHeaderByteOrder(t *testing.T) {
	// Test that multi-byte values are correctly encoded in big-endian format
	header := &DNSHeader{
		ID:                    0x1234,
		Flags:                 0x5678,
		QuestionCount:         0x9ABC,
		AnswerRecordCount:     0xDEF0,
		AuthorityRecordCount:  0x1357,
		AdditionalRecordCount: 0x2468,
	}

	bytes := header.ToBytes()

	expected := []byte{
		0x12, 0x34, // ID
		0x56, 0x78, // Flags
		0x9A, 0xBC, // QuestionCount
		0xDE, 0xF0, // AnswerRecordCount
		0x13, 0x57, // AuthorityRecordCount
		0x24, 0x68, // AdditionalRecordCount
	}

	if !reflect.DeepEqual(bytes, expected) {
		t.Errorf("byte order test failed:\ngot:  %v\nwant: %v", bytes, expected)
	}
}

func TestDNSHeaderFields(t *testing.T) {
	header := NewDNSHeader(0x1234, 0x5678, 10, 20, 30, 40)

	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"ID", header.ID, uint16(0x1234)},
		{"Flags", header.Flags, DNSFlag(0x5678)},
		{"QuestionCount", header.QuestionCount, uint16(10)},
		{"AnswerRecordCount", header.AnswerRecordCount, uint16(20)},
		{"AuthorityRecordCount", header.AuthorityRecordCount, uint16(30)},
		{"AdditionalRecordCount", header.AdditionalRecordCount, uint16(40)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.expected {
				t.Errorf("field %s: got %v, want %v", test.name, test.got, test.expected)
			}
		})
	}
}
