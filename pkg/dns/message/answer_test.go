package message

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/vadim-su/dnska/pkg/dns/types"
	"github.com/vadim-su/dnska/pkg/dns/utils"
)

// Helper function for checking if string contains substring
func containsString(text, substr string) bool {
	return strings.Contains(text, substr)
}

// Helper function for comparing domain names
func compareDomainNames(a, b utils.DomainName) bool {
	// Handle case where one is nil and other is empty slice
	if len(a.Labels) == 0 && len(b.Labels) == 0 {
		return true
	}
	return reflect.DeepEqual(a.Labels, b.Labels)
}

func TestNewDNSAnswer(t *testing.T) {
	tests := []struct {
		name        string
		nameBytes   []byte
		class       types.DNSClass
		type_       types.DNSType
		ttl         uint32
		data        []byte
		expected    *DNSAnswer
		expectedErr bool
		errContains string
		description string
	}{
		{
			name: "valid A record answer",
			nameBytes: []byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00, // End of domain name
			},
			class: types.CLASS_IN,
			type_: types.TYPE_A,
			ttl:   300,
			data:  []byte{192, 0, 2, 1}, // IP address 192.0.2.1
			expected: &DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 7, Content: []byte("example")},
						{Length: 3, Content: []byte("com")},
					},
				},
				class: [2]byte{0x00, 0x01},             // CLASS_IN
				type_: [2]byte{0x00, 0x01},             // TYPE_A
				ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C}, // 300 seconds
				data:  []byte{192, 0, 2, 1},
			},
			expectedErr: false,
			description: "Should create valid A record answer",
		},
		{
			name: "valid AAAA record answer",
			nameBytes: []byte{
				0x04, 't', 'e', 's', 't',
				0x03, 'o', 'r', 'g',
				0x00, // End of domain name
			},
			class: types.CLASS_IN,
			type_: types.TYPE_AAAA,
			ttl:   3600,
			data:  []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // IPv6 address
			expected: &DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 4, Content: []byte("test")},
						{Length: 3, Content: []byte("org")},
					},
				},
				class: [2]byte{0x00, 0x01},                                                                                    // CLASS_IN
				type_: [2]byte{0x00, 0x1C},                                                                                    // TYPE_AAAA
				ttl:   [4]byte{0x00, 0x00, 0x0E, 0x10},                                                                        // 3600 seconds
				data:  []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // IPv6 address
			},
			expectedErr: false,
			description: "Should create valid AAAA record answer",
		},
		{
			name: "valid MX record answer",
			nameBytes: []byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'n', 'e', 't',
				0x00, // End of domain name
			},
			class: types.CLASS_IN,
			type_: types.TYPE_MX,
			ttl:   86400,
			data:  []byte{0x00, 0x0A, 0x04, 'm', 'a', 'i', 'l', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'n', 'e', 't', 0x00}, // Priority 10, mail.example.net
			expected: &DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 7, Content: []byte("example")},
						{Length: 3, Content: []byte("net")},
					},
				},
				class: [2]byte{0x00, 0x01},             // CLASS_IN
				type_: [2]byte{0x00, 0x0F},             // TYPE_MX
				ttl:   [4]byte{0x00, 0x01, 0x51, 0x80}, // 86400 seconds
				data:  []byte{0x00, 0x0A, 0x04, 'm', 'a', 'i', 'l', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'n', 'e', 't', 0x00},
			},
			expectedErr: false,
			description: "Should create valid MX record answer",
		},
		{
			name: "root domain answer",
			nameBytes: []byte{
				0x00, // Root domain
			},
			class: types.CLASS_IN,
			type_: types.TYPE_NS,
			ttl:   172800,
			data:  []byte{0x01, 'a', 0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's', 0x03, 'n', 'e', 't', 0x00}, // a.root-servers.net
			expected: &DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{},
				},
				class: [2]byte{0x00, 0x01},             // CLASS_IN
				type_: [2]byte{0x00, 0x02},             // TYPE_NS
				ttl:   [4]byte{0x00, 0x02, 0xA3, 0x00}, // 172800 seconds
				data:  []byte{0x01, 'a', 0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's', 0x03, 'n', 'e', 't', 0x00},
			},
			expectedErr: false,
			description: "Should create valid root domain NS answer",
		},
		{
			name: "zero TTL answer",
			nameBytes: []byte{
				0x04, 't', 'e', 's', 't',
				0x00, // End of domain name
			},
			class: types.CLASS_IN,
			type_: types.TYPE_TXT,
			ttl:   0,
			data:  []byte{0x0B, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'}, // "hello world"
			expected: &DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 4, Content: []byte("test")},
					},
				},
				class: [2]byte{0x00, 0x01},             // CLASS_IN
				type_: [2]byte{0x00, 0x10},             // TYPE_TXT
				ttl:   [4]byte{0x00, 0x00, 0x00, 0x00}, // 0 seconds
				data:  []byte{0x0B, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'},
			},
			expectedErr: false,
			description: "Should create valid TXT answer with zero TTL",
		},
		{
			name: "maximum TTL answer",
			nameBytes: []byte{
				0x03, 'm', 'a', 'x',
				0x00, // End of domain name
			},
			class: types.CLASS_IN,
			type_: types.TYPE_A,
			ttl:   4294967295, // Maximum uint32
			data:  []byte{10, 0, 0, 1},
			expected: &DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 3, Content: []byte("max")},
					},
				},
				class: [2]byte{0x00, 0x01},             // CLASS_IN
				type_: [2]byte{0x00, 0x01},             // TYPE_A
				ttl:   [4]byte{0xFF, 0xFF, 0xFF, 0xFF}, // Maximum TTL
				data:  []byte{10, 0, 0, 1},
			},
			expectedErr: false,
			description: "Should create valid answer with maximum TTL",
		},
		{
			name: "empty data answer",
			nameBytes: []byte{
				0x05, 'e', 'm', 'p', 't', 'y',
				0x00, // End of domain name
			},
			class: types.CLASS_IN,
			type_: types.TYPE_A,
			ttl:   300,
			data:  []byte{},
			expected: &DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 5, Content: []byte("empty")},
					},
				},
				class: [2]byte{0x00, 0x01},             // CLASS_IN
				type_: [2]byte{0x00, 0x01},             // TYPE_A
				ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C}, // 300 seconds
				data:  []byte{},
			},
			expectedErr: false,
			description: "Should create valid answer with empty data",
		},
		{
			name: "chaos class answer",
			nameBytes: []byte{
				0x04, 't', 'e', 's', 't',
				0x00, // End of domain name
			},
			class: types.CLASS_CH,
			type_: types.TYPE_TXT,
			ttl:   0,
			data:  []byte{0x07, 'c', 'h', 'a', 'o', 's', '!', '!'},
			expected: &DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 4, Content: []byte("test")},
					},
				},
				class: [2]byte{0x00, 0x03},             // CLASS_CH
				type_: [2]byte{0x00, 0x10},             // TYPE_TXT
				ttl:   [4]byte{0x00, 0x00, 0x00, 0x00}, // 0 seconds
				data:  []byte{0x07, 'c', 'h', 'a', 'o', 's', '!', '!'},
			},
			expectedErr: false,
			description: "Should create valid Chaos class answer",
		},
		{
			name:        "invalid domain name - empty data",
			nameBytes:   []byte{},
			class:       types.CLASS_IN,
			type_:       types.TYPE_A,
			ttl:         300,
			data:        []byte{192, 0, 2, 1},
			expected:    nil,
			expectedErr: true,
			errContains: "can't create DNS answer",
			description: "Should fail with empty domain name data",
		},
		{
			name: "invalid domain name - malformed",
			nameBytes: []byte{
				0x07, 'e', 'x', 'a', 'm', // Incomplete label
			},
			class:       types.CLASS_IN,
			type_:       types.TYPE_A,
			ttl:         300,
			data:        []byte{192, 0, 2, 1},
			expected:    nil,
			expectedErr: true,
			errContains: "can't create DNS answer",
			description: "Should fail with malformed domain name",
		},
		{
			name: "invalid domain name - missing null terminator",
			nameBytes: []byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				// Missing null terminator
			},
			class:       types.CLASS_IN,
			type_:       types.TYPE_A,
			ttl:         300,
			data:        []byte{192, 0, 2, 1},
			expected:    nil,
			expectedErr: true,
			errContains: "can't create DNS answer",
			description: "Should fail with missing null terminator",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := NewDNSAnswer(testCase.nameBytes, testCase.class, testCase.type_, testCase.ttl, testCase.data)

			if testCase.expectedErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if testCase.errContains != "" && !containsString(err.Error(), testCase.errContains) {
					t.Errorf("Expected error to contain '%s', got '%s'", testCase.errContains, err.Error())
				}
				if result != nil {
					t.Errorf("Expected nil result on error, got: %+v", result)
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

			// Compare domain names
			if !compareDomainNames(result.name, testCase.expected.name) {
				t.Errorf("Domain name mismatch:\ngot:  %s\nwant: %s", result.name.String(), testCase.expected.name.String())
			}

			// Compare class
			if !bytes.Equal(result.class[:], testCase.expected.class[:]) {
				t.Errorf("Class mismatch: got %v, want %v", result.class, testCase.expected.class)
			}

			// Compare type
			if !bytes.Equal(result.type_[:], testCase.expected.type_[:]) {
				t.Errorf("Type mismatch: got %v, want %v", result.type_, testCase.expected.type_)
			}

			// Compare TTL
			if !bytes.Equal(result.ttl[:], testCase.expected.ttl[:]) {
				t.Errorf("TTL mismatch: got %v, want %v", result.ttl, testCase.expected.ttl)
			}

			// Compare data
			if !bytes.Equal(result.data, testCase.expected.data) {
				t.Errorf("Data mismatch: got %v, want %v", result.data, testCase.expected.data)
			}
		})
	}
}

func TestDNSAnswerToBytes(t *testing.T) {
	tests := []struct {
		name           string
		answer         DNSAnswer
		expectedResult []byte
		description    string
	}{
		{
			name: "simple A record",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 7, Content: []byte("example")},
						{Length: 3, Content: []byte("com")},
					},
				},
				class: [2]byte{0x00, 0x01},             // IN
				type_: [2]byte{0x00, 0x01},             // A
				ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C}, // 300 seconds
				data:  []byte{192, 0, 2, 1},
			},
			expectedResult: []byte{
				// Domain name
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x01, // Type A
				0x00, 0x00, 0x01, 0x2C, // TTL (300 seconds)
				0x00, 0x04, // Data length (4 bytes)
				192, 0, 2, 1, // IP address data
			},
			description: "Should encode simple A record correctly",
		},
		{
			name: "AAAA record with IPv6",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 4, Content: []byte("test")},
					},
				},
				class: [2]byte{0x00, 0x01},             // IN
				type_: [2]byte{0x00, 0x1C},             // AAAA
				ttl:   [4]byte{0x00, 0x00, 0x0E, 0x10}, // 3600 seconds
				data:  []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			},
			expectedResult: []byte{
				// Domain name
				0x04, 't', 'e', 's', 't',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x1C, // Type AAAA
				0x00, 0x00, 0x0E, 0x10, // TTL (3600 seconds)
				0x00, 0x10, // Data length (16 bytes)
				// IPv6 address data
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			},
			description: "Should encode AAAA record with IPv6 correctly",
		},
		{
			name: "root domain NS record",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{},
				},
				class: [2]byte{0x00, 0x01},             // IN
				type_: [2]byte{0x00, 0x02},             // NS
				ttl:   [4]byte{0x00, 0x02, 0xA3, 0x00}, // 172800 seconds
				data:  []byte{0x01, 'a', 0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's', 0x03, 'n', 'e', 't', 0x00},
			},
			expectedResult: []byte{
				// Root domain
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x02, // Type NS
				0x00, 0x02, 0xA3, 0x00, // TTL (172800 seconds)
				0x00, 0x14, // Data length (20 bytes)
				// NS data: a.root-servers.net
				0x01, 'a', 0x0C, 'r', 'o', 'o', 't', '-', 's', 'e', 'r', 'v', 'e', 'r', 's', 0x03, 'n', 'e', 't', 0x00,
			},
			description: "Should encode root domain NS record correctly",
		},
		{
			name: "TXT record with text data",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 4, Content: []byte("test")},
						{Length: 7, Content: []byte("example")},
						{Length: 3, Content: []byte("org")},
					},
				},
				class: [2]byte{0x00, 0x01},             // IN
				type_: [2]byte{0x00, 0x10},             // TXT
				ttl:   [4]byte{0x00, 0x00, 0x00, 0x3C}, // 60 seconds
				data:  []byte{0x0B, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'},
			},
			expectedResult: []byte{
				// Domain name
				0x04, 't', 'e', 's', 't',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'o', 'r', 'g',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x10, // Type TXT
				0x00, 0x00, 0x00, 0x3C, // TTL (60 seconds)
				0x00, 0x0C, // Data length (12 bytes)
				// TXT data: "hello world"
				0x0B, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd',
			},
			description: "Should encode TXT record correctly",
		},
		{
			name: "record with zero TTL",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 5, Content: []byte("cache")},
					},
				},
				class: [2]byte{0x00, 0x01},             // IN
				type_: [2]byte{0x00, 0x01},             // A
				ttl:   [4]byte{0x00, 0x00, 0x00, 0x00}, // 0 seconds
				data:  []byte{127, 0, 0, 1},
			},
			expectedResult: []byte{
				// Domain name
				0x05, 'c', 'a', 'c', 'h', 'e',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x01, // Type A
				0x00, 0x00, 0x00, 0x00, // TTL (0 seconds)
				0x00, 0x04, // Data length (4 bytes)
				127, 0, 0, 1, // IP address data
			},
			description: "Should encode record with zero TTL correctly",
		},
		{
			name: "record with maximum TTL",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 3, Content: []byte("max")},
					},
				},
				class: [2]byte{0x00, 0x01},             // IN
				type_: [2]byte{0x00, 0x01},             // A
				ttl:   [4]byte{0xFF, 0xFF, 0xFF, 0xFF}, // Maximum TTL
				data:  []byte{192, 168, 1, 1},
			},
			expectedResult: []byte{
				// Domain name
				0x03, 'm', 'a', 'x',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x01, // Type A
				0xFF, 0xFF, 0xFF, 0xFF, // TTL (maximum)
				0x00, 0x04, // Data length (4 bytes)
				192, 168, 1, 1, // IP address data
			},
			description: "Should encode record with maximum TTL correctly",
		},
		{
			name: "record with empty data",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 5, Content: []byte("empty")},
					},
				},
				class: [2]byte{0x00, 0x01},             // IN
				type_: [2]byte{0x00, 0x01},             // A
				ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C}, // 300 seconds
				data:  []byte{},
			},
			expectedResult: []byte{
				// Domain name
				0x05, 'e', 'm', 'p', 't', 'y',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x01, // Type A
				0x00, 0x00, 0x01, 0x2C, // TTL (300 seconds)
				0x00, 0x00, // Data length (0 bytes)
				// No data
			},
			description: "Should encode record with empty data correctly",
		},
		{
			name: "large data record",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 4, Content: []byte("test")},
					},
				},
				class: [2]byte{0x00, 0x01},             // IN
				type_: [2]byte{0x00, 0x10},             // TXT
				ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C}, // 300 seconds
				data:  make([]byte, 512),               // Large data (512 bytes)
			},
			expectedResult: func() []byte {
				result := []byte{
					// Domain name
					0x04, 't', 'e', 's', 't',
					0x00,       // End of domain name
					0x00, 0x01, // Class IN
					0x00, 0x10, // Type TXT
					0x00, 0x00, 0x01, 0x2C, // TTL (300 seconds)
					0x02, 0x00, // Data length (512 bytes)
				}
				result = append(result, make([]byte, 512)...) // Add 512 zero bytes
				return result
			}(),
			description: "Should encode record with large data correctly",
		},
		{
			name: "Chaos class record",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 7, Content: []byte("version")},
						{Length: 4, Content: []byte("bind")},
					},
				},
				class: [2]byte{0x00, 0x03},             // CH (Chaos)
				type_: [2]byte{0x00, 0x10},             // TXT
				ttl:   [4]byte{0x00, 0x00, 0x00, 0x00}, // 0 seconds
				data:  []byte{0x0E, '9', '.', '1', '6', '.', '1', '-', 'U', 'b', 'u', 'n', 't', 'u'},
			},
			expectedResult: []byte{
				// Domain name
				0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
				0x04, 'b', 'i', 'n', 'd',
				0x00,       // End of domain name
				0x00, 0x03, // Class CH
				0x00, 0x10, // Type TXT
				0x00, 0x00, 0x00, 0x00, // TTL (0 seconds)
				0x00, 0x0E, // Data length (14 bytes)
				// TXT data: "9.16.1-Ubuntu"
				0x0E, '9', '.', '1', '6', '.', '1', '-', 'U', 'b', 'u', 'n', 't', 'u',
			},
			description: "Should encode Chaos class record correctly",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.answer.ToBytes()

			if !bytes.Equal(result, testCase.expectedResult) {
				t.Errorf("Result mismatch:\ngot:  %v\nwant: %v\ndescription: %s",
					result, testCase.expectedResult, testCase.description)
			}

			// Verify the result is not empty
			if len(result) == 0 {
				t.Error("ToBytes returned empty result")
			}

			// Verify minimum structure: name + class + type + ttl + data_length
			minimumExpectedLength := 1 + 2 + 2 + 4 + 2 // At least these fields
			if len(result) < minimumExpectedLength {
				t.Errorf("Result too short: got %d bytes, expected at least %d bytes",
					len(result), minimumExpectedLength)
			}
		})
	}
}

func TestDNSAnswerToBytesRoundTrip(t *testing.T) {
	// Create an answer, convert to bytes, then verify structure
	originalAnswer := DNSAnswer{
		name: utils.DomainName{
			Labels: []utils.Label{
				{Length: 7, Content: []byte("example")},
				{Length: 3, Content: []byte("com")},
			},
		},
		class: [2]byte{0x00, 0x01},             // IN
		type_: [2]byte{0x00, 0x01},             // A
		ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C}, // 300 seconds
		data:  []byte{192, 0, 2, 1},
	}

	answerBytes := originalAnswer.ToBytes()

	// Verify the bytes can be analyzed structurally
	if len(answerBytes) < 16 { // Minimum for this answer
		t.Fatalf("Answer bytes too short: %d", len(answerBytes))
	}

	// Check that data length field matches actual data length
	dataLengthOffset := len(answerBytes) - len(originalAnswer.data) - 2
	if dataLengthOffset >= 0 && dataLengthOffset < len(answerBytes)-1 {
		dataLength := uint16(answerBytes[dataLengthOffset])<<8 | uint16(answerBytes[dataLengthOffset+1])
		if dataLength != uint16(len(originalAnswer.data)) {
			t.Errorf("Data length field mismatch: encoded %d, actual %d", dataLength, len(originalAnswer.data))
		}
	}

	// Verify the actual data is at the end
	actualDataStart := len(answerBytes) - len(originalAnswer.data)
	if actualDataStart >= 0 {
		actualData := answerBytes[actualDataStart:]
		if !bytes.Equal(actualData, originalAnswer.data) {
			t.Errorf("Data mismatch in encoded bytes: got %v, want %v", actualData, originalAnswer.data)
		}
	}
}

func TestNewDNSAnswerRoundTrip(t *testing.T) {
	// Test creating an answer and verifying all fields are set correctly
	nameBytes := []byte{
		0x04, 't', 'e', 's', 't',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'o', 'r', 'g',
		0x00, // End of domain name
	}
	class := types.CLASS_IN
	recordType := types.TYPE_MX
	ttl := uint32(3600)
	data := []byte{0x00, 0x0A, 0x04, 'm', 'a', 'i', 'l', 0x04, 't', 'e', 's', 't', 0x00} // Priority 10, mail.test

	answer, err := NewDNSAnswer(nameBytes, class, recordType, ttl, data)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if answer == nil {
		t.Fatal("Answer is nil")
	}

	// Verify domain name was parsed correctly
	expectedDomain := "test.example.org."
	actualDomain := answer.name.String()
	if actualDomain != expectedDomain {
		t.Errorf("Domain name mismatch: got %s, want %s", actualDomain, expectedDomain)
	}

	// Verify class
	expectedClass := types.DnsTypeClassToBytes(class)
	if !bytes.Equal(answer.class[:], expectedClass[:]) {
		t.Errorf("Class mismatch: got %v, want %v", answer.class, expectedClass)
	}

	// Verify type
	expectedType := types.DnsTypeClassToBytes(recordType)
	if !bytes.Equal(answer.type_[:], expectedType[:]) {
		t.Errorf("Type mismatch: got %v, want %v", answer.type_, expectedType)
	}

	// Verify TTL
	expectedTTL := [4]byte{
		byte(ttl >> 24),
		byte(ttl >> 16),
		byte(ttl >> 8),
		byte(ttl),
	}
	if !bytes.Equal(answer.ttl[:], expectedTTL[:]) {
		t.Errorf("TTL mismatch: got %v, want %v", answer.ttl, expectedTTL)
	}

	// Verify data
	if !bytes.Equal(answer.data, data) {
		t.Errorf("Data mismatch: got %v, want %v", answer.data, data)
	}

	// Convert to bytes and verify structure
	answerBytes := answer.ToBytes()
	if len(answerBytes) == 0 {
		t.Error("ToBytes returned empty result")
	}
}

func TestDNSAnswerEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		answer      DNSAnswer
		description string
	}{
		{
			name: "answer with very large data",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 4, Content: []byte("huge")},
					},
				},
				class: [2]byte{0x00, 0x01},
				type_: [2]byte{0x00, 0x10},
				ttl:   [4]byte{0x00, 0x00, 0x01, 0x2C},
				data:  make([]byte, 65535), // Maximum data size
			},
			description: "Should handle maximum data size",
		},
		{
			name: "answer with all zero values",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{},
				},
				class: [2]byte{0x00, 0x00},
				type_: [2]byte{0x00, 0x00},
				ttl:   [4]byte{0x00, 0x00, 0x00, 0x00},
				data:  []byte{},
			},
			description: "Should handle all zero values",
		},
		{
			name: "answer with maximum values",
			answer: DNSAnswer{
				name: utils.DomainName{
					Labels: []utils.Label{
						{Length: 1, Content: []byte("a")},
					},
				},
				class: [2]byte{0xFF, 0xFF},
				type_: [2]byte{0xFF, 0xFF},
				ttl:   [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
				data:  []byte{0xFF},
			},
			description: "Should handle maximum field values",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.answer.ToBytes()

			// Should not panic and should return some result
			if result == nil {
				t.Errorf("ToBytes returned nil\ndescription: %s", testCase.description)
			}

			// Should include at least the basic structure
			minimumLength := 1 + 2 + 2 + 4 + 2 // name + class + type + ttl + data_length
			if len(result) < minimumLength {
				t.Errorf("Result too short: got %d bytes, expected at least %d\ndescription: %s",
					len(result), minimumLength, testCase.description)
			}
		})
	}
}
