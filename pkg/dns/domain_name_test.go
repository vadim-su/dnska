package dns

import (
	"fmt"
	"reflect"
	"testing"
)

func TestNewDomainName(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    *DomainName
		expectedErr bool
	}{
		{
			name:  "root domain",
			input: []byte{0x00},
			expected: &DomainName{
				labels: nil,
			},
			expectedErr: false,
		},
		{
			name:  "simple top level domain",
			input: []byte{0x04, 't', 'e', 's', 't', 0x00},
			expected: &DomainName{
				labels: []Label{
					{
						length:  4,
						content: []byte("test"),
					},
				},
			},
			expectedErr: false,
		},
		{
			name:  "two level domain",
			input: []byte{0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00},
			expected: &DomainName{
				labels: []Label{
					{
						length:  4,
						content: []byte("test"),
					},
					{
						length:  3,
						content: []byte("com"),
					},
				},
			},
			expectedErr: false,
		},
		{
			name:  "three level domain",
			input: []byte{0x03, 'd', 'e', 'v', 0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00},
			expected: &DomainName{
				labels: []Label{
					{
						length:  3,
						content: []byte("dev"),
					},
					{
						length:  4,
						content: []byte("test"),
					},
					{
						length:  3,
						content: []byte("com"),
					},
				},
			},
			expectedErr: false,
		},
		{
			name:        "empty data",
			input:       []byte{},
			expected:    nil,
			expectedErr: true,
		},
		{
			name:        "insufficient bytes for label",
			input:       []byte{0x04, 't', 'e'},
			expected:    nil,
			expectedErr: true,
		},
		{
			name:        "missing null terminator",
			input:       []byte{0x04, 't', 'e', 's', 't'},
			expected:    nil,
			expectedErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, size, err := NewDomainName(test.input)

			if test.expectedErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("got %+v, want %+v", result, test.expected)
			}

			expectedSize := uint16(len(test.input))
			if size != expectedSize {
				t.Errorf("got size %d, want %d", size, expectedSize)
			}
		})
	}
}

func TestDomainNameToBytes(t *testing.T) {
	tests := []struct {
		name     string
		domain   *DomainName
		expected []byte
	}{
		{
			name: "root domain",
			domain: &DomainName{
				labels: nil,
			},
			expected: []byte{0x00},
		},
		{
			name: "simple domain",
			domain: &DomainName{
				labels: []Label{
					{
						length:  4,
						content: []byte("test"),
					},
				},
			},
			expected: []byte{0x04, 't', 'e', 's', 't', 0x00},
		},
		{
			name: "two level domain",
			domain: &DomainName{
				labels: []Label{
					{
						length:  4,
						content: []byte("test"),
					},
					{
						length:  3,
						content: []byte("com"),
					},
				},
			},
			expected: []byte{0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.domain.ToBytes()
			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("got %v, want %v", result, test.expected)
			}
		})
	}
}

func TestDomainNameString(t *testing.T) {
	tests := []struct {
		name     string
		domain   *DomainName
		expected string
	}{
		{
			name: "root domain",
			domain: &DomainName{
				labels: nil,
			},
			expected: ".",
		},
		{
			name: "simple domain",
			domain: &DomainName{
				labels: []Label{
					{
						length:  4,
						content: []byte("test"),
					},
				},
			},
			expected: "test.",
		},
		{
			name: "two level domain",
			domain: &DomainName{
				labels: []Label{
					{
						length:  4,
						content: []byte("test"),
					},
					{
						length:  3,
						content: []byte("com"),
					},
				},
			},
			expected: "test.com.",
		},
		{
			name: "three level domain",
			domain: &DomainName{
				labels: []Label{
					{
						length:  3,
						content: []byte("www"),
					},
					{
						length:  7,
						content: []byte("example"),
					},
					{
						length:  3,
						content: []byte("org"),
					},
				},
			},
			expected: "www.example.org.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.domain.String()
			if result != test.expected {
				t.Errorf("got %q, want %q", result, test.expected)
			}
		})
	}
}

func TestLabelToBytes(t *testing.T) {
	tests := []struct {
		name     string
		label    Label
		expected []byte
	}{
		{
			name: "simple label",
			label: Label{
				length:  4,
				content: []byte("test"),
			},
			expected: []byte{0x04, 't', 'e', 's', 't'},
		},
		{
			name: "single character label",
			label: Label{
				length:  1,
				content: []byte("a"),
			},
			expected: []byte{0x01, 'a'},
		},
		{
			name: "empty content",
			label: Label{
				length:  0,
				content: []byte{},
			},
			expected: []byte{0x00},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.label.ToBytes()
			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("got %v, want %v", result, test.expected)
			}
		})
	}
}

func TestDomainNameGetSuffixFrom(t *testing.T) {
	domain := &DomainName{
		labels: []Label{
			{length: 3, content: []byte("www")},
			{length: 7, content: []byte("example")},
			{length: 3, content: []byte("com")},
		},
	}

	tests := []struct {
		name        string
		startIndex  int
		expectedLen int
	}{
		{
			name:        "suffix from index 0",
			startIndex:  0,
			expectedLen: 3,
		},
		{
			name:        "suffix from index 1",
			startIndex:  1,
			expectedLen: 2,
		},
		{
			name:        "suffix from index 2",
			startIndex:  2,
			expectedLen: 1,
		},
		{
			name:        "suffix from beyond end",
			startIndex:  5,
			expectedLen: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := domain.getSuffixFrom(test.startIndex)
			if len(result.labels) != test.expectedLen {
				t.Errorf("got %d labels, want %d", len(result.labels), test.expectedLen)
			}
		})
	}
}

func TestDomainNameGetBytesUpToLabel(t *testing.T) {
	domain := &DomainName{
		labels: []Label{
			{length: 3, content: []byte("www")},     // 4 bytes (1 + 3)
			{length: 7, content: []byte("example")}, // 8 bytes (1 + 7)
			{length: 3, content: []byte("com")},     // 4 bytes (1 + 3)
		},
	}

	tests := []struct {
		name       string
		labelIndex int
		expected   uint16
	}{
		{
			name:       "bytes up to label 0",
			labelIndex: 0,
			expected:   0,
		},
		{
			name:       "bytes up to label 1",
			labelIndex: 1,
			expected:   4, // www + length byte
		},
		{
			name:       "bytes up to label 2",
			labelIndex: 2,
			expected:   12, // www + example + 2 length bytes
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := domain.getBytesUpToLabel(test.labelIndex)
			if result != test.expected {
				t.Errorf("got %d, want %d", result, test.expected)
			}
		})
	}
}

func TestRoundTripConversion(t *testing.T) {
	tests := [][]byte{
		{0x00},                           // root
		{0x04, 't', 'e', 's', 't', 0x00}, // test.
		{0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00},                      // test.com.
		{0x03, 'w', 'w', 'w', 0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00}, // www.test.com.
	}

	for idx, original := range tests {
		t.Run(fmt.Sprintf("round_trip_%d", idx), func(t *testing.T) {
			// Parse domain name
			domain, _, err := NewDomainName(original)
			if err != nil {
				t.Fatalf("failed to parse domain: %v", err)
			}

			// Convert back to bytes
			result := domain.ToBytes()

			// Should match original
			if !reflect.DeepEqual(result, original) {
				t.Errorf("round trip failed: got %v, want %v", result, original)
			}
		})
	}
}

func TestDomainNameToBytesWithCompression(t *testing.T) {
	tests := []struct {
		name            string
		domain          *DomainName
		compressionMap  *CompressionMap
		currentOffset   uint16
		expectedResult  []byte
		expectedMapSize int
	}{
		{
			name: "simple domain without existing compression",
			domain: &DomainName{
				labels: []Label{
					{length: 4, content: []byte("test")},
					{length: 3, content: []byte("com")},
				},
			},
			compressionMap:  NewCompressionMap(),
			currentOffset:   12,
			expectedResult:  []byte{0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00},
			expectedMapSize: 2, // "test.com." and "com."
		},
		{
			name: "domain with existing compression for full domain",
			domain: &DomainName{
				labels: []Label{
					{length: 4, content: []byte("test")},
					{length: 3, content: []byte("com")},
				},
			},
			compressionMap: func() *CompressionMap {
				cm := NewCompressionMap()
				cm.nameToOffset["test.com."] = 20
				return cm
			}(),
			currentOffset:   12,
			expectedResult:  []byte{0xC0, 0x14}, // pointer to offset 20
			expectedMapSize: 1,                  // existing entry only
		},
		{
			name: "domain with suffix compression",
			domain: &DomainName{
				labels: []Label{
					{length: 3, content: []byte("www")},
					{length: 4, content: []byte("test")},
					{length: 3, content: []byte("com")},
				},
			},
			compressionMap: func() *CompressionMap {
				cm := NewCompressionMap()
				cm.nameToOffset["test.com."] = 20
				return cm
			}(),
			currentOffset:   12,
			expectedResult:  []byte{0x03, 'w', 'w', 'w', 0xC0, 0x14}, // "www" + pointer to "test.com."
			expectedMapSize: 1,                                       // no new entries added (existing compression used)
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalMapSize := len(test.compressionMap.nameToOffset)
			result := test.domain.ToBytesWithCompression(test.compressionMap, test.currentOffset)

			if !reflect.DeepEqual(result, test.expectedResult) {
				t.Errorf("got %v, want %v", result, test.expectedResult)
			}

			newMapSize := len(test.compressionMap.nameToOffset)
			if test.name == "simple domain without existing compression" && newMapSize != test.expectedMapSize {
				t.Errorf("compression map size: got %d, want %d", newMapSize, test.expectedMapSize)
			} else if test.name != "simple domain without existing compression" && newMapSize != originalMapSize {
				t.Errorf("compression map size changed unexpectedly: got %d, want %d", newMapSize, originalMapSize)
			}
		})
	}
}

func TestCompressionEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		originalMsg    []byte
		expectedLabels int
		expectedErr    bool
	}{
		{
			name: "mixed labels and compression",
			data: []byte{0x03, 'w', 'w', 'w', 0xC0, 0x10}, // "www" + pointer to offset 16
			originalMsg: func() []byte {
				// Create a message where offset 16 contains "example.com."
				msg := make([]byte, 32)
				copy(msg[16:], []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00})
				return msg
			}(),
			expectedLabels: 3, // www + example + com
			expectedErr:    false,
		},
		{
			name:           "compression pointer at start",
			data:           []byte{0xC0, 0x0C}, // pointer to offset 12
			originalMsg:    []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's', 't', 0x00},
			expectedLabels: 1, // test
			expectedErr:    false,
		},
		{
			name:           "nested compression (should handle gracefully)",
			data:           []byte{0xC0, 0x02},                                                         // pointer to offset 2
			originalMsg:    []byte{0x00, 0x00, 0xC0, 0x06, 0x00, 0x00, 0x04, 't', 'e', 's', 't', 0x00}, // offset 2 points to offset 6
			expectedLabels: 1,
			expectedErr:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, _, err := NewDomainNameWithDecompression(test.data, test.originalMsg)

			if test.expectedErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(result.labels) != test.expectedLabels {
				t.Errorf("got %d labels, want %d", len(result.labels), test.expectedLabels)
			}
		})
	}
}

func TestDomainNameStringRepresentation(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{
			input:    []byte{0x00},
			expected: ".",
		},
		{
			input:    []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00},
			expected: "example.",
		},
		{
			input:    []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
			expected: "example.com.",
		},
		{
			input:    []byte{0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
			expected: "www.example.com.",
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("string_%s", test.expected), func(t *testing.T) {
			domain, _, err := NewDomainName(test.input)
			if err != nil {
				t.Fatalf("failed to parse domain: %v", err)
			}

			result := domain.String()
			if result != test.expected {
				t.Errorf("got %q, want %q", result, test.expected)
			}
		})
	}
}

func TestDomainNameSize(t *testing.T) {
	tests := []struct {
		name         string
		input        []byte
		expectedSize uint16
	}{
		{
			name:         "root domain",
			input:        []byte{0x00},
			expectedSize: 1,
		},
		{
			name:         "single label",
			input:        []byte{0x04, 't', 'e', 's', 't', 0x00},
			expectedSize: 6,
		},
		{
			name:         "two labels",
			input:        []byte{0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00},
			expectedSize: 10,
		},
		{
			name:         "long domain",
			input:        []byte{0x03, 'w', 'w', 'w', 0x04, 't', 'e', 's', 't', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
			expectedSize: 22,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, size, err := NewDomainName(test.input)
			if err != nil {
				t.Fatalf("failed to parse domain: %v", err)
			}

			if size != test.expectedSize {
				t.Errorf("got size %d, want %d", size, test.expectedSize)
			}
		})
	}
}

func TestInvalidDomainNames(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectedErr string
	}{
		{
			name:        "empty input",
			input:       []byte{},
			expectedErr: "Domain Name can't be empty",
		},
		{
			name:        "truncated after length",
			input:       []byte{0x05},
			expectedErr: "Not enough bytes in name's label",
		},
		{
			name:        "truncated in middle of label",
			input:       []byte{0x05, 't', 'e'},
			expectedErr: "Not enough bytes in name's label",
		},
		{
			name:        "missing null terminator",
			input:       []byte{0x04, 't', 'e', 's', 't'},
			expectedErr: "Domain Name can't be empty",
		},
		{
			name:        "label length exceeds remaining data",
			input:       []byte{0x10, 't', 'e', 's', 't', 0x00},
			expectedErr: "Not enough bytes in name's label",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := NewDomainName(test.input)
			if err == nil {
				t.Errorf("expected error but got none")
				return
			}

			if err.Error() != test.expectedErr {
				t.Errorf("got error %q, want %q", err.Error(), test.expectedErr)
			}
		})
	}
}

func TestNewDomainNameWithDecompression(t *testing.T) {
	tests := []struct {
		name            string
		data            []byte
		originalMessage []byte
		expected        *DomainName
		expectedSize    uint16
		expectedErr     bool
	}{
		{
			name:            "simple domain without compression",
			data:            []byte{0x04, 't', 'e', 's', 't', 0x00},
			originalMessage: []byte{},
			expected: &DomainName{
				labels: []Label{
					{length: 4, content: []byte("test")},
				},
			},
			expectedSize: 6,
			expectedErr:  false,
		},
		{
			name:            "empty data",
			data:            []byte{},
			originalMessage: []byte{},
			expected:        nil,
			expectedSize:    0,
			expectedErr:     true,
		},
		{
			name:            "compression pointer with valid offset",
			data:            []byte{0xC0, 0x0C}, // pointer to offset 12
			originalMessage: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's', 't', 0x00},
			expected: &DomainName{
				labels: []Label{
					{length: 4, content: []byte("test")},
				},
			},
			expectedSize: 2,
			expectedErr:  false,
		},
		{
			name:            "compression pointer with invalid offset",
			data:            []byte{0xC0, 0xFF}, // pointer to offset 255 (beyond message)
			originalMessage: []byte{0x04, 't', 'e', 's', 't', 0x00},
			expected:        nil,
			expectedSize:    0,
			expectedErr:     true,
		},
		{
			name:            "incomplete compression pointer",
			data:            []byte{0xC0}, // incomplete pointer
			originalMessage: []byte{},
			expected:        nil,
			expectedSize:    0,
			expectedErr:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, size, err := NewDomainNameWithDecompression(test.data, test.originalMessage)

			if test.expectedErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("got %+v, want %+v", result, test.expected)
			}

			if size != test.expectedSize {
				t.Errorf("got size %d, want %d", size, test.expectedSize)
			}
		})
	}
}
