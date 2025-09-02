package dns

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestDNSQuestionToBytesWithCompression(t *testing.T) {
	tests := []struct {
		name               string
		question           DNSQuestion
		compressionMap     *CompressionMap
		currentOffset      uint16
		expectedResult     []byte
		expectedMapEntries int
		description        string
	}{
		{
			name: "simple question without existing compression",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x01}, // A
			},
			compressionMap: NewCompressionMap(),
			currentOffset:  12,
			expectedResult: []byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x01, // Type A
			},
			expectedMapEntries: 2,
			description:        "Should encode question without compression and add domain to map",
		},
		{
			name: "question with compression pointer for full domain",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x1C}, // AAAA
			},
			compressionMap: func() *CompressionMap {
				compressionMap := NewCompressionMap()
				compressionMap.nameToOffset["example.com."] = 20
				return compressionMap
			}(),
			currentOffset: 50,
			expectedResult: []byte{
				0xC0, 0x14, // Compression pointer to offset 20
				0x00, 0x01, // Class IN
				0x00, 0x1C, // Type AAAA
			},
			expectedMapEntries: 0,
			description:        "Should use compression pointer when domain exists in map",
		},
		{
			name: "question with suffix compression",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 3, content: []byte("www")},
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x0F}, // MX
			},
			compressionMap: func() *CompressionMap {
				compressionMap := NewCompressionMap()
				compressionMap.nameToOffset["example.com."] = 25
				return compressionMap
			}(),
			currentOffset: 60,
			expectedResult: []byte{
				0x03, 'w', 'w', 'w',
				0xC0, 0x19, // Compression pointer to offset 25
				0x00, 0x01, // Class IN
				0x00, 0x0F, // Type MX
			},
			expectedMapEntries: 0,
			description:        "Should use suffix compression when available",
		},
		{
			name: "root domain question",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x02}, // NS
			},
			compressionMap: NewCompressionMap(),
			currentOffset:  100,
			expectedResult: []byte{
				0x00,       // Root domain
				0x00, 0x01, // Class IN
				0x00, 0x02, // Type NS
			},
			expectedMapEntries: 1,
			description:        "Should handle root domain correctly",
		},
		{
			name: "question with zero offset",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 4, content: []byte("test")},
						{length: 3, content: []byte("org")},
					},
				},
				Class: [2]byte{0x00, 0x03}, // CH (Chaos)
				Type:  [2]byte{0x00, 0x10}, // TXT
			},
			compressionMap: NewCompressionMap(),
			currentOffset:  0,
			expectedResult: []byte{
				0x04, 't', 'e', 's', 't',
				0x03, 'o', 'r', 'g',
				0x00,       // End of domain name
				0x00, 0x03, // Class CH
				0x00, 0x10, // Type TXT
			},
			expectedMapEntries: 2,
			description:        "Should handle zero offset correctly",
		},
		{
			name: "question with maximum valid values",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 1, content: []byte("a")},
					},
				},
				Class: [2]byte{0xFF, 0xFF}, // Maximum class value
				Type:  [2]byte{0xFF, 0xFF}, // Maximum type value
			},
			compressionMap: NewCompressionMap(),
			currentOffset:  65535,
			expectedResult: []byte{
				0x01, 'a',
				0x00,       // End of domain name
				0xFF, 0xFF, // Class (max value)
				0xFF, 0xFF, // Type (max value)
			},
			expectedMapEntries: 1,
			description:        "Should handle maximum values correctly",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			initialMapSize := len(testCase.compressionMap.nameToOffset)

			result := testCase.question.ToBytesWithCompression(
				testCase.compressionMap,
				testCase.currentOffset,
			)

			// Verify the result bytes
			if !bytes.Equal(result, testCase.expectedResult) {
				t.Errorf("Result mismatch:\ngot:  %v\nwant: %v\ndescription: %s",
					result, testCase.expectedResult, testCase.description)
			}

			// Verify compression map was updated appropriately
			finalMapSize := len(testCase.compressionMap.nameToOffset)
			expectedFinalSize := initialMapSize + testCase.expectedMapEntries
			if finalMapSize != expectedFinalSize {
				t.Errorf("Compression map size mismatch: got %d entries, want %d entries",
					finalMapSize, expectedFinalSize)
			}

			// Verify the result length is reasonable
			if len(result) < 4 { // At minimum: class (2) + type (2) = 4 bytes
				t.Errorf("Result too short: got %d bytes, minimum expected 4 bytes", len(result))
			}
		})
	}
}

func TestDNSQuestionToBytesWithCompressionEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		question       DNSQuestion
		compressionMap *CompressionMap
		currentOffset  uint16
		expectedLength int
		description    string
	}{
		{
			name: "very long domain name",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 10, content: []byte("verylongname")[:10]},
						{length: 15, content: []byte("anotherlongname")},
						{length: 20, content: []byte("yetanotherverylong12")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01},
				Type:  [2]byte{0x00, 0x01},
			},
			compressionMap: NewCompressionMap(),
			currentOffset:  200,
			expectedLength: 10 + 1 + 15 + 1 + 20 + 1 + 3 + 1 + 1 + 4, // labels + length bytes + null + class + type
			description:    "Should handle very long domain names",
		},
		{
			name: "empty compression map",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 4, content: []byte("test")},
					},
				},
				Class: [2]byte{0x00, 0x01},
				Type:  [2]byte{0x00, 0x01},
			},
			compressionMap: &CompressionMap{
				nameToOffset: make(map[string]uint16),
				message:      make([]byte, 0, 512),
			},
			currentOffset:  50,
			expectedLength: 4 + 1 + 1 + 4, // label + length + null + class + type
			description:    "Should work with empty compression map",
		},
		{
			name: "compression map with many existing entries",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("net")},
					},
				},
				Class: [2]byte{0x00, 0x01},
				Type:  [2]byte{0x00, 0x01},
			},
			compressionMap: func() *CompressionMap {
				compressionMap := NewCompressionMap()
				for index := range 100 {
					key := fmt.Sprintf("domain%d.com.", index)
					compressionMap.nameToOffset[key] = uint16(index * 20)
				}
				return compressionMap
			}(),
			currentOffset:  2000,
			expectedLength: 7 + 1 + 3 + 1 + 1 + 4, // labels + length bytes + null + class + type
			description:    "Should work with compression map containing many entries",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.question.ToBytesWithCompression(
				testCase.compressionMap,
				testCase.currentOffset,
			)

			if len(result) != testCase.expectedLength {
				t.Errorf("Length mismatch: got %d, want %d\ndescription: %s",
					len(result), testCase.expectedLength, testCase.description)
			}

			// Verify structure: should end with class and type (4 bytes)
			if len(result) >= 4 {
				class := [2]byte{result[len(result)-4], result[len(result)-3]}
				resultType := [2]byte{result[len(result)-2], result[len(result)-1]}

				if !bytes.Equal(class[:], testCase.question.Class[:]) {
					t.Errorf("Class mismatch: got %v, want %v",
						class, testCase.question.Class)
				}

				if !bytes.Equal(resultType[:], testCase.question.Type[:]) {
					t.Errorf("Type mismatch: got %v, want %v",
						resultType, testCase.question.Type)
				}
			}
		})
	}
}

func TestDNSQuestionToBytesWithCompressionRoundTrip(t *testing.T) {
	originalQuestion := DNSQuestion{
		Name: DomainName{
			labels: []Label{
				{length: 7, content: []byte("example")},
				{length: 3, content: []byte("com")},
			},
		},
		Class: [2]byte{0x00, 0x01}, // IN
		Type:  [2]byte{0x00, 0x01}, // A
	}

	compressionMap := NewCompressionMap()
	currentOffset := uint16(12)

	// Convert to bytes with compression
	compressedBytes := originalQuestion.ToBytesWithCompression(compressionMap, currentOffset)

	// For comparison, also get bytes without compression
	normalBytes := originalQuestion.ToBytes()

	// Verify that both methods produce valid output
	if len(compressedBytes) == 0 {
		t.Error("ToBytesWithCompression returned empty result")
	}

	if len(normalBytes) == 0 {
		t.Error("ToBytes returned empty result")
	}

	// Both should end with the same class and type
	if len(compressedBytes) >= 4 && len(normalBytes) >= 4 {
		compressedClassType := compressedBytes[len(compressedBytes)-4:]
		normalClassType := normalBytes[len(normalBytes)-4:]

		if !bytes.Equal(compressedClassType, normalClassType) {
			t.Errorf("Class and type should be identical:\ncompressed: %v\nnormal: %v",
				compressedClassType, normalClassType)
		}
	}

	// Verify compression map was updated
	if len(compressionMap.nameToOffset) == 0 {
		t.Error("Compression map should have been updated with domain name")
	}

	// Check that the domain was added to compression map
	expectedDomain := "example.com."
	if _, exists := compressionMap.nameToOffset[expectedDomain]; !exists {
		t.Errorf("Domain %s should be in compression map", expectedDomain)
	}
}

func TestDNSQuestionToBytesWithCompressionConsistency(t *testing.T) {
	question := DNSQuestion{
		Name: DomainName{
			labels: []Label{
				{length: 4, content: []byte("test")},
				{length: 7, content: []byte("example")},
				{length: 3, content: []byte("org")},
			},
		},
		Class: [2]byte{0x00, 0x01}, // IN
		Type:  [2]byte{0x00, 0x0F}, // MX
	}

	// Test multiple calls with the same parameters
	compressionMap := NewCompressionMap()
	currentOffset := uint16(50)

	result1 := question.ToBytesWithCompression(compressionMap, currentOffset)
	result2 := question.ToBytesWithCompression(compressionMap, currentOffset)

	// Second call should use compression and be shorter
	if len(result2) >= len(result1) {
		t.Errorf("Second call should use compression and be shorter: first=%d, second=%d",
			len(result1), len(result2))
	}

	// Both should end with the same class and type
	if len(result1) >= 4 && len(result2) >= 4 {
		classType1 := result1[len(result1)-4:]
		classType2 := result2[len(result2)-4:]

		if !bytes.Equal(classType1, classType2) {
			t.Errorf("Class and type should be consistent:\nfirst: %v\nsecond: %v",
				classType1, classType2)
		}
	}
}

func TestDNSQuestionToBytes(t *testing.T) {
	tests := []struct {
		name           string
		question       DNSQuestion
		expectedResult []byte
		description    string
	}{
		{
			name: "simple A record question",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("com")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x01}, // A
			},
			expectedResult: []byte{
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x01, // Type A
			},
			description: "Should encode simple A record question correctly",
		},
		{
			name: "root domain NS question",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x02}, // NS
			},
			expectedResult: []byte{
				0x00,       // Root domain
				0x00, 0x01, // Class IN
				0x00, 0x02, // Type NS
			},
			description: "Should encode root domain NS question correctly",
		},
		{
			name: "MX record question",
			question: DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{length: 4, content: []byte("mail")},
						{length: 7, content: []byte("example")},
						{length: 3, content: []byte("net")},
					},
				},
				Class: [2]byte{0x00, 0x01}, // IN
				Type:  [2]byte{0x00, 0x0F}, // MX
			},
			expectedResult: []byte{
				0x04, 'm', 'a', 'i', 'l',
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'n', 'e', 't',
				0x00,       // End of domain name
				0x00, 0x01, // Class IN
				0x00, 0x0F, // Type MX
			},
			description: "Should encode MX record question correctly",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := testCase.question.ToBytes()

			if !bytes.Equal(result, testCase.expectedResult) {
				t.Errorf("Result mismatch:\ngot:  %v\nwant: %v\ndescription: %s",
					result, testCase.expectedResult, testCase.description)
			}
		})
	}
}

func TestDNSQuestionToBytesRoundTrip(t *testing.T) {
	originalQuestion := DNSQuestion{
		Name: DomainName{
			labels: []Label{
				{length: 3, content: []byte("www")},
				{length: 7, content: []byte("example")},
				{length: 3, content: []byte("com")},
			},
		},
		Class: [2]byte{0x00, 0x01}, // IN
		Type:  [2]byte{0x00, 0x1C}, // AAAA
	}

	// Convert to bytes
	questionBytes := originalQuestion.ToBytes()

	// Verify the bytes can be used to reconstruct a similar structure
	if len(questionBytes) < 4 {
		t.Fatalf("Question bytes too short: %d", len(questionBytes))
	}

	// Extract class and type from the end
	extractedClass := [2]byte{questionBytes[len(questionBytes)-4], questionBytes[len(questionBytes)-3]}
	extractedType := [2]byte{questionBytes[len(questionBytes)-2], questionBytes[len(questionBytes)-1]}

	if !bytes.Equal(extractedClass[:], originalQuestion.Class[:]) {
		t.Errorf("Class round-trip failed: got %v, want %v",
			extractedClass, originalQuestion.Class)
	}

	if !bytes.Equal(extractedType[:], originalQuestion.Type[:]) {
		t.Errorf("Type round-trip failed: got %v, want %v",
			extractedType, originalQuestion.Type)
	}
}

// Helper function for tests
func createTestQuestion(domain string, class, recordType uint16) DNSQuestion {
	var labels []Label
	if domain != "." {
		parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
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
		Class: [2]byte{byte(class >> 8), byte(class & 0xFF)},
		Type:  [2]byte{byte(recordType >> 8), byte(recordType & 0xFF)},
	}
}

func TestCreateTestQuestion(t *testing.T) {
	question := createTestQuestion("example.com.", 1, 1)

	if len(question.Name.labels) != 2 {
		t.Errorf("Expected 2 labels, got %d", len(question.Name.labels))
	}

	if string(question.Name.labels[0].content) != "example" {
		t.Errorf("Expected first label to be 'example', got '%s'", question.Name.labels[0].content)
	}

	if string(question.Name.labels[1].content) != "com" {
		t.Errorf("Expected second label to be 'com', got '%s'", question.Name.labels[1].content)
	}

	expectedClass := [2]byte{0x00, 0x01}
	if question.Class != expectedClass {
		t.Errorf("Expected class %v, got %v", expectedClass, question.Class)
	}

	expectedType := [2]byte{0x00, 0x01}
	if question.Type != expectedType {
		t.Errorf("Expected type %v, got %v", expectedType, question.Type)
	}
}
