package dns

import (
	"reflect"
	"testing"
)

func TestNewCompressionMap(t *testing.T) {
	compression_map := NewCompressionMap()

	if compression_map == nil {
		t.Fatal("NewCompressionMap() returned nil")
	}

	if compression_map.nameToOffset == nil {
		t.Error("nameToOffset map is nil")
	}

	if compression_map.message == nil {
		t.Error("message slice is nil")
	}

	if len(compression_map.nameToOffset) != 0 {
		t.Errorf("nameToOffset map should be empty, got length %d", len(compression_map.nameToOffset))
	}

	if len(compression_map.message) != 0 {
		t.Errorf("message slice should be empty, got length %d", len(compression_map.message))
	}

	if cap(compression_map.message) != 512 {
		t.Errorf("message slice should have capacity 512, got %d", cap(compression_map.message))
	}
}

func TestCreateCompressionPointer(t *testing.T) {
	tests := []struct {
		name     string
		offset   uint16
		expected []byte
	}{
		{
			name:     "zero offset",
			offset:   0x0000,
			expected: []byte{0xC0, 0x00},
		},
		{
			name:     "small offset",
			offset:   0x0001,
			expected: []byte{0xC0, 0x01},
		},
		{
			name:     "medium offset",
			offset:   0x0012,
			expected: []byte{0xC0, 0x12},
		},
		{
			name:     "large offset",
			offset:   0x1234,
			expected: []byte{0xD2, 0x34},
		},
		{
			name:     "maximum valid offset",
			offset:   0x3FFF, // 14 bits maximum
			expected: []byte{0xFF, 0xFF},
		},
		{
			name:     "byte boundary 0x00FF",
			offset:   0x00FF,
			expected: []byte{0xC0, 0xFF},
		},
		{
			name:     "byte boundary 0x0100",
			offset:   0x0100,
			expected: []byte{0xC1, 0x00},
		},
		{
			name:     "typical DNS offset",
			offset:   0x000C, // Common offset for DNS headers
			expected: []byte{0xC0, 0x0C},
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			result := createCompressionPointer(test_case.offset)

			if !reflect.DeepEqual(result, test_case.expected) {
				t.Errorf(
					"createCompressionPointer(%v) = %v, expected %v",
					test_case.offset,
					result,
					test_case.expected,
				)
			}

			// Verify the result has compression bits set
			if (result[0] & 0xC0) != 0xC0 {
				t.Errorf(
					"Result does not have compression bits set: first byte = 0x%02X",
					result[0],
				)
			}
		})
	}
}

func TestCreateCompressionPointerRoundTrip(t *testing.T) {
	test_offsets := []uint16{
		0x0000,
		0x0001,
		0x0012,
		0x00FF,
		0x0100,
		0x1234,
		0x3FFF,
	}

	for _, original_offset := range test_offsets {
		t.Run(
			"round_trip_"+string(rune(original_offset)),
			func(t *testing.T) {
				pointer_bytes := createCompressionPointer(original_offset)
				extracted_offset := extractCompressionOffset(pointer_bytes)

				if extracted_offset != original_offset {
					t.Errorf(
						"Round trip failed: original=%v, extracted=%v",
						original_offset,
						extracted_offset,
					)
				}
			},
		)
	}
}

func TestIsCompressionPointer(t *testing.T) {
	tests := []struct {
		name      string
		firstByte byte
		expected  bool
	}{
		{
			name:      "compression pointer 0xC0",
			firstByte: 0xC0,
			expected:  true,
		},
		{
			name:      "compression pointer 0xC1",
			firstByte: 0xC1,
			expected:  true,
		},
		{
			name:      "compression pointer 0xFF",
			firstByte: 0xFF,
			expected:  true,
		},
		{
			name:      "compression pointer 0xD2",
			firstByte: 0xD2,
			expected:  true,
		},
		{
			name:      "not compression pointer 0x00",
			firstByte: 0x00,
			expected:  false,
		},
		{
			name:      "not compression pointer 0x3F",
			firstByte: 0x3F,
			expected:  false,
		},
		{
			name:      "not compression pointer 0x80",
			firstByte: 0x80,
			expected:  false,
		},
		{
			name:      "not compression pointer 0xBF",
			firstByte: 0xBF,
			expected:  false,
		},
		{
			name:      "label length 1",
			firstByte: 0x01,
			expected:  false,
		},
		{
			name:      "label length 63",
			firstByte: 0x3F,
			expected:  false,
		},
		{
			name:      "reserved bits 10",
			firstByte: 0x80,
			expected:  false,
		},
		{
			name:      "reserved bits 01",
			firstByte: 0x40,
			expected:  false,
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			result := isCompressionPointer(test_case.firstByte)

			if result != test_case.expected {
				t.Errorf(
					"isCompressionPointer(0x%02X) = %v, expected %v",
					test_case.firstByte,
					result,
					test_case.expected,
				)
			}
		})
	}
}

func TestExtractCompressionOffset(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint16
	}{
		{
			name:     "zero offset",
			data:     []byte{0xC0, 0x00},
			expected: 0x0000,
		},
		{
			name:     "small offset",
			data:     []byte{0xC0, 0x01},
			expected: 0x0001,
		},
		{
			name:     "medium offset",
			data:     []byte{0xC0, 0x12},
			expected: 0x0012,
		},
		{
			name:     "large offset",
			data:     []byte{0xD2, 0x34},
			expected: 0x1234,
		},
		{
			name:     "maximum offset",
			data:     []byte{0xFF, 0xFF},
			expected: 0x3FFF,
		},
		{
			name:     "byte boundary 0x00FF",
			data:     []byte{0xC0, 0xFF},
			expected: 0x00FF,
		},
		{
			name:     "byte boundary 0x0100",
			data:     []byte{0xC1, 0x00},
			expected: 0x0100,
		},
		{
			name:     "typical DNS header offset",
			data:     []byte{0xC0, 0x0C},
			expected: 0x000C,
		},
		{
			name:     "with extra data",
			data:     []byte{0xC0, 0x0C, 0x99, 0x88},
			expected: 0x000C,
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			result := extractCompressionOffset(test_case.data)

			if result != test_case.expected {
				t.Errorf(
					"extractCompressionOffset(%v) = 0x%04X, expected 0x%04X",
					test_case.data,
					result,
					test_case.expected,
				)
			}
		})
	}
}

func TestExtractCompressionOffsetMasking(t *testing.T) {
	// Test that the function properly masks out the compression bits
	tests := []struct {
		name        string
		firstByte   byte
		secondByte  byte
		expected    uint16
		description string
	}{
		{
			name:        "mask compression bits 11",
			firstByte:   0xC0, // 11000000
			secondByte:  0x00,
			expected:    0x0000,
			description: "compression bits 11 should be masked out",
		},
		{
			name:        "mask compression bits 11 with offset bits",
			firstByte:   0xFF, // 11111111
			secondByte:  0xFF,
			expected:    0x3FFF, // 00111111 11111111
			description: "compression bits should be masked, leaving 14 offset bits",
		},
		{
			name:        "partial offset in first byte",
			firstByte:   0xD5, // 11010101
			secondByte:  0xAA,
			expected:    0x15AA, // 00010101 10101010
			description: "only lower 6 bits of first byte should be used",
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			data := []byte{test_case.firstByte, test_case.secondByte}
			result := extractCompressionOffset(data)

			if result != test_case.expected {
				t.Errorf(
					"extractCompressionOffset([0x%02X, 0x%02X]) = 0x%04X, expected 0x%04X (%s)",
					test_case.firstByte,
					test_case.secondByte,
					result,
					test_case.expected,
					test_case.description,
				)
			}

			// Verify that compression bits are properly masked
			high_byte_masked := test_case.firstByte & 0x3F
			expected_from_manual := uint16(high_byte_masked)<<8 | uint16(test_case.secondByte)
			if result != expected_from_manual {
				t.Errorf(
					"Masking verification failed: got 0x%04X, manual calculation gives 0x%04X",
					result,
					expected_from_manual,
				)
			}
		})
	}
}

func TestCompressionConstants(t *testing.T) {
	// Test the compression pointer mask constant
	if COMPRESSION_POINTER_MASK != 0xC000 {
		t.Errorf(
			"COMPRESSION_POINTER_MASK = 0x%04X, expected 0xC000",
			COMPRESSION_POINTER_MASK,
		)
	}

	// Verify the mask has the correct bit pattern (11 followed by 14 zeros)
	expected_binary := "1100000000000000"
	actual_binary := ""
	for bit_position := 15; bit_position >= 0; bit_position-- {
		if (COMPRESSION_POINTER_MASK>>bit_position)&1 == 1 {
			actual_binary += "1"
		} else {
			actual_binary += "0"
		}
	}

	if actual_binary != expected_binary {
		t.Errorf(
			"COMPRESSION_POINTER_MASK binary representation = %s, expected %s",
			actual_binary,
			expected_binary,
		)
	}
}

func TestCompressionPointerIntegration(t *testing.T) {
	// Test the complete flow: create pointer -> check if pointer -> extract offset
	test_offsets := []uint16{0x0000, 0x000C, 0x0012, 0x1234, 0x3FFF}

	for _, original_offset := range test_offsets {
		t.Run(
			"integration_test_offset_"+string(rune(original_offset)),
			func(t *testing.T) {
				// Step 1: Create compression pointer
				pointer_bytes := createCompressionPointer(original_offset)

				// Step 2: Verify it's recognized as a compression pointer
				if !isCompressionPointer(pointer_bytes[0]) {
					t.Errorf(
						"Created pointer not recognized as compression pointer: first byte = 0x%02X",
						pointer_bytes[0],
					)
				}

				// Step 3: Extract offset and verify it matches original
				extracted_offset := extractCompressionOffset(pointer_bytes)
				if extracted_offset != original_offset {
					t.Errorf(
						"Integration test failed: original=%v, extracted=%v",
						original_offset,
						extracted_offset,
					)
				}
			},
		)
	}
}

func FuzzCreateCompressionPointer(f *testing.F) {
	// Add seed values for the fuzzer
	seed_offsets := []uint16{
		0x0000, // minimum
		0x000C, // typical DNS offset
		0x0100, // byte boundary
		0x1234, // arbitrary value
		0x3FFF, // maximum valid 14-bit value
	}

	for _, seed_offset := range seed_offsets {
		f.Add(seed_offset)
	}

	f.Fuzz(func(t *testing.T, offset uint16) {
		// Only test with valid 14-bit offsets
		valid_offset := offset & 0x3FFF

		pointer_bytes := createCompressionPointer(valid_offset)

		// Verify result length
		if len(pointer_bytes) != 2 {
			t.Errorf("Expected 2 bytes, got %d", len(pointer_bytes))
		}

		// Verify compression bits are set
		if (pointer_bytes[0] & 0xC0) != 0xC0 {
			t.Errorf(
				"Compression bits not set correctly: first byte = 0x%02X",
				pointer_bytes[0],
			)
		}

		// Verify round trip
		extracted := extractCompressionOffset(pointer_bytes)
		if extracted != valid_offset {
			t.Errorf(
				"Round trip failed: input=%v, extracted=%v",
				valid_offset,
				extracted,
			)
		}

		// Verify isCompressionPointer recognizes it
		if !isCompressionPointer(pointer_bytes[0]) {
			t.Errorf(
				"isCompressionPointer failed to recognize created pointer: 0x%02X",
				pointer_bytes[0],
			)
		}
	})
}

func TestCompressionPointerEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		offset        uint16
		shouldBeValid bool
		description   string
	}{
		{
			name:          "offset exceeds 14 bits",
			offset:        0x4000, // 16th bit set
			shouldBeValid: false,
			description:   "offset that would overflow 14-bit limit",
		},
		{
			name:          "offset uses all 14 bits",
			offset:        0x3FFF, // maximum 14-bit value
			shouldBeValid: true,
			description:   "maximum valid offset",
		},
		{
			name:          "offset with 15th bit set",
			offset:        0x8000,
			shouldBeValid: false,
			description:   "offset with high bit set",
		},
		{
			name:          "offset with multiple high bits",
			offset:        0xFFFF,
			shouldBeValid: false,
			description:   "maximum uint16 value",
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			pointer_bytes := createCompressionPointer(test_case.offset)

			// Always verify compression bits are set
			if (pointer_bytes[0] & 0xC0) != 0xC0 {
				t.Errorf(
					"Compression bits not set correctly: first byte = 0x%02X",
					pointer_bytes[0],
				)
			}

			// Extract and verify the offset is masked to 14 bits
			extracted_offset := extractCompressionOffset(pointer_bytes)
			expected_masked := test_case.offset & 0x3FFF

			if extracted_offset != expected_masked {
				t.Errorf(
					"Offset masking failed: input=0x%04X, extracted=0x%04X, expected=0x%04X",
					test_case.offset,
					extracted_offset,
					expected_masked,
				)
			}
		})
	}
}

func TestExtractCompressionOffsetWithInvalidData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint16
	}{
		{
			name:     "non-compression pointer data",
			data:     []byte{0x80, 0x12}, // reserved bit pattern 10
			expected: 0x0012,             // Still extracts offset bits
		},
		{
			name:     "label length data",
			data:     []byte{0x03, 0x77}, // normal label length
			expected: 0x0377,             // Extracts as if it were offset
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			// Note: extractCompressionOffset assumes data has at least 2 bytes
			// and doesn't validate input format - it just extracts offset bits
			result := extractCompressionOffset(test_case.data)

			if result != test_case.expected {
				t.Errorf(
					"extractCompressionOffset(%v) = 0x%04X, expected 0x%04X",
					test_case.data,
					result,
					test_case.expected,
				)
			}
		})
	}
}

func TestExtractCompressionOffsetRequirements(t *testing.T) {
	// Test that the function requires at least 2 bytes of input
	// This documents the function's precondition
	defer func() {
		if recovery := recover(); recovery == nil {
			t.Error("Expected panic when calling extractCompressionOffset with insufficient data")
		}
	}()

	// This should panic due to slice bounds check
	_ = extractCompressionOffset([]byte{0xC0})
}

func TestCompressionMapInitialization(t *testing.T) {
	compression_map := NewCompressionMap()

	// Test that we can add entries to the map (conceptual test)
	if compression_map.nameToOffset == nil {
		t.Error("nameToOffset should be initialized")
	}

	if compression_map.message == nil {
		t.Error("message should be initialized")
	}

	// Test initial state
	if len(compression_map.nameToOffset) != 0 {
		t.Error("nameToOffset should start empty")
	}

	if len(compression_map.message) != 0 {
		t.Error("message should start empty")
	}

	// Test capacity allocation
	if cap(compression_map.message) != 512 {
		t.Errorf("message should have initial capacity 512, got %d", cap(compression_map.message))
	}
}

func TestCompressionPointerBitManipulation(t *testing.T) {
	// Test specific bit patterns to ensure correct bit manipulation
	test_cases := []struct {
		name          string
		offset        uint16
		expectedBits  string
		expectedBytes [2]byte
	}{
		{
			name:          "all zeros",
			offset:        0x0000,
			expectedBits:  "1100000000000000",
			expectedBytes: [2]byte{0xC0, 0x00},
		},
		{
			name:          "alternating pattern",
			offset:        0x2AAA, // 10101010101010
			expectedBits:  "1110101010101010",
			expectedBytes: [2]byte{0xEA, 0xAA},
		},
		{
			name:          "inverse alternating",
			offset:        0x1555, // 01010101010101
			expectedBits:  "1101010101010101",
			expectedBytes: [2]byte{0xD5, 0x55},
		},
	}

	for _, test_case := range test_cases {
		t.Run(test_case.name, func(t *testing.T) {
			result := createCompressionPointer(test_case.offset)

			if !reflect.DeepEqual(result, test_case.expectedBytes[:]) {
				t.Errorf(
					"createCompressionPointer(0x%04X) = [0x%02X, 0x%02X], expected [0x%02X, 0x%02X]",
					test_case.offset,
					result[0], result[1],
					test_case.expectedBytes[0], test_case.expectedBytes[1],
				)
			}

			// Verify bit pattern
			combined := uint16(result[0])<<8 | uint16(result[1])
			actual_bits := ""
			for bit_position := 15; bit_position >= 0; bit_position-- {
				if (combined>>bit_position)&1 == 1 {
					actual_bits += "1"
				} else {
					actual_bits += "0"
				}
			}

			if actual_bits != test_case.expectedBits {
				t.Errorf(
					"Bit pattern mismatch: got %s, expected %s",
					actual_bits,
					test_case.expectedBits,
				)
			}
		})
	}
}
