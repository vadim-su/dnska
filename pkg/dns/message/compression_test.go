package message

import (
	"reflect"
	"testing"

	"github.com/vadim-su/dnska/pkg/dns/utils"
)

func TestNewCompressionMap(t *testing.T) {
	compression_map := utils.NewCompressionMap()

	if compression_map == nil {
		t.Fatal("NewCompressionMap() returned nil")
	}

	// Note: Cannot test private fields nameToOffset and message from outside the utils package
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
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			result := utils.CreateCompressionPointer(test_case.offset)

			if !reflect.DeepEqual(result, test_case.expected) {
				t.Errorf(
					"CreateCompressionPointer(%v) = %v, expected %v",
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
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			result := utils.IsCompressionPointer(test_case.firstByte)

			if result != test_case.expected {
				t.Errorf(
					"IsCompressionPointer(0x%02X) = %v, expected %v",
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
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			result := utils.ExtractCompressionOffset(test_case.data)

			if result != test_case.expected {
				t.Errorf(
					"ExtractCompressionOffset(%v) = 0x%04X, expected 0x%04X",
					test_case.data,
					result,
					test_case.expected,
				)
			}
		})
	}
}

func TestCompressionConstants(t *testing.T) {
	// Test the compression pointer mask constant
	if utils.COMPRESSION_POINTER_MASK != 0xC000 {
		t.Errorf(
			"COMPRESSION_POINTER_MASK = 0x%04X, expected 0xC000",
			utils.COMPRESSION_POINTER_MASK,
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
				pointer_bytes := utils.CreateCompressionPointer(original_offset)

				// Step 2: Verify it's recognized as a compression pointer
				if !utils.IsCompressionPointer(pointer_bytes[0]) {
					t.Errorf(
						"Created pointer not recognized as compression pointer: first byte = 0x%02X",
						pointer_bytes[0],
					)
				}

				// Step 3: Extract offset and verify it matches original
				extracted_offset := utils.ExtractCompressionOffset(pointer_bytes)
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
