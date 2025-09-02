package dns

import (
	"reflect"
	"testing"
)

func TestDnsTypeClassToBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected [2]byte
	}{
		// Test DNSType values
		{
			name:     "TYPE_A",
			input:    TYPE_A,
			expected: [2]byte{0x00, 0x01},
		},
		{
			name:     "TYPE_NS",
			input:    TYPE_NS,
			expected: [2]byte{0x00, 0x02},
		},
		{
			name:     "TYPE_CNAME",
			input:    TYPE_CNAME,
			expected: [2]byte{0x00, 0x05},
		},
		{
			name:     "TYPE_SOA",
			input:    TYPE_SOA,
			expected: [2]byte{0x00, 0x06},
		},
		{
			name:     "TYPE_PTR",
			input:    TYPE_PTR,
			expected: [2]byte{0x00, 0x0C},
		},
		{
			name:     "TYPE_MX",
			input:    TYPE_MX,
			expected: [2]byte{0x00, 0x0F},
		},
		{
			name:     "TYPE_TXT",
			input:    TYPE_TXT,
			expected: [2]byte{0x00, 0x10},
		},
		{
			name:     "TYPE_AAAA",
			input:    TYPE_AAAA,
			expected: [2]byte{0x00, 0x1C},
		},
		// Test DNSClass values
		{
			name:     "CLASS_IN",
			input:    CLASS_IN,
			expected: [2]byte{0x00, 0x01},
		},
		{
			name:     "CLASS_CS",
			input:    CLASS_CS,
			expected: [2]byte{0x00, 0x02},
		},
		{
			name:     "CLASS_CH",
			input:    CLASS_CH,
			expected: [2]byte{0x00, 0x03},
		},
		{
			name:     "CLASS_HS",
			input:    CLASS_HS,
			expected: [2]byte{0x00, 0x04},
		},
		// Test edge cases with high byte values
		{
			name:     "high value DNSType",
			input:    DNSType(0x1234),
			expected: [2]byte{0x12, 0x34},
		},
		{
			name:     "high value DNSClass",
			input:    DNSClass(0xABCD),
			expected: [2]byte{0xAB, 0xCD},
		},
		{
			name:     "maximum uint16 value as DNSType",
			input:    DNSType(0xFFFF),
			expected: [2]byte{0xFF, 0xFF},
		},
		{
			name:     "zero value as DNSType",
			input:    DNSType(0x0000),
			expected: [2]byte{0x00, 0x00},
		},
		{
			name:     "zero value as DNSClass",
			input:    DNSClass(0x0000),
			expected: [2]byte{0x00, 0x00},
		},
		// Test byte boundary values
		{
			name:     "value 0x00FF",
			input:    DNSType(0x00FF),
			expected: [2]byte{0x00, 0xFF},
		},
		{
			name:     "value 0xFF00",
			input:    DNSType(0xFF00),
			expected: [2]byte{0xFF, 0x00},
		},
		{
			name:     "value 0x0100",
			input:    DNSType(0x0100),
			expected: [2]byte{0x01, 0x00},
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			var result [2]byte

			switch value := test_case.input.(type) {
			case DNSType:
				result = dnsTypeClassToBytes(value)
			case DNSClass:
				result = dnsTypeClassToBytes(value)
			default:
				t.Fatalf("Unsupported input type: %T", value)
			}

			if !reflect.DeepEqual(result, test_case.expected) {
				t.Errorf(
					"dnsTypeClassToBytes(%v) = %v, expected %v",
					test_case.input,
					result,
					test_case.expected,
				)
			}
		})
	}
}

func TestDnsTypeClassToBytesWithGenericUint16(t *testing.T) {
	tests := []struct {
		name     string
		input    uint16
		expected [2]byte
	}{
		{
			name:     "generic uint16 zero",
			input:    0x0000,
			expected: [2]byte{0x00, 0x00},
		},
		{
			name:     "generic uint16 low byte only",
			input:    0x00AB,
			expected: [2]byte{0x00, 0xAB},
		},
		{
			name:     "generic uint16 high byte only",
			input:    0xCD00,
			expected: [2]byte{0xCD, 0x00},
		},
		{
			name:     "generic uint16 both bytes",
			input:    0x1234,
			expected: [2]byte{0x12, 0x34},
		},
		{
			name:     "generic uint16 maximum",
			input:    0xFFFF,
			expected: [2]byte{0xFF, 0xFF},
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			result := dnsTypeClassToBytes(test_case.input)

			if !reflect.DeepEqual(result, test_case.expected) {
				t.Errorf(
					"dnsTypeClassToBytes(%v) = %v, expected %v",
					test_case.input,
					result,
					test_case.expected,
				)
			}
		})
	}
}

func TestDnsTypeClassToBytesRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		dnsType    DNSType
		dnsClass   DNSClass
		genericVal uint16
	}{
		{
			name:       "round trip test 1",
			dnsType:    TYPE_A,
			dnsClass:   CLASS_IN,
			genericVal: 0x1234,
		},
		{
			name:       "round trip test 2",
			dnsType:    TYPE_MX,
			dnsClass:   CLASS_CH,
			genericVal: 0xABCD,
		},
	}

	for _, test_case := range tests {
		t.Run(test_case.name, func(t *testing.T) {
			// Test DNSType round trip
			typeBytes := dnsTypeClassToBytes(test_case.dnsType)
			reconstructedType := uint16(typeBytes[0])<<8 | uint16(typeBytes[1])
			if DNSType(reconstructedType) != test_case.dnsType {
				t.Errorf(
					"DNSType round trip failed: original=%v, reconstructed=%v",
					test_case.dnsType,
					DNSType(reconstructedType),
				)
			}

			// Test DNSClass round trip
			classBytes := dnsTypeClassToBytes(test_case.dnsClass)
			reconstructedClass := uint16(classBytes[0])<<8 | uint16(classBytes[1])
			if DNSClass(reconstructedClass) != test_case.dnsClass {
				t.Errorf(
					"DNSClass round trip failed: original=%v, reconstructed=%v",
					test_case.dnsClass,
					DNSClass(reconstructedClass),
				)
			}

			// Test generic uint16 round trip
			genericBytes := dnsTypeClassToBytes(test_case.genericVal)
			reconstructedGeneric := uint16(genericBytes[0])<<8 | uint16(genericBytes[1])
			if reconstructedGeneric != test_case.genericVal {
				t.Errorf(
					"Generic uint16 round trip failed: original=%v, reconstructed=%v",
					test_case.genericVal,
					reconstructedGeneric,
				)
			}
		})
	}
}

func FuzzDnsTypeClassToBytes(f *testing.F) {
	// Add seed values for the fuzzer
	seed_values := []uint16{
		0x0000, // minimum value
		0x0001, // TYPE_A
		0x0002, // TYPE_NS
		0x0005, // TYPE_CNAME
		0x000F, // TYPE_MX
		0x0100, // byte boundary
		0x00FF, // byte boundary
		0xFF00, // byte boundary
		0x1234, // arbitrary value
		0xABCD, // arbitrary value
		0xFFFF, // maximum value
	}

	for _, seed_value := range seed_values {
		f.Add(seed_value)
	}

	f.Fuzz(func(t *testing.T, input_value uint16) {
		// Test with raw uint16
		result := dnsTypeClassToBytes(input_value)

		// Verify the conversion is correct
		expected_high_byte := byte(input_value >> 8)
		expected_low_byte := byte(input_value & 0xFF)

		if result[0] != expected_high_byte {
			t.Errorf(
				"High byte mismatch for input %v: got %v, expected %v",
				input_value,
				result[0],
				expected_high_byte,
			)
		}

		if result[1] != expected_low_byte {
			t.Errorf(
				"Low byte mismatch for input %v: got %v, expected %v",
				input_value,
				result[1],
				expected_low_byte,
			)
		}

		// Test round trip conversion
		reconstructed := uint16(result[0])<<8 | uint16(result[1])
		if reconstructed != input_value {
			t.Errorf(
				"Round trip failed for input %v: got %v",
				input_value,
				reconstructed,
			)
		}

		// Test with DNSType cast
		dns_type_result := dnsTypeClassToBytes(DNSType(input_value))
		if !reflect.DeepEqual(result, dns_type_result) {
			t.Errorf(
				"DNSType cast result differs for input %v: uint16=%v, DNSType=%v",
				input_value,
				result,
				dns_type_result,
			)
		}

		// Test with DNSClass cast
		dns_class_result := dnsTypeClassToBytes(DNSClass(input_value))
		if !reflect.DeepEqual(result, dns_class_result) {
			t.Errorf(
				"DNSClass cast result differs for input %v: uint16=%v, DNSClass=%v",
				input_value,
				result,
				dns_class_result,
			)
		}
	})
}
