package dns

import "fmt"

const (
	NULL_BYTE = byte('\x00')
)

// Label represents a single label in a domain name
type Label struct {
	length  uint8
	content []byte
}

// ToBytes converts the Label to its byte representation
func (l *Label) ToBytes() []byte {
	label := make([]byte, l.length+1)

	label[0] = l.length
	copy(label[1:], l.content)

	return label
}

// DomainName represents a full domain name composed of multiple labels
type DomainName struct {
	labels []Label
}

// NewDomainName creates a new DomainName from raw byte data
func NewDomainName(data []byte) (*DomainName, uint16, error) {
	var length uint8
	var labels []Label
	var size uint16

	for {
		if len(data) == 0 {
			return nil, 0, fmt.Errorf("domain name can't be empty")
		}

		length = data[0]
		size += 1 // Count the length byte itself

		if length == NULL_BYTE {
			return &DomainName{labels}, size, nil
		}

		if len(data[1:]) < int(length) {
			return nil, 0, fmt.Errorf("not enough bytes in name's label")
		}

		labels = append(labels, Label{length, data[1 : length+1]})
		size += uint16(length) // Count the label content bytes
		data = data[length+1:] // Move past length byte + label content
	}
}

// ToBytes converts the DomainName to its byte representation
func (d *DomainName) ToBytes() []byte {
	totalBytes := uint(1) // Count ending byte

	for _, label := range d.labels {
		totalBytes += uint(label.length) + 1
	}

	domainName := make([]byte, totalBytes)

	cursor := uint(0)
	for _, label := range d.labels {
		labelBytes := label.ToBytes()
		copy(domainName[cursor:cursor+uint(len(labelBytes))], labelBytes)
		cursor += uint(len(labelBytes)) // THIS LINE WAS MISSING!
	}

	domainName[len(domainName)-1] = NULL_BYTE

	return domainName
}

// ToBytesWithCompression converts the DomainName to bytes using DNS name compression
func (d *DomainName) ToBytesWithCompression(
	compressionMap *CompressionMap,
	currentOffset uint16,
) []byte {
	// Try to find existing occurrence of this domain name
	domainString := d.String()

	// Check if we can use a pointer for the entire domain
	if offset, exists := compressionMap.nameToOffset[domainString]; exists {
		return createCompressionPointer(offset)
	}

	result := make([]byte, 0)

	// Check for suffix compression
	for labelIndex := 0; labelIndex < len(d.labels); labelIndex++ {
		suffix := d.getSuffixFrom(labelIndex)
		suffixString := suffix.String()

		if offset, exists := compressionMap.nameToOffset[suffixString]; exists {
			// Add the labels before the suffix
			for idx := range labelIndex {
				labelBytes := d.labels[idx].ToBytes()
				result = append(result, labelBytes...)
			}
			// Add compression pointer
			pointer := createCompressionPointer(offset)
			result = append(result, pointer...)
			return result
		}
	}

	// No compression possible, store full domain name
	fullBytes := d.ToBytes()

	// Store this domain name for future compression
	compressionMap.nameToOffset[domainString] = currentOffset

	// Also store all suffixes for future compression
	for labelIndex := 1; labelIndex < len(d.labels); labelIndex++ {
		suffix := d.getSuffixFrom(labelIndex)
		suffixOffset := currentOffset + d.getBytesUpToLabel(labelIndex)
		compressionMap.nameToOffset[suffix.String()] = suffixOffset
	}

	return fullBytes
}

// String converts the DomainName to its string representation
func (d *DomainName) String() string {
	if len(d.labels) == 0 {
		return "."
	}

	result := ""
	for _, label := range d.labels {
		result += string(label.content) + "."
	}
	return result
}

// getSuffixFrom returns a new DomainName starting from the specified label index
func (d *DomainName) getSuffixFrom(startIndex int) *DomainName {
	if startIndex >= len(d.labels) {
		return &DomainName{labels: []Label{}}
	}
	return &DomainName{labels: d.labels[startIndex:]}
}

// getBytesUpToLabel calculates the byte size of the domain name up to the specified label index
func (d *DomainName) getBytesUpToLabel(labelIndex int) uint16 {
	size := uint16(0)
	for idx := range labelIndex {
		size += uint16(d.labels[idx].length) + 1 // +1 for length byte
	}
	return size
}

// NewDomainNameWithDecompression creates a DomainName from raw byte data, handling DNS name compression
func NewDomainNameWithDecompression(
	data []byte,
	originalMessage []byte,
) (*DomainName, uint16, error) {
	var labels []Label
	var size uint16

	for {
		if len(data) == 0 {
			return nil, 0, fmt.Errorf("domain name can't be empty")
		}

		firstByte := data[0]

		// Check if this is a compression pointer
		if isCompressionPointer(firstByte) {
			if len(data) < 2 {
				return nil, 0, fmt.Errorf("invalid compression pointer")
			}

			// Extract offset from pointer
			offset := extractCompressionOffset(data)
			size += 2 // Compression pointer is 2 bytes

			// Follow the pointer to get remaining labels
			if int(offset) >= len(originalMessage) {
				return nil, 0, fmt.Errorf("invalid compression offset")
			}

			remainingDomain, _, err := NewDomainNameWithDecompression(
				originalMessage[offset:],
				originalMessage,
			)
			if err != nil {
				return nil, 0, err
			}

			// Combine current labels with pointed domain
			labels = append(labels, remainingDomain.labels...)
			return &DomainName{labels}, size, nil
		}

		// Regular label processing
		length := firstByte
		size += 1

		if length == NULL_BYTE {
			return &DomainName{labels}, size, nil
		}

		if len(data[1:]) < int(length) {
			return nil, 0, fmt.Errorf("not enough bytes in name's label")
		}

		labels = append(labels, Label{length, data[1 : length+1]})
		size += uint16(length)
		data = data[length+1:]
	}
}
