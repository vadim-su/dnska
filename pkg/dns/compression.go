package dns

// CompressionMap is used to keep track of domain name offsets for DNS message compression.
type CompressionMap struct {
	nameToOffset map[string]uint16
	message      []byte
}

// NewCompressionMap creates a new CompressionMap instance.
func NewCompressionMap() *CompressionMap {
	return &CompressionMap{
		nameToOffset: make(map[string]uint16),
		message:      make([]byte, 0, 512),
	}
}

// AddDomainName adds a domain name to the compression map if it doesn't already exist.
const COMPRESSION_POINTER_MASK = 0xC000 // 11 followed by 14 bits

// AddDomainName adds a domain name to the compression map if it doesn't already exist.
func createCompressionPointer(offset uint16) []byte {
	pointer := COMPRESSION_POINTER_MASK | offset
	return []byte{byte(pointer >> 8), byte(pointer & 0xFF)}
}

// isCompressionPointer checks if the first byte indicates a compression pointer.
func isCompressionPointer(firstByte byte) bool {
	return (firstByte & 0xC0) == 0xC0
}

// extractCompressionOffset extracts the offset from a compression pointer.
func extractCompressionOffset(data []byte) uint16 {
	return uint16(data[0]&0x3F)<<8 | uint16(data[1])
}
