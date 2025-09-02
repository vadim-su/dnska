package utils

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
func CreateCompressionPointer(offset uint16) []byte {
	pointer := COMPRESSION_POINTER_MASK | offset
	return []byte{byte(pointer >> 8), byte(pointer & 0xFF)}
}

// isCompressionPointer checks if the first byte indicates a compression pointer.
func IsCompressionPointer(firstByte byte) bool {
	return (firstByte & 0xC0) == 0xC0
}

// extractCompressionOffset extracts the offset from a compression pointer.
func ExtractCompressionOffset(data []byte) uint16 {
	return uint16(data[0]&0x3F)<<8 | uint16(data[1])
}

// GetNameToOffset returns a copy of the nameToOffset map for testing
func (cm *CompressionMap) GetNameToOffset() map[string]uint16 {
	result := make(map[string]uint16)
	for k, v := range cm.nameToOffset {
		result[k] = v
	}
	return result
}

// SetNameOffset sets a name to offset mapping
func (cm *CompressionMap) SetNameOffset(name string, offset uint16) {
	cm.nameToOffset[name] = offset
}

// GetMessage returns a copy of the current message bytes
func (cm *CompressionMap) GetMessage() []byte {
	result := make([]byte, len(cm.message))
	copy(result, cm.message)
	return result
}

// SetMessage sets the message bytes
func (cm *CompressionMap) SetMessage(message []byte) {
	cm.message = make([]byte, len(message))
	copy(cm.message, message)
}
