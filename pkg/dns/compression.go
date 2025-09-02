package dns

type CompressionMap struct {
	nameToOffset map[string]uint16
	message      []byte
}

func NewCompressionMap() *CompressionMap {
	return &CompressionMap{
		nameToOffset: make(map[string]uint16),
		message:      make([]byte, 0, 512),
	}
}

const COMPRESSION_POINTER_MASK = 0xC000 // 11 followed by 14 bits

func createCompressionPointer(offset uint16) []byte {
	pointer := COMPRESSION_POINTER_MASK | offset
	return []byte{byte(pointer >> 8), byte(pointer & 0xFF)}
}

func isCompressionPointer(firstByte byte) bool {
	return (firstByte & 0xC0) == 0xC0
}

func extractCompressionOffset(data []byte) uint16 {
	return uint16(data[0]&0x3F)<<8 | uint16(data[1])
}
