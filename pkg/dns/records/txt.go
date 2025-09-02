package records

import (
	"fmt"
	"strings"

	"github.com/vadim-su/dnska/pkg/dns/types"
)

// TXTRecord represents a TXT record (text strings)
type TXTRecord struct {
	BaseRecord
	texts []string // List of text strings
}

// NewTXTRecord creates a new TXT record
func NewTXTRecord(name string, texts []string, ttl uint32) *TXTRecord {
	return &TXTRecord{
		BaseRecord: NewBaseRecord(name, types.CLASS_IN, ttl),
		texts:      texts,
	}
}

// NewTXTRecordFromString creates a new TXT record from a single text string
func NewTXTRecordFromString(name, text string, ttl uint32) *TXTRecord {
	return NewTXTRecord(name, []string{text}, ttl)
}

// Type returns the DNS record type
func (r *TXTRecord) Type() types.DNSType {
	return types.TYPE_TXT
}

// Texts returns the list of text strings
func (r *TXTRecord) Texts() []string {
	return r.texts
}

// Data returns the text strings as bytes
func (r *TXTRecord) Data() []byte {
	var data []byte
	for _, text := range r.texts {
		// Each text string is prefixed with its length (1 byte)
		textBytes := []byte(text)
		data = append(data, byte(len(textBytes)))
		data = append(data, textBytes...)
	}
	return data
}

// String returns a string representation of the TXT record
func (r *TXTRecord) String() string {
	quotedTexts := make([]string, len(r.texts))
	for i, text := range r.texts {
		quotedTexts[i] = fmt.Sprintf("\"%s\"", text)
	}
	return fmt.Sprintf("%s %d IN TXT %s", r.name, r.ttl, strings.Join(quotedTexts, " "))
}
