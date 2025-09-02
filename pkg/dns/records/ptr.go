package records

import (
	"fmt"

	"github.com/vadim-su/dnska/pkg/dns/types"
)

// PTRRecord represents a PTR record (pointer record for reverse DNS)
type PTRRecord struct {
	BaseRecord
	target string // The domain name this IP address points to
}

// NewPTRRecord creates a new PTR record
func NewPTRRecord(name, target string, ttl uint32) *PTRRecord {
	return &PTRRecord{
		BaseRecord: NewBaseRecord(name, types.CLASS_IN, ttl),
		target:     target,
	}
}

// Type returns the DNS record type
func (r *PTRRecord) Type() types.DNSType {
	return types.TYPE_PTR
}

// Target returns the domain name this record points to
func (r *PTRRecord) Target() string {
	return r.target
}

// Data returns the target domain name as bytes
func (r *PTRRecord) Data() []byte {
	// This would need proper DNS name encoding
	// For now, return the string as bytes
	return []byte(r.target)
}

// String returns a string representation of the PTR record
func (r *PTRRecord) String() string {
	return fmt.Sprintf("%s %d IN PTR %s", r.name, r.ttl, r.target)
}
