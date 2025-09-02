package records

import (
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// DNSRecord represents a generic DNS resource record
type DNSRecord interface {
	// Type returns the DNS record type
	Type() types.DNSType
	// Class returns the DNS record class
	Class() types.DNSClass
	// Name returns the domain name for this record
	Name() string
	// TTL returns the time-to-live for this record
	TTL() uint32
	// Data returns the raw data for this record
	Data() []byte
	// String returns a string representation of the record
	String() string
}

// BaseRecord provides common fields and methods for all DNS records
type BaseRecord struct {
	name  string
	class types.DNSClass
	ttl   uint32
}

// NewBaseRecord creates a new base record with common fields
func NewBaseRecord(name string, class types.DNSClass, ttl uint32) BaseRecord {
	return BaseRecord{
		name:  name,
		class: class,
		ttl:   ttl,
	}
}

// Name returns the domain name
func (r BaseRecord) Name() string {
	return r.name
}

// Class returns the DNS class
func (r BaseRecord) Class() types.DNSClass {
	return r.class
}

// TTL returns the time-to-live
func (r BaseRecord) TTL() uint32 {
	return r.ttl
}

// SetTTL updates the TTL value
func (r *BaseRecord) SetTTL(ttl uint32) {
	r.ttl = ttl
}
