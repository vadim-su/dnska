package records

import (
	"fmt"

	"github.com/vadim-su/dnska/pkg/dns/types"
)

// CNAMERecord represents a CNAME record (canonical name)
type CNAMERecord struct {
	BaseRecord
	target string // The canonical domain name
}

// NewCNAMERecord creates a new CNAME record
func NewCNAMERecord(name, target string, ttl uint32) *CNAMERecord {
	return &CNAMERecord{
		BaseRecord: NewBaseRecord(name, types.CLASS_IN, ttl),
		target:     target,
	}
}

// Type returns the DNS record type
func (r *CNAMERecord) Type() types.DNSType {
	return types.TYPE_CNAME
}

// Target returns the canonical domain name
func (r *CNAMERecord) Target() string {
	return r.target
}

// Data returns the target domain name as bytes
func (r *CNAMERecord) Data() []byte {
	// This would need proper DNS name encoding
	// For now, return the string as bytes
	return []byte(r.target)
}

// String returns a string representation of the CNAME record
func (r *CNAMERecord) String() string {
	return fmt.Sprintf("%s %d IN CNAME %s", r.name, r.ttl, r.target)
}
