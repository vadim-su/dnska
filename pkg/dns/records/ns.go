package records

import (
	"fmt"

	"github.com/vadim-su/dnska/pkg/dns/types"
)

// NSRecord represents an NS record (name server)
type NSRecord struct {
	BaseRecord
	nameServer string // Name server domain name
}

// NewNSRecord creates a new NS record
func NewNSRecord(name, nameServer string, ttl uint32) *NSRecord {
	return &NSRecord{
		BaseRecord: NewBaseRecord(name, types.CLASS_IN, ttl),
		nameServer: nameServer,
	}
}

// Type returns the DNS record type
func (r *NSRecord) Type() types.DNSType {
	return types.TYPE_NS
}

// NameServer returns the name server domain name
func (r *NSRecord) NameServer() string {
	return r.nameServer
}

// Data returns the name server domain name as bytes
func (r *NSRecord) Data() []byte {
	// This would need proper DNS name encoding
	// For now, return the string as bytes
	return []byte(r.nameServer)
}

// String returns a string representation of the NS record
func (r *NSRecord) String() string {
	return fmt.Sprintf("%s %d IN NS %s", r.name, r.ttl, r.nameServer)
}
