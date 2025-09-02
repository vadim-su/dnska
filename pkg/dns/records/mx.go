package records

import (
	"fmt"

	"github.com/vadim-su/dnska/pkg/dns/types"
)

// MXRecord represents an MX record (mail exchange)
type MXRecord struct {
	BaseRecord
	preference uint16    // Mail server preference (lower is higher priority)
	mailServer string   // Mail server domain name
}

// NewMXRecord creates a new MX record
func NewMXRecord(name, mailServer string, preference uint16, ttl uint32) *MXRecord {
	return &MXRecord{
		BaseRecord: NewBaseRecord(name, types.CLASS_IN, ttl),
		preference: preference,
		mailServer: mailServer,
	}
}

// Type returns the DNS record type
func (r *MXRecord) Type() types.DNSType {
	return types.TYPE_MX
}

// Preference returns the mail server preference
func (r *MXRecord) Preference() uint16 {
	return r.preference
}

// MailServer returns the mail server domain name
func (r *MXRecord) MailServer() string {
	return r.mailServer
}

// Data returns the preference and mail server as bytes
func (r *MXRecord) Data() []byte {
	// Format: 2 bytes preference + domain name bytes
	data := make([]byte, 2)
	data[0] = byte(r.preference >> 8)
	data[1] = byte(r.preference & 0xFF)

	// This would need proper DNS name encoding for the mail server
	// For now, append the string as bytes
	data = append(data, []byte(r.mailServer)...)
	return data
}

// String returns a string representation of the MX record
func (r *MXRecord) String() string {
	return fmt.Sprintf("%s %d IN MX %d %s", r.name, r.ttl, r.preference, r.mailServer)
}
