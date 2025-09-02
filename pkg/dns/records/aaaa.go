package records

import (
	"fmt"
	"net"

	"github.com/vadim-su/dnska/pkg/dns/types"
)

// AAAARecord represents an AAAA record (IPv6 address)
type AAAARecord struct {
	BaseRecord
	ip net.IP
}

// NewAAAARecord creates a new AAAA record
func NewAAAARecord(name string, ip net.IP, ttl uint32) *AAAARecord {
	return &AAAARecord{
		BaseRecord: NewBaseRecord(name, types.CLASS_IN, ttl),
		ip:         ip.To16(),
	}
}

// NewAAAARecordFromString creates a new AAAA record from string IP
func NewAAAARecordFromString(name, ipStr string, ttl uint32) (*AAAARecord, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	if ip.To16() == nil {
		return nil, fmt.Errorf("not an IPv6 address: %s", ipStr)
	}
	return NewAAAARecord(name, ip, ttl), nil
}

// Type returns the DNS record type
func (r *AAAARecord) Type() types.DNSType {
	return types.TYPE_AAAA
}

// IP returns the IPv6 address
func (r *AAAARecord) IP() net.IP {
	return r.ip
}

// Data returns the raw IPv6 address bytes
func (r *AAAARecord) Data() []byte {
	return r.ip.To16()
}

// String returns a string representation of the AAAA record
func (r *AAAARecord) String() string {
	return fmt.Sprintf("%s %d IN AAAA %s", r.name, r.ttl, r.ip.String())
}
