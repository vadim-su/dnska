package records

import (
	"fmt"
	"net"

	"github.com/vadim-su/dnska/pkg/dns/types"
)

// ARecord represents an A record (IPv4 address)
type ARecord struct {
	BaseRecord
	ip net.IP
}

// NewARecord creates a new A record
func NewARecord(name string, ip net.IP, ttl uint32) *ARecord {
	return &ARecord{
		BaseRecord: NewBaseRecord(name, types.CLASS_IN, ttl),
		ip:         ip.To4(),
	}
}

// NewARecordFromString creates a new A record from string IP
func NewARecordFromString(name, ipStr string, ttl uint32) (*ARecord, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	return NewARecord(name, ip, ttl), nil
}

// Type returns the DNS record type
func (r *ARecord) Type() types.DNSType {
	return types.TYPE_A
}

// IP returns the IPv4 address
func (r *ARecord) IP() net.IP {
	return r.ip
}

// Data returns the raw IPv4 address bytes
func (r *ARecord) Data() []byte {
	return r.ip.To4()
}

// String returns a string representation of the A record
func (r *ARecord) String() string {
	return fmt.Sprintf("%s %d IN A %s", r.name, r.ttl, r.ip.String())
}
