package records

import (
	"fmt"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/types"
)

// SOARecord represents an SOA record (Start of Authority)
type SOARecord struct {
	BaseRecord
	primaryNS   string        // Primary name server
	responsible string        // Responsible person (email)
	serial      uint32        // Zone serial number
	refresh     time.Duration // Refresh interval
	retry       time.Duration // Retry interval
	expire      time.Duration // Expire interval
	minimum     time.Duration // Minimum TTL
}

// NewSOARecord creates a new SOA record
func NewSOARecord(
	name, primaryNS, responsible string,
	serial uint32,
	refresh, retry, expire, minimum time.Duration,
	ttl uint32,
) *SOARecord {
	return &SOARecord{
		BaseRecord:  NewBaseRecord(name, types.CLASS_IN, ttl),
		primaryNS:   primaryNS,
		responsible: responsible,
		serial:      serial,
		refresh:     refresh,
		retry:       retry,
		expire:      expire,
		minimum:     minimum,
	}
}

// Type returns the DNS record type
func (r *SOARecord) Type() types.DNSType {
	return types.TYPE_SOA
}

// PrimaryNS returns the primary name server
func (r *SOARecord) PrimaryNS() string {
	return r.primaryNS
}

// Responsible returns the responsible person
func (r *SOARecord) Responsible() string {
	return r.responsible
}

// Serial returns the zone serial number
func (r *SOARecord) Serial() uint32 {
	return r.serial
}

// Refresh returns the refresh interval
func (r *SOARecord) Refresh() time.Duration {
	return r.refresh
}

// Retry returns the retry interval
func (r *SOARecord) Retry() time.Duration {
	return r.retry
}

// Expire returns the expire interval
func (r *SOARecord) Expire() time.Duration {
	return r.expire
}

// Minimum returns the minimum TTL
func (r *SOARecord) Minimum() time.Duration {
	return r.minimum
}

// Data returns the SOA data as bytes
func (r *SOARecord) Data() []byte {
	// Format: primaryNS + responsible + 5 uint32 values
	data := []byte{}

	// This would need proper DNS name encoding for primaryNS and responsible
	// For now, append strings as bytes
	data = append(data, []byte(r.primaryNS)...)
	data = append(data, []byte(r.responsible)...)

	// Serial number
	serialBytes := make([]byte, 4)
	serialBytes[0] = byte(r.serial >> 24)
	serialBytes[1] = byte(r.serial >> 16)
	serialBytes[2] = byte(r.serial >> 8)
	serialBytes[3] = byte(r.serial & 0xFF)
	data = append(data, serialBytes...)

	// Refresh interval
	refreshSec := uint32(r.refresh.Seconds())
	refreshBytes := make([]byte, 4)
	refreshBytes[0] = byte(refreshSec >> 24)
	refreshBytes[1] = byte(refreshSec >> 16)
	refreshBytes[2] = byte(refreshSec >> 8)
	refreshBytes[3] = byte(refreshSec & 0xFF)
	data = append(data, refreshBytes...)

	// Retry interval
	retrySec := uint32(r.retry.Seconds())
	retryBytes := make([]byte, 4)
	retryBytes[0] = byte(retrySec >> 24)
	retryBytes[1] = byte(retrySec >> 16)
	retryBytes[2] = byte(retrySec >> 8)
	retryBytes[3] = byte(retrySec & 0xFF)
	data = append(data, retryBytes...)

	// Expire interval
	expireSec := uint32(r.expire.Seconds())
	expireBytes := make([]byte, 4)
	expireBytes[0] = byte(expireSec >> 24)
	expireBytes[1] = byte(expireSec >> 16)
	expireBytes[2] = byte(expireSec >> 8)
	expireBytes[3] = byte(expireSec & 0xFF)
	data = append(data, expireBytes...)

	// Minimum TTL
	minSec := uint32(r.minimum.Seconds())
	minBytes := make([]byte, 4)
	minBytes[0] = byte(minSec >> 24)
	minBytes[1] = byte(minSec >> 16)
	minBytes[2] = byte(minSec >> 8)
	minBytes[3] = byte(minSec & 0xFF)
	data = append(data, minBytes...)

	return data
}

// String returns a string representation of the SOA record
func (r *SOARecord) String() string {
	return fmt.Sprintf("%s %d IN SOA %s %s %d %d %d %d %d",
		r.name, r.ttl, r.primaryNS, r.responsible, r.serial,
		int(r.refresh.Seconds()), int(r.retry.Seconds()),
		int(r.expire.Seconds()), int(r.minimum.Seconds()))
}
