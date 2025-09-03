package storage

import (
	"fmt"
	"strings"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// RecordConverter handles conversion between DNS records and storage formats
type RecordConverter struct{}

// NewRecordConverter creates a new RecordConverter
func NewRecordConverter() *RecordConverter {
	return &RecordConverter{}
}

// RecordData represents a DNS record in a generic storage format
type RecordData struct {
	ID         string    `json:"id,omitempty"`
	Name       string    `json:"name"`
	RecordType int       `json:"record_type"`
	Class      int       `json:"class"`
	TTL        uint32    `json:"ttl"`
	Data       string    `json:"data"`
	Zone       string    `json:"zone"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

// ToStorageFormat converts a DNS record to storage format
func (c *RecordConverter) ToStorageFormat(record records.DNSRecord) (*RecordData, error) {
	if record == nil {
		return nil, ErrInvalidRecord
	}

	data := &RecordData{
		Name:       strings.ToLower(record.Name()),
		RecordType: int(record.Type()),
		Class:      int(record.Class()),
		TTL:        record.TTL(),
		Zone:       c.extractZone(record.Name()),
		Data:       c.formatRecordData(record),
	}

	return data, nil
}

// FromStorageFormat converts storage format to a DNS record
func (c *RecordConverter) FromStorageFormat(data *RecordData) (records.DNSRecord, error) {
	if data == nil {
		return nil, ErrInvalidRecord
	}

	recordType := types.DNSType(data.RecordType)

	switch recordType {
	case types.TYPE_A:
		return records.NewARecordFromString(data.Name, data.Data, data.TTL)

	case types.TYPE_AAAA:
		return records.NewAAAARecordFromString(data.Name, data.Data, data.TTL)

	case types.TYPE_CNAME:
		return records.NewCNAMERecord(data.Name, data.Data, data.TTL), nil

	case types.TYPE_MX:
		return c.parseMXRecord(data.Name, data.Data, data.TTL)

	case types.TYPE_NS:
		return records.NewNSRecord(data.Name, data.Data, data.TTL), nil

	case types.TYPE_PTR:
		return records.NewPTRRecord(data.Name, data.Data, data.TTL), nil

	case types.TYPE_SOA:
		return c.parseSOARecord(data.Name, data.Data, data.TTL)

	case types.TYPE_TXT:
		return records.NewTXTRecordFromString(data.Name, data.Data, data.TTL), nil

	default:
		return nil, fmt.Errorf("%w: unsupported record type %s", ErrInvalidRecord, recordType)
	}
}

// BatchToStorageFormat converts multiple DNS records to storage format
func (c *RecordConverter) BatchToStorageFormat(records []records.DNSRecord) ([]*RecordData, error) {
	result := make([]*RecordData, len(records))
	for i, record := range records {
		data, err := c.ToStorageFormat(record)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		result[i] = data
	}
	return result, nil
}

// BatchFromStorageFormat converts multiple storage records to DNS records
func (c *RecordConverter) BatchFromStorageFormat(data []*RecordData) ([]records.DNSRecord, error) {
	result := make([]records.DNSRecord, len(data))
	for i, d := range data {
		record, err := c.FromStorageFormat(d)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		result[i] = record
	}
	return result, nil
}

// formatRecordData formats record data for storage based on record type
func (c *RecordConverter) formatRecordData(record records.DNSRecord) string {
	switch r := record.(type) {
	case *records.ARecord:
		return r.IP().String()

	case *records.AAAARecord:
		return r.IP().String()

	case *records.CNAMERecord:
		return r.Target()

	case *records.MXRecord:
		return fmt.Sprintf("%d %s", r.Preference(), r.MailServer())

	case *records.NSRecord:
		return r.NameServer()

	case *records.PTRRecord:
		return r.Target()

	case *records.SOARecord:
		return fmt.Sprintf("%s %s %d %d %d %d %d",
			r.PrimaryNS(), r.Responsible(), r.Serial(),
			int(r.Refresh().Seconds()), int(r.Retry().Seconds()),
			int(r.Expire().Seconds()), int(r.Minimum().Seconds()))

	case *records.TXTRecord:
		texts := r.Texts()
		if len(texts) > 0 {
			// Join multiple text strings with a separator
			return strings.Join(texts, "\x00")
		}
		return ""

	default:
		// Fallback to raw data conversion
		return string(record.Data())
	}
}

// parseMXRecord parses MX record data in format "priority mailserver"
func (c *RecordConverter) parseMXRecord(name, data string, ttl uint32) (records.DNSRecord, error) {
	parts := strings.Fields(data)
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: invalid MX record format", ErrInvalidRecord)
	}

	var priority uint16
	if _, err := fmt.Sscanf(parts[0], "%d", &priority); err != nil {
		return nil, fmt.Errorf("%w: invalid MX priority: %v", ErrInvalidRecord, err)
	}

	return records.NewMXRecord(name, parts[1], priority, ttl), nil
}

// parseSOARecord parses SOA record data
func (c *RecordConverter) parseSOARecord(name, data string, ttl uint32) (records.DNSRecord, error) {
	// SOA format: "primaryNS responsible serial refresh retry expire minimum"
	parts := strings.Fields(data)
	if len(parts) != 7 {
		return nil, fmt.Errorf("%w: invalid SOA record format", ErrInvalidRecord)
	}

	var serial, refresh, retry, expire, minimum uint32

	if _, err := fmt.Sscanf(parts[2], "%d", &serial); err != nil {
		return nil, fmt.Errorf("%w: invalid SOA serial: %v", ErrInvalidRecord, err)
	}
	if _, err := fmt.Sscanf(parts[3], "%d", &refresh); err != nil {
		return nil, fmt.Errorf("%w: invalid SOA refresh: %v", ErrInvalidRecord, err)
	}
	if _, err := fmt.Sscanf(parts[4], "%d", &retry); err != nil {
		return nil, fmt.Errorf("%w: invalid SOA retry: %v", ErrInvalidRecord, err)
	}
	if _, err := fmt.Sscanf(parts[5], "%d", &expire); err != nil {
		return nil, fmt.Errorf("%w: invalid SOA expire: %v", ErrInvalidRecord, err)
	}
	if _, err := fmt.Sscanf(parts[6], "%d", &minimum); err != nil {
		return nil, fmt.Errorf("%w: invalid SOA minimum: %v", ErrInvalidRecord, err)
	}

	return records.NewSOARecord(
		name, parts[0], parts[1], serial,
		time.Duration(refresh)*time.Second,
		time.Duration(retry)*time.Second,
		time.Duration(expire)*time.Second,
		time.Duration(minimum)*time.Second,
		ttl,
	), nil
}

// extractZone extracts the zone name from a domain name
func (c *RecordConverter) extractZone(name string) string {
	// Remove trailing dot if present
	name = strings.TrimSuffix(name, ".")

	// For simplicity, assume the zone is the last two labels
	// In production, this should be more sophisticated
	parts := strings.Split(name, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return name
}

// ExtractZones extracts unique zones from a list of domain names
func ExtractZones(names []string) []string {
	zoneMap := make(map[string]bool)
	c := &RecordConverter{}

	for _, name := range names {
		zone := c.extractZone(name)
		if zone != "" {
			zoneMap[zone] = true
		}
	}

	zones := make([]string, 0, len(zoneMap))
	for zone := range zoneMap {
		zones = append(zones, zone)
	}

	return zones
}
