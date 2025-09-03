package storage

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

const (
	// MaxDomainNameLength is the maximum length of a domain name (253 characters)
	MaxDomainNameLength = 253
	// MaxLabelLength is the maximum length of a single label (63 characters)
	MaxLabelLength = 63
	// DefaultMinTTL is the default minimum allowed TTL value
	DefaultMinTTL = uint32(0)
	// DefaultMaxTTL is the default maximum allowed TTL value (1 week)
	DefaultMaxTTL = uint32(604800)
)

// Validator validates DNS records and domain names
type Validator struct {
	enabled         bool
	allowUnderscore bool
	minTTL          uint32
	maxTTL          uint32
	allowedTypes    map[types.DNSType]bool
	labelRegex      *regexp.Regexp
}

// NewValidator creates a new Validator from configuration
func NewValidator(config *ValidationConfig) *Validator {
	if config == nil {
		config = &ValidationConfig{Enabled: true}
	}

	v := &Validator{
		enabled:         config.Enabled,
		allowUnderscore: config.AllowUnderscore,
		minTTL:          config.MinTTL,
		maxTTL:          config.MaxTTL,
	}

	// Set TTL defaults if not specified
	if v.minTTL == 0 && v.maxTTL == 0 {
		v.minTTL = DefaultMinTTL
		v.maxTTL = DefaultMaxTTL
	}

	// Build allowed types map
	if len(config.AllowedTypes) > 0 {
		v.allowedTypes = make(map[types.DNSType]bool)
		for _, typeStr := range config.AllowedTypes {
			// Parse common DNS type strings
			var dnsType types.DNSType
			switch strings.ToUpper(typeStr) {
			case "A":
				dnsType = types.TYPE_A
			case "AAAA":
				dnsType = types.TYPE_AAAA
			case "CNAME":
				dnsType = types.TYPE_CNAME
			case "MX":
				dnsType = types.TYPE_MX
			case "NS":
				dnsType = types.TYPE_NS
			case "PTR":
				dnsType = types.TYPE_PTR
			case "SOA":
				dnsType = types.TYPE_SOA
			case "TXT":
				dnsType = types.TYPE_TXT
			}
			if dnsType != 0 {
				v.allowedTypes[dnsType] = true
			}
		}
	}

	// Compile label regex
	pattern := `^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`
	if v.allowUnderscore {
		pattern = `^[a-zA-Z0-9_]([a-zA-Z0-9-_]*[a-zA-Z0-9_])?$`
	}
	v.labelRegex = regexp.MustCompile(pattern)

	return v
}

// ValidateRecord validates a DNS record
func (v *Validator) ValidateRecord(record records.DNSRecord) error {
	if !v.enabled {
		return nil
	}

	if record == nil {
		return fmt.Errorf("%w: nil record", ErrInvalidRecord)
	}

	// Check allowed types if configured
	if len(v.allowedTypes) > 0 && !v.allowedTypes[record.Type()] {
		return fmt.Errorf("%w: record type %s is not allowed", ErrInvalidRecord, record.Type())
	}

	// Validate name
	if err := v.ValidateName(record.Name()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}

	// Validate TTL
	if err := v.ValidateTTL(record.TTL()); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}

	// Validate record-specific data
	return v.validateRecordData(record)
}

// ValidateName validates a domain name
func (v *Validator) ValidateName(name string) error {
	if !v.enabled {
		return nil
	}

	if name == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidName)
	}

	// Remove trailing dot if present
	name = strings.TrimSuffix(name, ".")

	// Check total length
	if len(name) > MaxDomainNameLength {
		return fmt.Errorf("%w: exceeds maximum length of %d characters", ErrInvalidName, MaxDomainNameLength)
	}

	// Special case for root domain
	if name == "" || name == "." {
		return nil
	}

	// Split into labels and validate each
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if err := v.validateLabel(label); err != nil {
			return fmt.Errorf("%w: invalid label '%s': %v", ErrInvalidName, label, err)
		}
	}

	return nil
}

// ValidateZone validates a zone name
func (v *Validator) ValidateZone(zone string) error {
	if !v.enabled {
		return nil
	}

	if zone == "" {
		return fmt.Errorf("%w: empty zone", ErrInvalidZone)
	}

	// Zone names follow the same rules as domain names
	if err := v.ValidateName(zone); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidZone, err)
	}

	return nil
}

// ValidateTTL validates a TTL value
func (v *Validator) ValidateTTL(ttl uint32) error {
	if !v.enabled {
		return nil
	}

	if ttl < v.minTTL {
		return fmt.Errorf("%w: must be at least %d", ErrInvalidTTL, v.minTTL)
	}
	if ttl > v.maxTTL {
		return fmt.Errorf("%w: must not exceed %d", ErrInvalidTTL, v.maxTTL)
	}

	return nil
}

// validateLabel validates a single label in a domain name
func (v *Validator) validateLabel(label string) error {
	if len(label) == 0 {
		return fmt.Errorf("empty label")
	}
	if len(label) > MaxLabelLength {
		return fmt.Errorf("exceeds maximum length of %d characters", MaxLabelLength)
	}

	// Special handling for wildcard
	if label == "*" {
		return nil
	}

	// Special handling for underscore prefixed labels (used in SRV, DKIM, etc.)
	if strings.HasPrefix(label, "_") && v.allowUnderscore {
		return nil
	}

	// Check label format
	if !v.labelRegex.MatchString(label) {
		return fmt.Errorf("contains invalid characters")
	}

	return nil
}

// validateRecordData validates record-specific data
func (v *Validator) validateRecordData(record records.DNSRecord) error {
	switch r := record.(type) {
	case *records.CNAMERecord:
		return v.ValidateName(r.Target())

	case *records.MXRecord:
		if r.Preference() > 65535 {
			return fmt.Errorf("MX preference must be 0-65535")
		}
		return v.ValidateName(r.MailServer())

	case *records.NSRecord:
		return v.ValidateName(r.NameServer())

	case *records.PTRRecord:
		return v.ValidateName(r.Target())

	case *records.SOARecord:
		if err := v.ValidateName(r.PrimaryNS()); err != nil {
			return fmt.Errorf("invalid primary NS: %v", err)
		}
		// Validate email address format (responsible field)
		if !strings.Contains(r.Responsible(), ".") {
			return fmt.Errorf("invalid responsible field: must be in email format")
		}
		// Validate SOA timers
		if r.Serial() == 0 {
			return fmt.Errorf("SOA serial must be greater than 0")
		}
		return nil

	case *records.TXTRecord:
		// TXT records can contain any data, but check string lengths
		for i, text := range r.Texts() {
			if len(text) > 255 {
				return fmt.Errorf("TXT string %d exceeds 255 characters", i+1)
			}
		}
		return nil

	case *records.ARecord, *records.AAAARecord:
		// IP address validation is done by the record constructors
		return nil

	default:
		// Unknown record type - no specific validation
		return nil
	}
}

// ValidateBatch validates multiple records and returns all errors
func (v *Validator) ValidateBatch(records []records.DNSRecord) []error {
	if !v.enabled || len(records) == 0 {
		return nil
	}

	var errors []error
	for i, record := range records {
		if err := v.ValidateRecord(record); err != nil {
			errors = append(errors, fmt.Errorf("record %d: %w", i, err))
		}
	}
	return errors
}
