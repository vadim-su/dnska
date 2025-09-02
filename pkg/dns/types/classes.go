package types

// DNSClass represents a DNS class
type DNSClass uint16

// DNS Class constants
const (
	CLASS_IN DNSClass = 1 // Internet
	CLASS_CS DNSClass = 2 // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CLASS_CH DNSClass = 3 // the CHAOS class
	CLASS_HS DNSClass = 4 // Hesiod [Dyer 87]
)

// String returns the string representation of a DNS class
func (c DNSClass) String() string {
	switch c {
	case CLASS_IN:
		return "IN"
	case CLASS_CS:
		return "CS"
	case CLASS_CH:
		return "CH"
	case CLASS_HS:
		return "HS"
	default:
		return "UNKNOWN"
	}
}
