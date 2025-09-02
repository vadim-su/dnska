package types

// DNSRCode represents a DNS response code
type DNSRCode uint16

// DNS Response Code constants
const (
	RCODE_NO_ERROR        DNSRCode = 0 // No error
	RCODE_FORMAT_ERROR    DNSRCode = 1 // Format error
	RCODE_SERVER_FAILURE  DNSRCode = 2 // Server failure
	RCODE_NAME_ERROR      DNSRCode = 3 // Name error (domain doesn't exist)
	RCODE_NOT_IMPLEMENTED DNSRCode = 4 // Not implemented
	RCODE_REFUSED         DNSRCode = 5 // Refused
	RCODE_YXDOMAIN        DNSRCode = 6 // Name exists when it should not
	RCODE_YXRRSET         DNSRCode = 7 // RR set exists when it should not
	RCODE_NXRRSET         DNSRCode = 8 // RR set that should exist does not
	RCODE_NOT_AUTH        DNSRCode = 9 // Server not authoritative for zone
	RCODE_NOT_ZONE        DNSRCode = 10 // Name not contained in zone
)

// String returns the string representation of a DNS response code
func (r DNSRCode) String() string {
	switch r {
	case RCODE_NO_ERROR:
		return "NOERROR"
	case RCODE_FORMAT_ERROR:
		return "FORMERR"
	case RCODE_SERVER_FAILURE:
		return "SERVFAIL"
	case RCODE_NAME_ERROR:
		return "NXDOMAIN"
	case RCODE_NOT_IMPLEMENTED:
		return "NOTIMP"
	case RCODE_REFUSED:
		return "REFUSED"
	case RCODE_YXDOMAIN:
		return "YXDOMAIN"
	case RCODE_YXRRSET:
		return "YXRRSET"
	case RCODE_NXRRSET:
		return "NXRRSET"
	case RCODE_NOT_AUTH:
		return "NOTAUTH"
	case RCODE_NOT_ZONE:
		return "NOTZONE"
	default:
		return "UNKNOWN"
	}
}