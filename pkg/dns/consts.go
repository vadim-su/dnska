package dns

// DNSType represents a DNS record type
type DNSType uint16

// DNS Type constants
const (
	TYPE_A     DNSType = 1  // a host address
	TYPE_NS    DNSType = 2  // an authoritative name server
	TYPE_MD    DNSType = 3  // a mail destination (Obsolete - use MX)
	TYPE_MF    DNSType = 4  // a mail forwarder (Obsolete - use MX)
	TYPE_CNAME DNSType = 5  // the canonical name for an alias
	TYPE_SOA   DNSType = 6  // marks the start of a zone of authority
	TYPE_MB    DNSType = 7  // a mailbox domain name (EXPERIMENTAL)
	TYPE_MG    DNSType = 8  // a mail group member (EXPERIMENTAL)
	TYPE_MR    DNSType = 9  // a mail rename domain name (EXPERIMENTAL)
	TYPE_NULL  DNSType = 10 // a null RR (EXPERIMENTAL)
	TYPE_WKS   DNSType = 11 // a well known service description
	TYPE_PTR   DNSType = 12 // a domain name pointer
	TYPE_HINFO DNSType = 13 // host information
	TYPE_MINFO DNSType = 14 // mailbox or mail list information
	TYPE_MX    DNSType = 15 // mail exchange
	TYPE_TXT   DNSType = 16 // text strings
	TYPE_AAAA  DNSType = 28 // IPv6 host address
)

// DNSClass represents a DNS class
type DNSClass uint16

// DNS Class constants
const (
	CLASS_IN DNSClass = 1 // Internet
	CLASS_CS DNSClass = 2 // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CLASS_CH DNSClass = 3 // the CHAOS class
	CLASS_HS DNSClass = 4 // Hesiod [Dyer 87]
)

// DNS Header flag constants
type DNSFlag uint16

// Bit positions for various flags
const (
	BIT_OPCODE_START = 11 // OPCODE starts at bit 11
	BIT_RCODE_START  = 0  // RCODE starts at bit 0
)

// DNS Flag constants
const (
	FLAG_QR_RESPONSE = DNSFlag(1 << 15) // Query/Response
	FLAG_QR_QUERY    = DNSFlag(0 << 15) // Query/Response

	FLAG_OPCODE_STANDARD = DNSFlag(0 << 11) // Standard query
	FLAG_OPCODE_INVERSE  = DNSFlag(1 << 11) // Inverse query
	FLAG_OPCODE_STATUS   = DNSFlag(2 << 11) // Server status request

	FLAG_AA_AUTHORITATIVE = DNSFlag(1 << 10) // Authoritative Answer
	FLAG_AA_NON_AUTH      = DNSFlag(0 << 10) // Non-authoritative

	FLAG_TC_TRUNCATED     = DNSFlag(1 << 9) // Truncated
	FLAG_TC_NOT_TRUNCATED = DNSFlag(0 << 9) // Not truncated

	FLAG_RD_RECURSION_DESIRED     = DNSFlag(1 << 8) // Recursion Desired
	FLAG_RD_RECURSION_NOT_DESIRED = DNSFlag(0 << 8) // Recursion Not Desired

	FLAG_RA_RECURSION_AVAILABLE     = DNSFlag(1 << 7) // Recursion Available
	FLAG_RA_RECURSION_NOT_AVAILABLE = DNSFlag(0 << 7) // Recursion Not Available

	FLAG_Z_RESERVED = DNSFlag(0 << 4) // Reserved (3 bits)

	FLAG_RCODE_NO_ERROR        = DNSFlag(0) // No error
	FLAG_RCODE_FORMAT_ERROR    = DNSFlag(1) // Format error
	FLAG_RCODE_SERVER_FAILURE  = DNSFlag(2) // Server failure
	FLAG_RCODE_NAME_ERROR      = DNSFlag(3) // Name error (domain doesn't exist)
	FLAG_RCODE_NOT_IMPLEMENTED = DNSFlag(4) // Not implemented
	FLAG_RCODE_REFUSED         = DNSFlag(5) // Refused
)

// Helper function to convert uint16-based types to [2]byte
func dnsTypeClassToBytes[T ~uint16](value T) [2]byte {
	return [2]byte{byte(value >> 8), byte(value & 0xFF)}
}
