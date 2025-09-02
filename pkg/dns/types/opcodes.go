package types

// DNSOpcode represents a DNS operation code
type DNSOpcode uint16

// DNS Opcode constants
const (
	OPCODE_QUERY  DNSOpcode = 0 // Standard query
	OPCODE_IQUERY DNSOpcode = 1 // Inverse query (obsolete)
	OPCODE_STATUS DNSOpcode = 2 // Server status request
	OPCODE_NOTIFY DNSOpcode = 4 // Notify
	OPCODE_UPDATE DNSOpcode = 5 // Dynamic update
)

// String returns the string representation of a DNS opcode
func (o DNSOpcode) String() string {
	switch o {
	case OPCODE_QUERY:
		return "QUERY"
	case OPCODE_IQUERY:
		return "IQUERY"
	case OPCODE_STATUS:
		return "STATUS"
	case OPCODE_NOTIFY:
		return "NOTIFY"
	case OPCODE_UPDATE:
		return "UPDATE"
	default:
		return "UNKNOWN"
	}
}
