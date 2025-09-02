package dns

type DNSHeader struct {
	ID                    uint16
	Flags                 DNSFlag // 2 bytes
	QuestionCount         uint16
	AnswerRecordCount     uint16
	AuthorityRecordCount  uint16
	AdditionalRecordCount uint16
}

func NewDNSHeader(
	id uint16,
	flags DNSFlag,
	questionCount,
	answerRecordCount,
	authorityRecordCount,
	additionalRecordCount uint16,
) *DNSHeader {
	return &DNSHeader{
		ID:                    id,
		Flags:                 flags,
		QuestionCount:         questionCount,
		AnswerRecordCount:     answerRecordCount,
		AuthorityRecordCount:  authorityRecordCount,
		AdditionalRecordCount: additionalRecordCount,
	}
}

// Convert DNSHeader to byte array
func (h *DNSHeader) ToBytes() []byte {
	var header = make([]byte, 12)
	header[0] = byte(h.ID >> 8)
	header[1] = byte(h.ID & 0xFF)
	header[2] = byte(h.Flags >> 8)
	header[3] = byte(h.Flags & 0xFF)
	header[4] = byte(h.QuestionCount >> 8)
	header[5] = byte(h.QuestionCount & 0xFF)
	header[6] = byte(h.AnswerRecordCount >> 8)
	header[7] = byte(h.AnswerRecordCount & 0xFF)
	header[8] = byte(h.AuthorityRecordCount >> 8)
	header[9] = byte(h.AuthorityRecordCount & 0xFF)
	header[10] = byte(h.AdditionalRecordCount >> 8)
	header[11] = byte(h.AdditionalRecordCount & 0xFF)

	return header
}
