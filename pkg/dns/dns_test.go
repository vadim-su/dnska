package dns

import (
	"reflect"
	"testing"
)

func TestDomainNameCreation(t *testing.T) {
	cases := []struct {
		name       string
		domainName []byte
		expected   *DomainName
	}{
		{
			name:       "Simple top level domain",
			domainName: []byte("\x04test\x00"),
			expected: &DomainName{
				labels: []Label{
					{
						length:  4,
						content: []byte("test"),
					},
				},
			},
		},
		{
			name:       "Two level domain",
			domainName: []byte("\x04test\x03com\x00"),
			expected: &DomainName{
				labels: []Label{
					{
						length:  4,
						content: []byte("test"),
					},
					{
						length:  3,
						content: []byte("com"),
					},
				},
			},
		},
		{
			name:       "Simple top level domain",
			domainName: []byte("\x03dev\x04test\x03com\x00"),
			expected: &DomainName{
				labels: []Label{
					{
						length:  3,
						content: []byte("dev"),
					},
					{
						length:  4,
						content: []byte("test"),
					},
					{
						length:  3,
						content: []byte("com"),
					},
				},
			},
		},
		{
			name:       "Simple top level domain",
			domainName: []byte("\x03dev\x04test\x03com\x00"),
			expected: &DomainName{
				labels: []Label{
					{
						length:  3,
						content: []byte("dev"),
					},
					{
						length:  4,
						content: []byte("test"),
					},
					{
						length:  3,
						content: []byte("com"),
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, err := NewDomainName(c.domainName)
			if err != nil {
				t.Errorf("Error on creation: %v", err)
			}
			if !reflect.DeepEqual(got, c.expected) {
				t.Errorf("got %+v, want %+v", got, c.expected)
			}
		})
	}
}

func TestDNSQuestionCreation(t *testing.T) {
	cases := []struct {
		name       string
		domainName []byte
		expected   *DNSQuestion
	}{
		{
			name:       "Simple top level domain",
			domainName: []byte("\x04test\x00"),
			expected: &DNSQuestion{
				Name: DomainName{
					labels: []Label{
						{
							length:  4,
							content: []byte("test"),
						},
					},
				},
				Class: [2]byte{0x00, 0x01},
				Type:  [2]byte{0x00, 0x01},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, err := NewDomainName(c.domainName)
			if err != nil {
				t.Errorf("Error on creation: %v", err)
			}
			if !reflect.DeepEqual(got, c.expected) {
				t.Errorf("got %+v, want %+v", got, c.expected)
			}
		})
	}
}
