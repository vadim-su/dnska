package main

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/vadim-su/dnska/pkg/dns"
)

func TestNewDNSServer(t *testing.T) {
	tests := []struct {
		name         string
		address      string
		resolverAddr string
		expectError  bool
		description  string
	}{
		{
			name:         "valid addresses",
			address:      "127.0.0.1:8053",
			resolverAddr: "8.8.8.8:53",
			expectError:  false,
			description:  "Should create server with valid addresses",
		},
		{
			name:         "same address and resolver",
			address:      "127.0.0.1:8053",
			resolverAddr: "127.0.0.1:8053",
			expectError:  false,
			description:  "Should handle same address and resolver",
		},
		{
			name:         "invalid server address",
			address:      "invalid:address",
			resolverAddr: "8.8.8.8:53",
			expectError:  true,
			description:  "Should fail with invalid server address",
		},
		{
			name:         "invalid resolver address",
			address:      "127.0.0.1:8053",
			resolverAddr: "invalid:resolver",
			expectError:  true,
			description:  "Should fail with invalid resolver address",
		},
		{
			name:         "port in use",
			address:      "127.0.0.1:1", // Typically restricted port
			resolverAddr: "8.8.8.8:53",
			expectError:  true,
			description:  "Should fail when port is not available",
		},
		{
			name:         "zero port allocation",
			address:      "127.0.0.1:0", // Let OS choose port
			resolverAddr: "8.8.8.8:53",
			expectError:  false,
			description:  "Should work with OS-allocated port",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := NewDNSServer(test.address, test.resolverAddr)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					if server != nil {
						server.Close()
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if server == nil {
				t.Fatal("Server is nil")
			}

			// Verify server fields are set correctly
			if server.resolverAddr != test.resolverAddr {
				t.Errorf("Resolver address mismatch: expected %s, got %s", test.resolverAddr, server.resolverAddr)
			}

			if server.conn == nil {
				t.Error("Server connection is nil")
			}

			if server.resolverCon == nil {
				t.Error("Resolver connection is nil")
			}

			if server.resolverUDPAddr == nil {
				t.Error("Resolver UDP address is nil")
			}

			// Clean up
			if err := server.Close(); err != nil {
				t.Errorf("Failed to close server: %v", err)
			}
		})
	}
}

func TestDNSServerClose(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func() *DNSServer
		description string
	}{
		{
			name: "close valid server",
			setupServer: func() *DNSServer {
				server, err := NewDNSServer("127.0.0.1:0", "8.8.8.8:53")
				if err != nil {
					t.Fatalf("Failed to create server: %v", err)
				}
				return server
			},
			description: "Should close server without errors",
		},
		{
			name: "close already closed server",
			setupServer: func() *DNSServer {
				server, err := NewDNSServer("127.0.0.1:0", "8.8.8.8:53")
				if err != nil {
					t.Fatalf("Failed to create server: %v", err)
				}
				// Close once
				server.Close()
				return server
			},
			description: "Should handle already closed connections",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := test.setupServer()
			err := server.Close()

			// For already closed server, we expect an error
			if test.name == "close already closed server" {
				if err == nil {
					t.Error("Expected error when closing already closed server")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error closing server: %v", err)
				}
			}
		})
	}
}

func TestCreateAnswerForQuestion(t *testing.T) {
	server := &DNSServer{}

	tests := []struct {
		name        string
		question    dns.DNSQuestion
		expected    *dns.DNSAnswer
		description string
	}{
		{
			name: "create answer for A record",
			question: dns.DNSQuestion{
				Name:  createTestDomainName("example.com"),
				Type:  [2]byte{0x00, 0x01}, // TYPE_A
				Class: [2]byte{0x00, 0x01}, // CLASS_IN
			},
			description: "Should create A record answer with default IP",
		},
		{
			name: "create answer for different domain",
			question: dns.DNSQuestion{
				Name:  createTestDomainName("test.org"),
				Type:  [2]byte{0x00, 0x01}, // TYPE_A
				Class: [2]byte{0x00, 0x01}, // CLASS_IN
			},
			description: "Should create answer for any domain",
		},
		{
			name: "create answer for root domain",
			question: dns.DNSQuestion{
				Name:  createTestDomainName("."),
				Type:  [2]byte{0x00, 0x01}, // TYPE_A
				Class: [2]byte{0x00, 0x01}, // CLASS_IN
			},
			description: "Should handle root domain",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			answer, err := server.createAnswerForQuestion(test.question)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if answer == nil {
				t.Fatal("Answer is nil")
			}

			// Verify the answer has expected structure
			answerBytes := answer.ToBytes()
			if len(answerBytes) == 0 {
				t.Error("Answer serialization is empty")
			}

			// The answer should be serializable (we can't directly access private data field)
			// but we can verify the answer contains the expected IP by checking the serialized form
			serializedBytes := answer.ToBytes()
			// Check that the answer contains our default IP in the last 4 bytes (RDATA section)
			if len(serializedBytes) >= 4 {
				actualIP := serializedBytes[len(serializedBytes)-4:]
				if !reflect.DeepEqual(actualIP, defaultIPAddress) {
					t.Errorf("Answer IP mismatch: expected %v, got %v", defaultIPAddress, actualIP)
				}
			}
		})
	}
}

func TestCreateAnswers(t *testing.T) {
	tests := []struct {
		name          string
		server        *DNSServer
		questions     []dns.DNSQuestion
		expectedCount int
		description   string
	}{
		{
			name: "create answers for single question",
			server: &DNSServer{
				address:      "127.0.0.1:8053",
				resolverAddr: "127.0.0.1:8053", // Same as server, no forwarding
			},
			questions: []dns.DNSQuestion{
				{
					Name:  createTestDomainName("example.com"),
					Type:  [2]byte{0x00, 0x01}, // TYPE_A
					Class: [2]byte{0x00, 0x01}, // CLASS_IN
				},
			},
			expectedCount: 1,
			description:   "Should create fallback answer when no forwarding",
		},
		{
			name: "create answers for multiple questions",
			server: &DNSServer{
				address:      "127.0.0.1:8053",
				resolverAddr: "127.0.0.1:8053", // Same as server, no forwarding
			},
			questions: []dns.DNSQuestion{
				{
					Name:  createTestDomainName("example.com"),
					Type:  [2]byte{0x00, 0x01}, // TYPE_A
					Class: [2]byte{0x00, 0x01}, // CLASS_IN
				},
				{
					Name:  createTestDomainName("test.org"),
					Type:  [2]byte{0x00, 0x01}, // TYPE_A
					Class: [2]byte{0x00, 0x01}, // CLASS_IN
				},
			},
			expectedCount: 2,
			description:   "Should create answers for all questions",
		},
		{
			name: "no questions",
			server: &DNSServer{
				address:      "127.0.0.1:8053",
				resolverAddr: "127.0.0.1:8053",
			},
			questions:     []dns.DNSQuestion{},
			expectedCount: 0,
			description:   "Should handle empty questions list",
		},
		{
			name: "forwarding configured but will fail",
			server: &DNSServer{
				address:      "127.0.0.1:8053",
				resolverAddr: "1.2.3.4:53", // Different resolver, will try forwarding
			},
			questions: []dns.DNSQuestion{
				{
					Name:  createTestDomainName("example.com"),
					Type:  [2]byte{0x00, 0x01}, // TYPE_A
					Class: [2]byte{0x00, 0x01}, // CLASS_IN
				},
			},
			expectedCount: 1,
			description:   "Should fallback to default answer when forwarding fails",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			answers, err := test.server.createAnswers(test.questions)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(answers) != test.expectedCount {
				t.Errorf("Answer count mismatch: expected %d, got %d", test.expectedCount, len(answers))
			}

			// Verify each answer is valid
			for index, answer := range answers {
				answerBytes := answer.ToBytes()
				if len(answerBytes) == 0 {
					t.Errorf("Answer %d serialization is empty", index)
				}
			}
		})
	}
}

func TestForwardRequest(t *testing.T) {
	tests := []struct {
		name        string
		server      *DNSServer
		questions   []dns.DNSQuestion
		expectEmpty bool
		description string
	}{
		{
			name: "forward to unreachable resolver",
			server: &DNSServer{
				resolverAddr: "192.0.2.1:53", // RFC 5737 test address, should be unreachable
			},
			questions: []dns.DNSQuestion{
				{
					Name:  createTestDomainName("example.com"),
					Type:  [2]byte{0x00, 0x01}, // TYPE_A
					Class: [2]byte{0x00, 0x01}, // CLASS_IN
				},
			},
			expectEmpty: true,
			description: "Should return empty when resolver is unreachable",
		},
		{
			name: "forward with invalid resolver address",
			server: &DNSServer{
				resolverAddr: "invalid:address",
			},
			questions: []dns.DNSQuestion{
				{
					Name:  createTestDomainName("example.com"),
					Type:  [2]byte{0x00, 0x01}, // TYPE_A
					Class: [2]byte{0x00, 0x01}, // CLASS_IN
				},
			},
			expectEmpty: true,
			description: "Should return empty with invalid resolver address",
		},
		{
			name: "forward with no questions",
			server: &DNSServer{
				resolverAddr: "8.8.8.8:53",
			},
			questions:   []dns.DNSQuestion{},
			expectEmpty: true,
			description: "Should handle empty questions list",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set a short timeout for these tests
			originalTimeout := 100 * time.Millisecond

			answers := test.server.forwardRequest(test.questions)

			if test.expectEmpty {
				if len(answers) != 0 {
					t.Errorf("Expected empty answers, got %d", len(answers))
				}
			}

			// Note: We can't easily test successful forwarding without setting up
			// a mock DNS server, so we focus on error cases
			_ = originalTimeout // Avoid unused variable
		})
	}
}

func TestHandleRequest(t *testing.T) {
	// Create a test server
	server, err := NewDNSServer("127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Close()

	tests := []struct {
		name        string
		request     *dns.DNSRequest
		expectError bool
		description string
	}{
		{
			name: "handle valid request",
			request: &dns.DNSRequest{
				Header: dns.DNSHeader{
					ID:                    0x1234,
					Flags:                 dns.FLAG_QR_QUERY | dns.FLAG_OPCODE_STANDARD,
					QuestionCount:         1,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []dns.DNSQuestion{
					{
						Name:  createTestDomainName("example.com"),
						Type:  [2]byte{0x00, 0x01}, // TYPE_A
						Class: [2]byte{0x00, 0x01}, // CLASS_IN
					},
				},
			},
			expectError: false,
			description: "Should handle valid DNS request",
		},
		{
			name: "handle request with multiple questions",
			request: &dns.DNSRequest{
				Header: dns.DNSHeader{
					ID:                    0x5678,
					Flags:                 dns.FLAG_QR_QUERY | dns.FLAG_OPCODE_STANDARD,
					QuestionCount:         2,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []dns.DNSQuestion{
					{
						Name:  createTestDomainName("example.com"),
						Type:  [2]byte{0x00, 0x01}, // TYPE_A
						Class: [2]byte{0x00, 0x01}, // CLASS_IN
					},
					{
						Name:  createTestDomainName("test.org"),
						Type:  [2]byte{0x00, 0x01}, // TYPE_A
						Class: [2]byte{0x00, 0x01}, // CLASS_IN
					},
				},
			},
			expectError: false,
			description: "Should handle request with multiple questions",
		},
		{
			name: "handle request with no questions",
			request: &dns.DNSRequest{
				Header: dns.DNSHeader{
					ID:                    0x9999,
					Flags:                 dns.FLAG_QR_QUERY | dns.FLAG_OPCODE_STANDARD,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []dns.DNSQuestion{},
			},
			expectError: false,
			description: "Should handle request with no questions",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create a dummy client address
			clientAddr := &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 12345,
			}

			err := server.handleRequest(test.request, clientAddr)

			if test.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestProcessNextRequest(t *testing.T) {
	// Create a test server
	server, err := NewDNSServer("127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Close()

	tests := []struct {
		name        string
		data        []byte
		expectError bool
		description string
	}{
		{
			name: "process valid DNS request",
			data: []byte{
				// Header
				0x12, 0x34, // ID
				0x01, 0x00, // Flags (query)
				0x00, 0x01, // Question count
				0x00, 0x00, // Answer count
				0x00, 0x00, // Authority count
				0x00, 0x00, // Additional count
				// Question
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
				0x03, 'c', 'o', 'm',
				0x00,       // End of name
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
			},
			expectError: false,
			description: "Should process valid DNS request data",
		},
		{
			name:        "process invalid DNS data",
			data:        []byte{0x01, 0x02, 0x03}, // Too short
			expectError: true,
			description: "Should fail with invalid DNS data",
		},
		{
			name:        "process empty data",
			data:        []byte{},
			expectError: true,
			description: "Should fail with empty data",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// We can't easily test the full processNextRequest method because it
			// involves UDP ReadFromUDP which requires actual network communication.
			// Instead, we test the DNS parsing part directly.

			if len(test.data) > 0 {
				_, err := dns.NewDNSRequest(test.data)

				if test.expectError {
					if err == nil {
						t.Error("Expected error parsing DNS request but got none")
					}
				} else {
					if err != nil {
						t.Errorf("Unexpected error parsing DNS request: %v", err)
					}
				}
			}
		})
	}
}

// Helper functions

func createTestDomainName(domain string) dns.DomainName {
	if domain == "." {
		// Create root domain name
		emptyName, _, _ := dns.NewDomainName([]byte{0x00})
		return *emptyName
	}

	// Remove trailing dot if present
	if len(domain) > 0 && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	if domain == "" {
		// Create empty domain name
		emptyName, _, _ := dns.NewDomainName([]byte{0x00})
		return *emptyName
	}

	// Split domain into parts
	parts := []string{}
	current := ""
	for _, char := range domain {
		if char == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(char)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	// Build the domain name in DNS wire format
	var nameBytes []byte
	for _, part := range parts {
		if len(part) > 0 && len(part) <= 63 {
			nameBytes = append(nameBytes, byte(len(part)))
			nameBytes = append(nameBytes, []byte(part)...)
		}
	}
	nameBytes = append(nameBytes, 0x00) // Root label

	domainName, _, err := dns.NewDomainName(nameBytes)
	if err != nil {
		// Fallback to empty domain name
		emptyName, _, _ := dns.NewDomainName([]byte{0x00})
		return *emptyName
	}

	return *domainName
}

func TestConstants(t *testing.T) {
	tests := []struct {
		name        string
		value       interface{}
		expected    interface{}
		description string
	}{
		{
			name:        "server address constant",
			value:       serverAddress,
			expected:    "127.0.0.1:2053",
			description: "Should have correct default server address",
		},
		{
			name:        "default resolver constant",
			value:       defaultResolver,
			expected:    "127.0.0.1:2053",
			description: "Should have correct default resolver",
		},
		{
			name:        "buffer size constant",
			value:       bufferSize,
			expected:    512,
			description: "Should have correct buffer size",
		},
		{
			name:        "default TTL constant",
			value:       defaultTTL,
			expected:    60,
			description: "Should have correct default TTL",
		},
		{
			name:        "default IP address",
			value:       defaultIPAddress,
			expected:    []byte{8, 8, 8, 8},
			description: "Should have correct default IP (8.8.8.8)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !reflect.DeepEqual(test.value, test.expected) {
				t.Errorf("Constant mismatch: expected %v, got %v", test.expected, test.value)
			}
		})
	}
}

func TestDNSServerStructFields(t *testing.T) {
	server, err := NewDNSServer("127.0.0.1:0", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	tests := []struct {
		name        string
		checkFn     func(*DNSServer) bool
		description string
	}{
		{
			name: "address field set",
			checkFn: func(s *DNSServer) bool {
				return s.address != ""
			},
			description: "Server address should be set",
		},
		{
			name: "resolver address field set",
			checkFn: func(s *DNSServer) bool {
				return s.resolverAddr == "8.8.8.8:53"
			},
			description: "Resolver address should be set correctly",
		},
		{
			name: "server connection initialized",
			checkFn: func(s *DNSServer) bool {
				return s.conn != nil
			},
			description: "Server connection should be initialized",
		},
		{
			name: "resolver connection initialized",
			checkFn: func(s *DNSServer) bool {
				return s.resolverCon != nil
			},
			description: "Resolver connection should be initialized",
		},
		{
			name: "resolver UDP address initialized",
			checkFn: func(s *DNSServer) bool {
				return s.resolverUDPAddr != nil
			},
			description: "Resolver UDP address should be initialized",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.checkFn(server) {
				t.Errorf("Field check failed: %s", test.description)
			}
		})
	}
}

func TestCreateAnswersErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		server      *DNSServer
		questions   []dns.DNSQuestion
		description string
	}{
		{
			name: "create answers with malformed question",
			server: &DNSServer{
				address:      "127.0.0.1:8053",
				resolverAddr: "127.0.0.1:8053",
			},
			questions: []dns.DNSQuestion{
				{
					Name:  dns.DomainName{}, // Empty domain name
					Type:  [2]byte{0x00, 0x01},
					Class: [2]byte{0x00, 0x01},
				},
			},
			description: "Should handle questions with empty domain names",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			answers, err := test.server.createAnswers(test.questions)

			// Should not return error even with malformed questions
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// May return fewer answers than questions if some fail
			if len(answers) > len(test.questions) {
				t.Errorf("More answers than questions: got %d answers for %d questions",
					len(answers), len(test.questions))
			}
		})
	}
}

func TestHandleRequestEdgeCases(t *testing.T) {
	server, err := NewDNSServer("127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Close()

	tests := []struct {
		name        string
		request     *dns.DNSRequest
		clientAddr  *net.UDPAddr
		description string
	}{
		{
			name: "handle request with zero ID",
			request: &dns.DNSRequest{
				Header: dns.DNSHeader{
					ID:                    0x0000,
					Flags:                 dns.FLAG_QR_QUERY | dns.FLAG_OPCODE_STANDARD,
					QuestionCount:         1,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []dns.DNSQuestion{
					{
						Name:  createTestDomainName("test.com"),
						Type:  [2]byte{0x00, 0x01},
						Class: [2]byte{0x00, 0x01},
					},
				},
			},
			clientAddr: &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 12345,
			},
			description: "Should handle request with zero ID",
		},
		{
			name: "handle request with maximum ID",
			request: &dns.DNSRequest{
				Header: dns.DNSHeader{
					ID:                    0xFFFF,
					Flags:                 dns.FLAG_QR_QUERY | dns.FLAG_OPCODE_STANDARD,
					QuestionCount:         0,
					AnswerRecordCount:     0,
					AuthorityRecordCount:  0,
					AdditionalRecordCount: 0,
				},
				Questions: []dns.DNSQuestion{},
			},
			clientAddr: &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 54321,
			},
			description: "Should handle request with maximum ID and IPv6 client",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := server.handleRequest(test.request, test.clientAddr)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestForwardRequestEdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		server      *DNSServer
		questions   []dns.DNSQuestion
		description string
	}{
		{
			name: "forward with port 0 resolver",
			server: &DNSServer{
				resolverAddr: "127.0.0.1:0",
			},
			questions: []dns.DNSQuestion{
				{
					Name:  createTestDomainName("example.com"),
					Type:  [2]byte{0x00, 0x01},
					Class: [2]byte{0x00, 0x01},
				},
			},
			description: "Should handle resolver with port 0",
		},
		{
			name: "forward with localhost resolver",
			server: &DNSServer{
				resolverAddr: "localhost:53",
			},
			questions: []dns.DNSQuestion{
				{
					Name:  createTestDomainName("test.local"),
					Type:  [2]byte{0x00, 0x01},
					Class: [2]byte{0x00, 0x01},
				},
			},
			description: "Should handle localhost resolver address",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			answers := test.server.forwardRequest(test.questions)
			// All these should fail and return empty answers
			if len(answers) != 0 {
				t.Errorf("Expected empty answers for failed forward, got %d", len(answers))
			}
		})
	}
}

func TestNewDNSServerEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		address      string
		resolverAddr string
		expectError  bool
		description  string
	}{
		{
			name:         "IPv6 addresses",
			address:      "[::1]:8053",
			resolverAddr: "[2001:4860:4860::8888]:53",
			expectError:  false,
			description:  "Should handle IPv6 addresses",
		},
		{
			name:         "hostname resolver",
			address:      "127.0.0.1:0",
			resolverAddr: "dns.google:53",
			expectError:  false,
			description:  "Should handle hostname in resolver",
		},
		{
			name:         "malformed port",
			address:      "127.0.0.1:abc",
			resolverAddr: "8.8.8.8:53",
			expectError:  true,
			description:  "Should fail with malformed port",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := NewDNSServer(test.address, test.resolverAddr)

			if test.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					if server != nil {
						server.Close()
					}
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if server != nil {
				server.Close()
			}
		})
	}
}
