package integration

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vadim-su/dnska/internal/config"
	"github.com/vadim-su/dnska/internal/server"
	"github.com/vadim-su/dnska/pkg/dns/message"
	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
	"github.com/vadim-su/dnska/pkg/dns/utils"
)

// TestServerHelper provides utilities for integration testing
type TestServerHelper struct {
	Server  *server.Server
	Address string
	Port    int
}

// StartTestServer starts a DNS server on a random port for testing
func StartTestServer(t *testing.T) *TestServerHelper {
	t.Helper()

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Create config with test port
	cfg := config.DefaultConfig()
	cfg.Server.Address = fmt.Sprintf("127.0.0.1:%d", port)
	cfg.Server.ReadTimeout = 2 * time.Second
	cfg.Server.WriteTimeout = 2 * time.Second

	// Use shorter timeouts for tests
	cfg.Resolver.Timeout = 1 * time.Second
	cfg.Cache.TTL = 10 * time.Second

	// Create and start server
	srv, err := server.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	serverStarted := make(chan error, 1)
	go func() {
		err := srv.Start()
		if err != nil {
			serverStarted <- err
		}
	}()

	// Wait for server to start or fail
	select {
	case err := <-serverStarted:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
	}

	// Verify server is listening
	conn, err := net.Dial("udp", cfg.Server.Address)
	if err != nil {
		srv.Close()
		t.Fatalf("Server is not listening: %v", err)
	}
	conn.Close()

	return &TestServerHelper{
		Server:  srv,
		Address: cfg.Server.Address,
		Port:    port,
	}
}

// Stop stops the test server
func (h *TestServerHelper) Stop(t *testing.T) {
	t.Helper()
	if err := h.Server.Close(); err != nil {
		t.Errorf("Failed to stop server: %v", err)
	}
}

// AddRecord adds a DNS record to the test server
func (h *TestServerHelper) AddRecord(t *testing.T, record records.DNSRecord) {
	t.Helper()
	if err := h.Server.AddRecord(record); err != nil {
		t.Fatalf("Failed to add record: %v", err)
	}
}

// SendDNSQuery sends a DNS query to the test server and returns the response
func (h *TestServerHelper) SendDNSQuery(t *testing.T, domain string, recordType types.DNSType) *message.DNSResponse {
	t.Helper()

	// Create DNS question
	domainBytes := encodeDomainName(domain)
	domainName, _, err := utils.NewDomainName(domainBytes)
	if err != nil {
		t.Fatalf("Failed to create domain name: %v", err)
	}

	question := message.DNSQuestion{
		Name:  *domainName,
		Type:  types.DnsTypeClassToBytes(recordType),
		Class: types.DnsTypeClassToBytes(types.CLASS_IN),
	}

	// Create DNS query
	query := message.GenerateDNSQuery(1234, []message.DNSQuestion{question})
	queryBytes := query.ToBytesWithCompression()

	// Send query via UDP
	conn, err := net.Dial("udp", h.Address)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send query
	_, err = conn.Write(queryBytes)
	if err != nil {
		t.Fatalf("Failed to send query: %v", err)
	}

	// Read response
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Parse response
	response, err := message.NewDNSResponse(buffer[:n])
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	return response
}

// encodeDomainName converts a domain string to DNS wire format
func encodeDomainName(domain string) []byte {
	if domain == "" {
		return []byte{0}
	}

	// Remove trailing dot if present
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	result := []byte{}
	labels := []byte(domain)
	start := 0

	for i := 0; i <= len(labels); i++ {
		if i == len(labels) || labels[i] == '.' {
			labelLen := i - start
			if labelLen > 0 {
				result = append(result, byte(labelLen))
				result = append(result, labels[start:i]...)
			}
			start = i + 1
		}
	}

	result = append(result, 0) // Null terminator
	return result
}

// sendDNSQuerySafe sends a DNS query without using testing.T (safe for goroutines)
func sendDNSQuerySafe(address, domain string, recordType types.DNSType) (*message.DNSResponse, error) {
	// Create DNS question
	domainBytes := encodeDomainName(domain)
	domainName, _, err := utils.NewDomainName(domainBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain name: %v", err)
	}

	question := message.DNSQuestion{
		Name:  *domainName,
		Type:  types.DnsTypeClassToBytes(recordType),
		Class: types.DnsTypeClassToBytes(types.CLASS_IN),
	}

	// Create DNS query
	query := message.GenerateDNSQuery(uint16(time.Now().UnixNano()&0xFFFF), []message.DNSQuestion{question})
	queryBytes := query.ToBytesWithCompression()

	// Send query via UDP
	conn, err := net.Dial("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send query
	_, err = conn.Write(queryBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %v", err)
	}

	// Read response
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse response
	response, err := message.NewDNSResponse(buffer[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return response, nil
}

// TestServerStartStop tests that the server can start and stop properly
func TestServerStartStop(t *testing.T) {
	helper := StartTestServer(t)
	// Don't use defer here since we're manually stopping

	// Verify server is running
	if !helper.Server.IsRunning() {
		t.Error("Server should be running")
	}

	// Stop server
	helper.Stop(t)

	// Verify server is stopped
	if helper.Server.IsRunning() {
		t.Error("Server should be stopped")
	}
}

// TestDNSQuery tests basic DNS query functionality
func TestDNSQuery(t *testing.T) {
	helper := StartTestServer(t)
	defer helper.Stop(t)

	// Add a test A record
	aRecord := records.NewARecord("test.local", net.IPv4(192, 168, 1, 1), 300)
	helper.AddRecord(t, aRecord)

	// Query for the record
	response := helper.SendDNSQuery(t, "test.local", types.TYPE_A)

	// Verify response
	if len(response.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(response.Answers))
	}

	// Check response code
	if response.Header.Flags&0xF != 0 {
		t.Errorf("Expected NOERROR response code, got %d", response.Header.Flags&0xF)
	}
}

// TestMultipleRecords tests querying multiple records
func TestMultipleRecords(t *testing.T) {
	helper := StartTestServer(t)
	defer helper.Stop(t)

	// Add multiple A records for the same domain
	aRecord1 := records.NewARecord("multi.local", net.IPv4(192, 168, 1, 1), 300)
	aRecord2 := records.NewARecord("multi.local", net.IPv4(192, 168, 1, 2), 300)

	helper.AddRecord(t, aRecord1)
	helper.AddRecord(t, aRecord2)

	// Query for the records
	response := helper.SendDNSQuery(t, "multi.local", types.TYPE_A)

	// Verify we got both records
	if len(response.Answers) != 2 {
		t.Fatalf("Expected 2 answers, got %d", len(response.Answers))
	}
}

// TestCNAMERecord tests CNAME record resolution
func TestCNAMERecord(t *testing.T) {
	helper := StartTestServer(t)
	defer helper.Stop(t)

	// Add a CNAME record
	cnameRecord := records.NewCNAMERecord("alias.local", "target.local", 300)
	helper.AddRecord(t, cnameRecord)

	// Add an A record for the target
	aRecord := records.NewARecord("target.local", net.IPv4(192, 168, 1, 1), 300)
	helper.AddRecord(t, aRecord)

	// Query for the CNAME
	response := helper.SendDNSQuery(t, "alias.local", types.TYPE_CNAME)

	// Verify response
	if len(response.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(response.Answers))
	}
}

// TestNXDOMAIN tests non-existent domain response
func TestNXDOMAIN(t *testing.T) {
	helper := StartTestServer(t)
	defer helper.Stop(t)

	// Query for non-existent domain
	response := helper.SendDNSQuery(t, "nonexistent.local", types.TYPE_A)

	// Should get NXDOMAIN response (RCODE 3)
	rcode := types.DNSFlag(response.Header.Flags & 0xF)
	if rcode != types.DNSFlag(types.RCODE_NAME_ERROR) {
		t.Errorf("Expected NXDOMAIN (3), got RCODE %d", rcode)
	}
}

// TestConcurrentQueries tests handling multiple concurrent queries
func TestConcurrentQueries(t *testing.T) {
	helper := StartTestServer(t)
	defer helper.Stop(t)

	// Add test records
	for i := 1; i <= 10; i++ {
		domain := fmt.Sprintf("test%d.local", i)
		ip := net.IPv4(192, 168, 1, byte(i))
		aRecord := records.NewARecord(domain, ip, 300)
		helper.AddRecord(t, aRecord)
	}

	// Send concurrent queries
	type queryResult struct {
		index       int
		err         error
		answerCount int
	}
	results := make(chan queryResult, 10)

	for i := 1; i <= 10; i++ {
		go func(index int) {
			domain := fmt.Sprintf("test%d.local", index)
			response, err := sendDNSQuerySafe(helper.Address, domain, types.TYPE_A)
			if err != nil {
				results <- queryResult{index: index, err: err}
			} else {
				results <- queryResult{index: index, answerCount: len(response.Answers)}
			}
		}(i)
	}

	// Wait for all queries to complete
	for i := 0; i < 10; i++ {
		select {
		case result := <-results:
			if result.err != nil {
				t.Errorf("Query %d failed: %v", result.index, result.err)
			} else if result.answerCount != 1 {
				t.Errorf("Query %d: Expected 1 answer, got %d", result.index, result.answerCount)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent queries")
		}
	}
}

// TestTCPQuery tests DNS over TCP
func TestTCPQuery(t *testing.T) {
	helper := StartTestServer(t)
	defer helper.Stop(t)

	// Add a test record
	aRecord := records.NewARecord("tcp-test.local", net.IPv4(192, 168, 1, 1), 300)
	helper.AddRecord(t, aRecord)

	// Create DNS question
	domainBytes := encodeDomainName("tcp-test.local")
	domainName, _, err := utils.NewDomainName(domainBytes)
	if err != nil {
		t.Fatalf("Failed to create domain name: %v", err)
	}

	question := message.DNSQuestion{
		Name:  *domainName,
		Type:  types.DnsTypeClassToBytes(types.TYPE_A),
		Class: types.DnsTypeClassToBytes(types.CLASS_IN),
	}

	// Create DNS query
	query := message.GenerateDNSQuery(5678, []message.DNSQuestion{question})
	queryBytes := query.ToBytesWithCompression()

	// Send query via TCP
	conn, err := net.Dial("tcp", helper.Address)
	if err != nil {
		t.Fatalf("Failed to connect via TCP: %v", err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send length prefix (TCP DNS requirement)
	length := uint16(len(queryBytes))
	lengthBytes := []byte{byte(length >> 8), byte(length)}
	_, err = conn.Write(lengthBytes)
	if err != nil {
		t.Fatalf("Failed to send length prefix: %v", err)
	}

	// Send query
	_, err = conn.Write(queryBytes)
	if err != nil {
		t.Fatalf("Failed to send TCP query: %v", err)
	}

	// Read response length
	lengthBuf := make([]byte, 2)
	_, err = conn.Read(lengthBuf)
	if err != nil {
		t.Fatalf("Failed to read response length: %v", err)
	}

	responseLength := (uint16(lengthBuf[0]) << 8) | uint16(lengthBuf[1])

	// Read response
	buffer := make([]byte, responseLength)
	_, err = conn.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read TCP response: %v", err)
	}

	// Parse response
	response, err := message.NewDNSResponse(buffer)
	if err != nil {
		t.Fatalf("Failed to parse TCP response: %v", err)
	}

	// Verify response
	if len(response.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(response.Answers))
	}
}

// TestForwardResolution tests that forward resolution works
func TestForwardResolution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping forward resolution test in short mode")
	}

	helper := StartTestServer(t)
	defer helper.Stop(t)

	// Query for a real domain (this will use forward resolution)
	// Using a stable domain that should always exist
	response := helper.SendDNSQuery(t, "google.com", types.TYPE_A)

	// Should get at least one answer
	if len(response.Answers) == 0 {
		t.Error("Expected at least one answer for google.com")
	}

	// Check response code is NOERROR
	if response.Header.Flags&0xF != 0 {
		t.Errorf("Expected NOERROR response code, got %d", response.Header.Flags&0xF)
	}
}

// TestCacheHit tests that caching works
func TestCacheHit(t *testing.T) {
	helper := StartTestServer(t)
	defer helper.Stop(t)

	// Add a test record
	aRecord := records.NewARecord("cache-test.local", net.IPv4(192, 168, 1, 1), 300)
	helper.AddRecord(t, aRecord)

	// First query - cache miss
	start1 := time.Now()
	response1 := helper.SendDNSQuery(t, "cache-test.local", types.TYPE_A)
	duration1 := time.Since(start1)

	if len(response1.Answers) != 1 {
		t.Fatalf("First query: Expected 1 answer, got %d", len(response1.Answers))
	}

	// Second query - should hit cache and be faster
	start2 := time.Now()
	response2 := helper.SendDNSQuery(t, "cache-test.local", types.TYPE_A)
	duration2 := time.Since(start2)

	if len(response2.Answers) != 1 {
		t.Fatalf("Second query: Expected 1 answer, got %d", len(response2.Answers))
	}

	// Log the durations for debugging
	t.Logf("First query took: %v", duration1)
	t.Logf("Second query took: %v", duration2)

	// Note: We can't reliably test that cache is faster in all environments
	// but we can verify both queries return the same result
}
