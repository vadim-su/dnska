package storage

import (
	"context"
	"testing"

	"github.com/vadim-su/dnska/pkg/dns/records"
)

// TestHelpers provides utility functions for tests

// CreateTestRecords creates a set of test DNS records
func CreateTestRecords(t *testing.T) []records.DNSRecord {
	testRecords := []records.DNSRecord{}

	// A records
	if r, err := records.NewARecordFromString("test.example.com", "192.168.1.1", 300); err == nil {
		testRecords = append(testRecords, r)
	}

	if r, err := records.NewARecordFromString("www.example.com", "192.168.1.2", 300); err == nil {
		testRecords = append(testRecords, r)
	}

	// AAAA record
	if r, err := records.NewAAAARecordFromString("test.example.com", "2001:db8::1", 300); err == nil {
		testRecords = append(testRecords, r)
	}

	// CNAME record
	testRecords = append(testRecords, records.NewCNAMERecord("alias.example.com", "test.example.com", 300))

	// MX record
	testRecords = append(testRecords, records.NewMXRecord("example.com", "mail.example.com", 10, 300))

	// NS record
	testRecords = append(testRecords, records.NewNSRecord("example.com", "ns1.example.com", 300))

	// PTR record
	testRecords = append(testRecords, records.NewPTRRecord("1.1.168.192.in-addr.arpa", "test.example.com", 300))

	// SOA record
	testRecords = append(testRecords, records.NewSOARecord(
		"example.com",
		"ns1.example.com",
		"admin.example.com",
		2023010101,
		3600,
		1800,
		604800,
		86400,
		300,
	))

	// TXT record
	testRecords = append(testRecords, records.NewTXTRecordFromString("example.com", "v=spf1 +all", 300))

	return testRecords
}

// AssertRecordsEqual asserts that two DNS records are equal
func AssertRecordsEqual(t *testing.T, expected, actual records.DNSRecord) {
	if expected == nil && actual == nil {
		return
	}

	if expected == nil || actual == nil {
		t.Errorf("Records not equal: one is nil (expected: %v, actual: %v)", expected, actual)
		return
	}

	if expected.Name() != actual.Name() {
		t.Errorf("Record names not equal: expected %s, got %s", expected.Name(), actual.Name())
	}

	if expected.Type() != actual.Type() {
		t.Errorf("Record types not equal: expected %s, got %s", expected.Type(), actual.Type())
	}

	if expected.Class() != actual.Class() {
		t.Errorf("Record classes not equal: expected %s, got %s", expected.Class(), actual.Class())
	}

	if expected.TTL() != actual.TTL() {
		t.Errorf("Record TTLs not equal: expected %d, got %d", expected.TTL(), actual.TTL())
	}
}

// PopulateStorage adds test records to a storage
func PopulateStorage(t *testing.T, storage Storage, records []records.DNSRecord) {
	ctx := context.Background()
	for _, record := range records {
		if err := storage.PutRecord(ctx, record); err != nil {
			t.Fatalf("Failed to populate storage with record %s: %v", record.Name(), err)
		}
	}
}

// CleanupStorage removes all records from a storage
func CleanupStorage(t *testing.T, storage Storage) {
	ctx := context.Background()
	records, err := storage.ListRecords(ctx)
	if err != nil {
		t.Fatalf("Failed to list records for cleanup: %v", err)
	}

	for _, record := range records {
		if err := storage.DeleteRecord(ctx, record.Name(), record.Type()); err != nil {
			t.Errorf("Failed to delete record %s: %v", record.Name(), err)
		}
	}
}
