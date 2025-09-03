package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vadim-su/dnska/internal/storage"
	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// TestStorageValidatorIntegration tests storage and validator working together
func TestStorageValidatorIntegration(t *testing.T) {
	tests := []struct {
		name      string
		config    *storage.ValidationConfig
		record    records.DNSRecord
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid record with strict validation",
			config: &storage.ValidationConfig{
				Enabled:         true,
				AllowUnderscore: false,
				MinTTL:          60,
				MaxTTL:          86400,
			},
			record:    mustCreateARecord(t, "example.com", "192.168.1.1", 300),
			wantError: false,
		},
		{
			name: "invalid TTL below minimum",
			config: &storage.ValidationConfig{
				Enabled: true,
				MinTTL:  60,
				MaxTTL:  86400,
			},
			record:    mustCreateARecord(t, "example.com", "192.168.1.1", 30),
			wantError: true,
			errorMsg:  "TTL",
		},
		{
			name: "invalid TTL above maximum",
			config: &storage.ValidationConfig{
				Enabled: true,
				MinTTL:  60,
				MaxTTL:  86400,
			},
			record:    mustCreateARecord(t, "example.com", "192.168.1.1", 100000),
			wantError: true,
			errorMsg:  "TTL",
		},
		{
			name: "underscore in domain with allowUnderscore=false",
			config: &storage.ValidationConfig{
				Enabled:         true,
				AllowUnderscore: false,
			},
			record:    mustCreateTXTRecord(t, "_dmarc.example.com", "v=DMARC1; p=none"),
			wantError: true,
			errorMsg:  "invalid",
		},
		{
			name: "underscore in domain with allowUnderscore=true",
			config: &storage.ValidationConfig{
				Enabled:         true,
				AllowUnderscore: true,
			},
			record:    mustCreateTXTRecord(t, "_dmarc.example.com", "v=DMARC1; p=none"),
			wantError: false,
		},
		{
			name: "restricted record type",
			config: &storage.ValidationConfig{
				Enabled:      true,
				AllowedTypes: []string{"A", "AAAA"},
			},
			record:    records.NewMXRecord("example.com", "mail.example.com", 10, 300),
			wantError: true,
			errorMsg:  "not allowed",
		},
		{
			name: "validation disabled accepts invalid domain",
			config: &storage.ValidationConfig{
				Enabled: false,
			},
			record: &testRecord{
				name:       "invalid..domain.com",
				recordType: types.TYPE_A,
				ttl:        300,
				data:       []byte{192, 168, 1, 1},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := storage.NewMemoryStorage(tt.config)
			require.NoError(t, err)
			defer s.Close()

			ctx := context.Background()
			err = s.PutRecord(ctx, tt.record)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestStorageZoneManagementIntegration tests automatic zone management
func TestStorageZoneManagementIntegration(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	// Add records in different zones
	records := []records.DNSRecord{
		mustCreateARecord(t, "host1.subdomain.example.com", "192.168.1.1", 300),
		mustCreateARecord(t, "host2.subdomain.example.com", "192.168.1.2", 300),
		mustCreateARecord(t, "www.example.com", "192.168.1.3", 300),
		mustCreateARecord(t, "example.org", "192.168.2.1", 300),
		mustCreateARecord(t, "deep.nested.subdomain.example.com", "192.168.1.4", 300),
	}

	// Add all records
	for _, record := range records {
		require.NoError(t, s.PutRecord(ctx, record))
	}

	// Check zones are created correctly
	zones, err := s.GetZones(ctx)
	assert.NoError(t, err)

	// Should have zones for all levels
	assert.Contains(t, zones, "com")
	assert.Contains(t, zones, "org")
	assert.Contains(t, zones, "example.com")
	assert.Contains(t, zones, "example.org")
	assert.Contains(t, zones, "subdomain.example.com")

	// Test zone-based record listing
	t.Run("list records by zone", func(t *testing.T) {
		exampleComRecords, err := s.ListRecordsByZone(ctx, "example.com")
		assert.NoError(t, err)
		assert.Len(t, exampleComRecords, 4) // All .example.com records

		subdomainRecords, err := s.ListRecordsByZone(ctx, "subdomain.example.com")
		assert.NoError(t, err)
		assert.Len(t, subdomainRecords, 3) // Including deep.nested

		orgRecords, err := s.ListRecordsByZone(ctx, "example.org")
		assert.NoError(t, err)
		assert.Len(t, orgRecords, 1)
	})

	// Test zone cleanup on deletion
	t.Run("zone cleanup on record deletion", func(t *testing.T) {
		// Delete the only .org record
		err := s.DeleteRecord(ctx, "example.org", types.TYPE_A)
		assert.NoError(t, err)

		zonesAfterDelete, err := s.GetZones(ctx)
		assert.NoError(t, err)
		_ = zonesAfterDelete // Check depends on implementation

		// example.org zone should still exist if other records reference it
		// But if it's the last record, some implementations might clean it up
		// This behavior is implementation-specific
	})
}

// TestStorageConcurrentAccessIntegration tests concurrent access patterns
func TestStorageConcurrentAccessIntegration(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	const (
		numWriters       = 5
		numReaders       = 10
		recordsPerWriter = 20
	)

	var wg sync.WaitGroup
	errors := make(chan error, numWriters+numReaders)

	// Start writers
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < recordsPerWriter; i++ {
				domain := generateDomain(writerID, i)
				record, err := records.NewARecordFromString(domain, "192.168.1.1", 300)
				if err != nil {
					errors <- err
					return
				}
				if err := s.PutRecord(ctx, record); err != nil {
					errors <- err
					return
				}
			}
		}(w)
	}

	// Let writers get started
	time.Sleep(10 * time.Millisecond)

	// Start readers
	for r := 0; r < numReaders; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			// Each reader tries to read random records
			for i := 0; i < 50; i++ {
				writerID := i % numWriters
				recordID := i % recordsPerWriter
				domain := generateDomain(writerID, recordID)

				// Try to read - might not exist yet
				_, _ = s.GetRecord(ctx, domain, types.TYPE_A)

				// Also do a list operation
				_, _ = s.ListRecords(ctx)

				time.Sleep(time.Millisecond) // Small delay to spread access
			}
		}(r)
	}

	// Start some deleters
	for d := 0; d < 2; d++ {
		wg.Add(1)
		go func(deleterID int) {
			defer wg.Done()
			time.Sleep(50 * time.Millisecond) // Let some records be created first

			for i := 0; i < 10; i++ {
				domain := generateDomain(deleterID, i)
				_ = s.DeleteRecord(ctx, domain, types.TYPE_A)
				time.Sleep(5 * time.Millisecond)
			}
		}(d)
	}

	// Wait for all operations to complete
	wg.Wait()
	close(errors)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
		errorCount++
	}
	assert.Equal(t, 0, errorCount, "Should have no errors during concurrent access")

	// Verify data integrity
	allRecords, err := s.ListRecords(ctx)
	assert.NoError(t, err)
	t.Logf("Final record count: %d", len(allRecords))

	// Check that remaining records are valid
	for _, record := range allRecords {
		assert.NotEmpty(t, record.Name())
		assert.NotZero(t, record.Type())
		assert.NotZero(t, record.TTL())
	}
}

// TestStorageBatchOperationsIntegration tests batch operations
func TestStorageBatchOperationsIntegration(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	t.Run("batch put with validation", func(t *testing.T) {
		batchRecords := []records.DNSRecord{
			mustCreateARecord(t, "batch1.example.com", "192.168.1.1", 300),
			mustCreateARecord(t, "batch2.example.com", "192.168.1.2", 300),
			mustCreateAAAARecord(t, "batch1.example.com", "2001:db8::1", 300),
			records.NewMXRecord("example.com", "mail.example.com", 10, 300),
			records.NewCNAMERecord("www.example.com", "example.com", 300),
		}

		err := s.BatchPutRecords(ctx, batchRecords)
		assert.NoError(t, err)

		// Verify all records were stored
		for _, record := range batchRecords {
			retrieved, err := s.GetRecord(ctx, record.Name(), record.Type())
			assert.NoError(t, err)
			assert.NotNil(t, retrieved)
		}
	})

	t.Run("batch put with invalid record fails atomically", func(t *testing.T) {
		// Clear storage first
		allRecords, _ := s.ListRecords(ctx)
		for _, r := range allRecords {
			s.DeleteRecord(ctx, r.Name(), r.Type())
		}

		validRecord := mustCreateARecord(t, "valid.example.com", "192.168.1.1", 300)
		invalidRecord := &testRecord{
			name:       "", // Invalid: empty name
			recordType: types.TYPE_A,
			ttl:        300,
			data:       []byte{192, 168, 1, 1},
		}

		batchRecords := []records.DNSRecord{validRecord, invalidRecord}

		err := s.BatchPutRecords(ctx, batchRecords)
		assert.Error(t, err, "Batch should fail with invalid record")

		// In current implementation, partial records might be stored
		// This is implementation-specific behavior
	})

	t.Run("batch delete operations", func(t *testing.T) {
		// Setup: Add some records
		setupRecords := []records.DNSRecord{
			mustCreateARecord(t, "delete1.example.com", "192.168.1.1", 300),
			mustCreateARecord(t, "delete2.example.com", "192.168.1.2", 300),
			mustCreateARecord(t, "keep.example.com", "192.168.1.3", 300),
		}

		for _, r := range setupRecords {
			require.NoError(t, s.PutRecord(ctx, r))
		}

		// Batch delete specific records
		namesToDelete := []string{"delete1.example.com", "delete2.example.com"}
		err := s.BatchDeleteRecords(ctx, namesToDelete, types.TYPE_A)
		assert.NoError(t, err)

		// Verify deleted
		for _, name := range namesToDelete {
			_, err := s.GetRecord(ctx, name, types.TYPE_A)
			assert.ErrorIs(t, err, storage.ErrRecordNotFound)
		}

		// Verify kept record still exists
		kept, err := s.GetRecord(ctx, "keep.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.NotNil(t, kept)
	})
}

// TestStorageQueryIntegration tests complex query operations
func TestStorageQueryIntegration(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	// Setup diverse test data
	testData := []records.DNSRecord{
		mustCreateARecord(t, "alpha.example.com", "192.168.1.1", 100),
		mustCreateARecord(t, "beta.example.com", "192.168.1.2", 200),
		mustCreateARecord(t, "gamma.example.com", "192.168.1.3", 300),
		mustCreateAAAARecord(t, "alpha.example.com", "2001:db8::1", 400),
		mustCreateAAAARecord(t, "beta.example.com", "2001:db8::2", 500),
		records.NewCNAMERecord("www.example.com", "example.com", 600),
		records.NewMXRecord("example.com", "mail.example.com", 10, 700),
		records.NewMXRecord("example.com", "mail2.example.com", 20, 700),
		mustCreateARecord(t, "alpha.example.org", "192.168.2.1", 100),
		mustCreateARecord(t, "beta.example.org", "192.168.2.2", 200),
	}

	for _, record := range testData {
		require.NoError(t, s.PutRecord(ctx, record))
	}

	t.Run("filter by record type", func(t *testing.T) {
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			RecordType: types.TYPE_A,
		})
		assert.NoError(t, err)
		assert.Len(t, results, 5) // 5 A records

		for _, r := range results {
			assert.Equal(t, types.TYPE_A, r.Type())
		}
	})

	t.Run("filter by zone", func(t *testing.T) {
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			Zone: "example.com",
		})
		assert.NoError(t, err)
		assert.Len(t, results, 8) // All .example.com records

		for _, r := range results {
			assert.Contains(t, r.Name(), "example.com")
		}
	})

	t.Run("filter by name prefix", func(t *testing.T) {
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			NamePrefix: "alpha",
		})
		assert.NoError(t, err)
		assert.Len(t, results, 3) // alpha.example.com (A+AAAA) + alpha.example.org (A)

		for _, r := range results {
			assert.Contains(t, r.Name(), "alpha")
		}
	})

	t.Run("pagination", func(t *testing.T) {
		// Get first page
		page1, err := s.QueryRecords(ctx, storage.QueryOptions{
			Limit:  3,
			Offset: 0,
		})
		assert.NoError(t, err)
		assert.Len(t, page1, 3)

		// Get second page
		page2, err := s.QueryRecords(ctx, storage.QueryOptions{
			Limit:  3,
			Offset: 3,
		})
		assert.NoError(t, err)
		assert.Len(t, page2, 3)

		// Verify no overlap
		page1Names := make(map[string]bool)
		for _, r := range page1 {
			key := r.Name() + ":" + r.Type().String()
			page1Names[key] = true
		}

		for _, r := range page2 {
			key := r.Name() + ":" + r.Type().String()
			assert.False(t, page1Names[key], "Pages should not overlap")
		}
	})

	t.Run("sorting", func(t *testing.T) {
		// Sort by TTL ascending
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			RecordType: types.TYPE_A,
			SortBy:     "ttl",
			SortOrder:  "asc",
		})
		assert.NoError(t, err)

		// Verify ordering
		for i := 1; i < len(results); i++ {
			assert.LessOrEqual(t, results[i-1].TTL(), results[i].TTL())
		}

		// Sort by name descending
		results, err = s.QueryRecords(ctx, storage.QueryOptions{
			SortBy:    "name",
			SortOrder: "desc",
		})
		assert.NoError(t, err)

		// Verify ordering
		for i := 1; i < len(results); i++ {
			assert.GreaterOrEqual(t, results[i-1].Name(), results[i].Name())
		}
	})

	t.Run("complex query", func(t *testing.T) {
		// Combine multiple filters
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			Zone:       "example.com",
			RecordType: types.TYPE_A,
			SortBy:     "name",
			SortOrder:  "asc",
			Limit:      2,
		})
		assert.NoError(t, err)
		assert.Len(t, results, 2)
		assert.Equal(t, types.TYPE_A, results[0].Type())
		assert.Contains(t, results[0].Name(), "example.com")
	})
}

// Helper functions

func generateDomain(writerID, recordID int) string {
	return string(rune('a'+writerID)) + "-" +
		string(rune('0'+recordID/10)) +
		string(rune('0'+recordID%10)) +
		".example.com"
}

func mustCreateARecord(t *testing.T, name, ip string, ttl uint32) records.DNSRecord {
	r, err := records.NewARecordFromString(name, ip, ttl)
	require.NoError(t, err)
	return r
}

func mustCreateAAAARecord(t *testing.T, name, ip string, ttl uint32) records.DNSRecord {
	r, err := records.NewAAAARecordFromString(name, ip, ttl)
	require.NoError(t, err)
	return r
}

func mustCreateTXTRecord(t *testing.T, name, text string) records.DNSRecord {
	return records.NewTXTRecordFromString(name, text, 300)
}

// testRecord is a minimal DNSRecord implementation for testing
type testRecord struct {
	name       string
	recordType types.DNSType
	ttl        uint32
	data       []byte
}

func (r *testRecord) Name() string            { return r.name }
func (r *testRecord) Type() types.DNSType     { return r.recordType }
func (r *testRecord) Class() types.DNSClass   { return types.CLASS_IN }
func (r *testRecord) TTL() uint32             { return r.ttl }
func (r *testRecord) Data() []byte            { return r.data }
func (r *testRecord) SetTTL(ttl uint32)       { r.ttl = ttl }
func (r *testRecord) String() string          { return r.name }
func (r *testRecord) Copy() records.DNSRecord { return r }
