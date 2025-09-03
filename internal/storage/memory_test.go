package storage_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vadim-su/dnska/internal/storage"
	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

func TestMemoryStorage_Suite(t *testing.T) {
	// Run the standard storage test suite
	memStorage, err := storage.NewMemoryStorage(&storage.ValidationConfig{
		Enabled: true,
	})
	require.NoError(t, err)
	defer memStorage.Close()

	suite := NewStorageTestSuite(t, memStorage)
	suite.RunAll()
}

func TestMemoryStorage_Initialization(t *testing.T) {
	t.Run("with default validation", func(t *testing.T) {
		s, err := storage.NewMemoryStorage(nil)
		assert.NoError(t, err)
		assert.NotNil(t, s)
		defer s.Close()
	})

	t.Run("with custom validation", func(t *testing.T) {
		config := &storage.ValidationConfig{
			Enabled:         true,
			AllowUnderscore: true,
			MinTTL:          60,
			MaxTTL:          86400,
			AllowedTypes:    []string{"A", "AAAA", "CNAME"},
		}

		s, err := storage.NewMemoryStorage(config)
		assert.NoError(t, err)
		assert.NotNil(t, s)
		defer s.Close()

		// Test that non-allowed type is rejected
		mxRecord := records.NewMXRecord("test.example.com", "mail.example.com", 10, 300)
		err = s.PutRecord(context.Background(), mxRecord)
		assert.Error(t, err, "Should reject MX record when not in allowed types")
	})

	t.Run("with disabled validation", func(t *testing.T) {
		config := &storage.ValidationConfig{
			Enabled: false,
		}

		s, err := storage.NewMemoryStorage(config)
		assert.NoError(t, err)
		assert.NotNil(t, s)
		defer s.Close()

		// Should accept invalid domain with validation disabled
		err = s.PutRecord(context.Background(), &testRecord{
			name:       "invalid..domain",
			recordType: types.TYPE_A,
			ttl:        300,
			data:       []byte{192, 168, 1, 1},
		})
		assert.NoError(t, err, "Should accept invalid domain when validation is disabled")
	})
}

func TestMemoryStorage_Concurrency(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	const goroutines = 10
	const recordsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Concurrent writes
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < recordsPerGoroutine; j++ {
				name := generateDomainName(id, j)
				record, _ := records.NewARecordFromString(name, "192.168.1.1", 300)
				err := s.PutRecord(ctx, record)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all records were stored
	allRecords, err := s.ListRecords(ctx)
	assert.NoError(t, err)
	assert.Len(t, allRecords, goroutines*recordsPerGoroutine)

	// Concurrent reads
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < recordsPerGoroutine; j++ {
				name := generateDomainName(id, j)
				record, err := s.GetRecord(ctx, name, types.TYPE_A)
				assert.NoError(t, err)
				assert.NotNil(t, record)
			}
		}(i)
	}

	wg.Wait()

	// Concurrent deletes
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < recordsPerGoroutine/2; j++ {
				name := generateDomainName(id, j)
				err := s.DeleteRecord(ctx, name, types.TYPE_A)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify half the records were deleted
	allRecords, err = s.ListRecords(ctx)
	assert.NoError(t, err)
	assert.Len(t, allRecords, goroutines*recordsPerGoroutine/2)
}

func TestMemoryStorage_Stats(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	// Check if storage implements StorageWithStats
	var statsStorage storage.StorageWithStats
	statsStorage, ok := interface{}(s).(storage.StorageWithStats)
	if !ok {
		t.Skip("MemoryStorage doesn't implement StorageWithStats")
	}

	ctx := context.Background()

	// Get initial stats
	stats, err := statsStorage.GetStats(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 0, stats.TotalRecords)
	assert.Equal(t, 0, stats.TotalZones)

	// Add some records
	records := []records.DNSRecord{
		mustCreateARecord("host1.zone1.com", "192.168.1.1", 300),
		mustCreateARecord("host2.zone1.com", "192.168.1.2", 300),
		mustCreateAAAARecord("host1.zone1.com", "2001:db8::1", 300),
		mustCreateARecord("host1.zone2.com", "192.168.2.1", 300),
		records.NewCNAMERecord("www.zone1.com", "zone1.com", 300),
	}

	for _, r := range records {
		require.NoError(t, s.PutRecord(ctx, r))
	}

	// Check updated stats
	stats, err = statsStorage.GetStats(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 5, stats.TotalRecords)
	assert.Equal(t, 7, stats.TotalZones) // com, zone1.com, zone2.com, and all subdomain zones
	assert.Equal(t, 3, stats.RecordTypes["A"])
	assert.Equal(t, 1, stats.RecordTypes["AAAA"])
	assert.Equal(t, 1, stats.RecordTypes["CNAME"])
	assert.Greater(t, stats.LastUpdated, int64(0))

	// Delete a record and check stats
	err = s.DeleteRecord(ctx, "host1.zone1.com", types.TYPE_A)
	assert.NoError(t, err)

	stats, err = statsStorage.GetStats(ctx)
	assert.NoError(t, err)
	assert.Equal(t, 4, stats.TotalRecords)
}

func TestMemoryStorage_Close(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)

	ctx := context.Background()

	// Add a record
	record, _ := records.NewARecordFromString("test.example.com", "192.168.1.1", 300)
	require.NoError(t, s.PutRecord(ctx, record))

	// Close the storage
	err = s.Close()
	assert.NoError(t, err)

	// Operations after close should fail
	err = s.PutRecord(ctx, record)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)

	_, err = s.GetRecord(ctx, "test.example.com", types.TYPE_A)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)

	_, err = s.ListRecords(ctx)
	assert.ErrorIs(t, err, storage.ErrStorageClosed)

	// Close again should be idempotent
	err = s.Close()
	assert.NoError(t, err)
}

func TestMemoryStorage_ZoneManagement(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	// Add records to build zone hierarchy
	testRecords := []records.DNSRecord{
		mustCreateARecord("example.com", "192.168.1.1", 300),
		mustCreateARecord("www.example.com", "192.168.1.2", 300),
		mustCreateARecord("mail.example.com", "192.168.1.3", 300),
		mustCreateARecord("subdomain.mail.example.com", "192.168.1.4", 300),
		mustCreateARecord("test.org", "192.168.2.1", 300),
	}

	for _, r := range testRecords {
		require.NoError(t, s.PutRecord(ctx, r))
	}

	// Get zones
	zones, err := s.GetZones(ctx)
	assert.NoError(t, err)
	assert.Contains(t, zones, "example.com")
	assert.Contains(t, zones, "org")
	assert.Contains(t, zones, "test.org")

	// List records by zone
	exampleRecords, err := s.ListRecordsByZone(ctx, "example.com")
	assert.NoError(t, err)
	assert.Len(t, exampleRecords, 4)

	// Test zone deletion cascading
	err = s.DeleteRecord(ctx, "example.com", 0)
	assert.NoError(t, err)

	zones, err = s.GetZones(ctx)
	assert.NoError(t, err)
	// Should still have zones from remaining records
	assert.Contains(t, zones, "example.com", "Subdomains should maintain zone")
}

func TestMemoryStorage_QueryOptions(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	// Setup test data with varied TTLs
	testRecords := []records.DNSRecord{
		mustCreateARecord("alpha.example.com", "192.168.1.1", 100),
		mustCreateARecord("beta.example.com", "192.168.1.2", 200),
		mustCreateARecord("gamma.example.com", "192.168.1.3", 300),
		mustCreateAAAARecord("alpha.example.com", "2001:db8::1", 400),
		mustCreateAAAARecord("beta.example.com", "2001:db8::2", 500),
	}

	for _, r := range testRecords {
		require.NoError(t, s.PutRecord(ctx, r))
	}

	t.Run("sort by name ascending", func(t *testing.T) {
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			RecordType: types.TYPE_A,
			SortBy:     "name",
			SortOrder:  "asc",
		})
		assert.NoError(t, err)
		assert.Len(t, results, 3)
		assert.Equal(t, "alpha.example.com", results[0].Name())
		assert.Equal(t, "beta.example.com", results[1].Name())
		assert.Equal(t, "gamma.example.com", results[2].Name())
	})

	t.Run("sort by name descending", func(t *testing.T) {
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			RecordType: types.TYPE_A,
			SortBy:     "name",
			SortOrder:  "desc",
		})
		assert.NoError(t, err)
		assert.Len(t, results, 3)
		assert.Equal(t, "gamma.example.com", results[0].Name())
		assert.Equal(t, "beta.example.com", results[1].Name())
		assert.Equal(t, "alpha.example.com", results[2].Name())
	})

	t.Run("sort by TTL", func(t *testing.T) {
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			SortBy:    "ttl",
			SortOrder: "asc",
		})
		assert.NoError(t, err)
		assert.Len(t, results, 5)
		assert.Equal(t, uint32(100), results[0].TTL())
		assert.Equal(t, uint32(200), results[1].TTL())
	})

	t.Run("sort by type", func(t *testing.T) {
		results, err := s.QueryRecords(ctx, storage.QueryOptions{
			SortBy:    "type",
			SortOrder: "asc",
		})
		assert.NoError(t, err)
		assert.Len(t, results, 5)
		// A records (type 1) should come before AAAA records (type 28)
		assert.Equal(t, types.TYPE_A, results[0].Type())
		assert.Equal(t, types.TYPE_A, results[1].Type())
		assert.Equal(t, types.TYPE_A, results[2].Type())
		assert.Equal(t, types.TYPE_AAAA, results[3].Type())
		assert.Equal(t, types.TYPE_AAAA, results[4].Type())
	})

	t.Run("pagination", func(t *testing.T) {
		// Get first page
		page1, err := s.QueryRecords(ctx, storage.QueryOptions{
			Limit:     2,
			Offset:    0,
			SortBy:    "name",
			SortOrder: "asc",
		})
		assert.NoError(t, err)
		assert.Len(t, page1, 2)

		// Get second page
		page2, err := s.QueryRecords(ctx, storage.QueryOptions{
			Limit:     2,
			Offset:    2,
			SortBy:    "name",
			SortOrder: "asc",
		})
		assert.NoError(t, err)
		assert.Len(t, page2, 2)

		// Get third page (partial)
		page3, err := s.QueryRecords(ctx, storage.QueryOptions{
			Limit:     2,
			Offset:    4,
			SortBy:    "name",
			SortOrder: "asc",
		})
		assert.NoError(t, err)
		assert.Len(t, page3, 1)
	})
}

func TestMemoryStorage_String(t *testing.T) {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{Enabled: true})
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()

	// Add some records
	records := []records.DNSRecord{
		mustCreateARecord("test.example.com", "192.168.1.1", 300),
		mustCreateAAAARecord("test.example.com", "2001:db8::1", 300),
		records.NewCNAMERecord("www.example.com", "example.com", 300),
	}

	for _, r := range records {
		require.NoError(t, s.PutRecord(ctx, r))
	}

	// Get string representation
	str := s.String()
	assert.Contains(t, str, "MemoryStorage")
	assert.Contains(t, str, "records:3")
	assert.Contains(t, str, "zones:4") // com, example.com, test.example.com, www.example.com
	assert.Contains(t, str, "test.example.com")
	assert.Contains(t, str, "www.example.com")
}

// Helper function to generate unique domain names for concurrent tests
func generateDomainName(goroutineID, recordID int) string {
	return string(rune('a'+goroutineID)) + "-" +
		string(rune('0'+recordID/100)) +
		string(rune('0'+(recordID/10)%10)) +
		string(rune('0'+recordID%10)) +
		".example.com"
}
