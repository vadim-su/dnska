package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vadim-su/dnska/internal/storage"
	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// StorageTestSuite runs a comprehensive test suite against any Storage implementation
type StorageTestSuite struct {
	t       *testing.T
	storage storage.Storage
	ctx     context.Context
}

// NewStorageTestSuite creates a new test suite for the given storage
func NewStorageTestSuite(t *testing.T, s storage.Storage) *StorageTestSuite {
	return &StorageTestSuite{
		t:       t,
		storage: s,
		ctx:     context.Background(),
	}
}

// RunAll runs all tests in the suite
func (s *StorageTestSuite) RunAll() {
	s.TestBasicCRUD()
	s.TestGetRecords()
	s.TestQueryRecords()
	s.TestBatchOperations()
	s.TestZoneOperations()
	s.TestValidation()
	s.TestEdgeCases()
}

// TestBasicCRUD tests basic create, read, update, delete operations
func (s *StorageTestSuite) TestBasicCRUD() {
	t := s.t
	ctx := s.ctx

	// Create a test A record
	aRecord, err := records.NewARecordFromString("test.example.com", "192.168.1.1", 300)
	require.NoError(t, err)

	// Test Put
	err = s.storage.PutRecord(ctx, aRecord)
	assert.NoError(t, err, "Should store A record without error")

	// Test Get
	retrieved, err := s.storage.GetRecord(ctx, "test.example.com", types.TYPE_A)
	assert.NoError(t, err, "Should retrieve A record without error")
	assert.NotNil(t, retrieved)
	assert.Equal(t, "test.example.com.", retrieved.Name())
	assert.Equal(t, types.TYPE_A, retrieved.Type())

	// Test adding second A record (DNS allows multiple A records)
	secondRecord, err := records.NewARecordFromString("test.example.com", "192.168.1.2", 600)
	require.NoError(t, err)

	err = s.storage.PutRecord(ctx, secondRecord)
	assert.NoError(t, err, "Should add second A record")

	// Should have 2 A records now
	allARecords, err := s.storage.GetRecords(ctx, "test.example.com", types.TYPE_A)
	assert.NoError(t, err)
	assert.Len(t, allARecords, 2, "Should have both A records")

	// Test Delete
	err = s.storage.DeleteRecord(ctx, "test.example.com", types.TYPE_A)
	assert.NoError(t, err, "Should delete record without error")

	// Verify deletion
	retrieved, err = s.storage.GetRecord(ctx, "test.example.com", types.TYPE_A)
	assert.ErrorIs(t, err, storage.ErrRecordNotFound)
	assert.Nil(t, retrieved)
}

// TestGetRecords tests retrieving multiple records
func (s *StorageTestSuite) TestGetRecords() {
	t := s.t
	ctx := s.ctx

	// Create multiple records for the same domain
	aRecord1, _ := records.NewARecordFromString("multi.example.com", "192.168.1.1", 300)
	aRecord2, _ := records.NewARecordFromString("multi.example.com", "192.168.1.2", 300)
	aaaaRecord, _ := records.NewAAAARecordFromString("multi.example.com", "2001:db8::1", 300)
	mxRecord := records.NewMXRecord("multi.example.com", "mail.example.com", 10, 300)

	// Store all records
	require.NoError(t, s.storage.PutRecord(ctx, aRecord1))
	require.NoError(t, s.storage.PutRecord(ctx, aRecord2))
	require.NoError(t, s.storage.PutRecord(ctx, aaaaRecord))
	require.NoError(t, s.storage.PutRecord(ctx, mxRecord))

	// Test getting records by type
	aRecords, err := s.storage.GetRecords(ctx, "multi.example.com", types.TYPE_A)
	assert.NoError(t, err)
	assert.Len(t, aRecords, 2, "Should return both A records")

	// Test getting all records (type = 0)
	allRecords, err := s.storage.GetRecords(ctx, "multi.example.com", 0)
	assert.NoError(t, err)
	assert.Len(t, allRecords, 4, "Should return all records for the domain")

	// Test getting non-existent domain
	noRecords, err := s.storage.GetRecords(ctx, "nonexistent.example.com", types.TYPE_A)
	assert.NoError(t, err)
	assert.Len(t, noRecords, 0, "Should return empty slice for non-existent domain")

	// Cleanup
	s.storage.DeleteRecord(ctx, "multi.example.com", 0)
}

// TestQueryRecords tests the query functionality
func (s *StorageTestSuite) TestQueryRecords() {
	t := s.t
	ctx := s.ctx

	// Setup test data
	testRecords := []records.DNSRecord{
		mustCreateARecord("alpha.example.com", "192.168.1.1", 300),
		mustCreateARecord("beta.example.com", "192.168.1.2", 600),
		mustCreateARecord("gamma.example.com", "192.168.1.3", 900),
		mustCreateAAAARecord("alpha.example.com", "2001:db8::1", 300),
		records.NewCNAMERecord("www.example.com", "example.com", 300),
		records.NewMXRecord("example.com", "mail.example.com", 10, 300),
	}

	for _, r := range testRecords {
		require.NoError(t, s.storage.PutRecord(ctx, r))
	}

	// Test query by name
	results, err := s.storage.QueryRecords(ctx, storage.QueryOptions{
		Name: "alpha.example.com",
	})
	assert.NoError(t, err)
	assert.Len(t, results, 2, "Should return both alpha.example.com records")

	// Test query by record type
	results, err = s.storage.QueryRecords(ctx, storage.QueryOptions{
		RecordType: types.TYPE_A,
	})
	assert.NoError(t, err)
	assert.Len(t, results, 3, "Should return all A records")

	// Test query with pagination
	results, err = s.storage.QueryRecords(ctx, storage.QueryOptions{
		Limit:  2,
		Offset: 1,
	})
	assert.NoError(t, err)
	assert.LessOrEqual(t, len(results), 2, "Should respect limit")

	// Test query with name prefix
	results, err = s.storage.QueryRecords(ctx, storage.QueryOptions{
		NamePrefix: "alpha",
	})
	assert.NoError(t, err)
	assert.Len(t, results, 2, "Should return records starting with 'alpha'")

	// Test query with sorting
	results, err = s.storage.QueryRecords(ctx, storage.QueryOptions{
		RecordType: types.TYPE_A,
		SortBy:     "ttl",
		SortOrder:  "asc",
	})
	assert.NoError(t, err)
	if len(results) >= 2 {
		assert.LessOrEqual(t, results[0].TTL(), results[1].TTL(), "Should be sorted by TTL ascending")
	}

	// Cleanup
	for _, r := range testRecords {
		s.storage.DeleteRecord(ctx, r.Name(), r.Type())
	}
}

// TestBatchOperations tests batch put and delete operations
func (s *StorageTestSuite) TestBatchOperations() {
	t := s.t
	ctx := s.ctx

	// Prepare batch records
	batchRecords := []records.DNSRecord{
		mustCreateARecord("batch1.example.com", "192.168.1.1", 300),
		mustCreateARecord("batch2.example.com", "192.168.1.2", 300),
		mustCreateARecord("batch3.example.com", "192.168.1.3", 300),
		mustCreateAAAARecord("batch1.example.com", "2001:db8::1", 300),
		records.NewCNAMERecord("batch-cname.example.com", "example.com", 300),
	}

	// Test batch put
	err := s.storage.BatchPutRecords(ctx, batchRecords)
	assert.NoError(t, err, "Should batch insert records without error")

	// Verify all records were inserted
	for _, record := range batchRecords {
		retrieved, err := s.storage.GetRecord(ctx, record.Name(), record.Type())
		assert.NoError(t, err, "Record should exist after batch insert")
		assert.NotNil(t, retrieved)
	}

	// Test batch delete by names
	namesToDelete := []string{"batch1.example.com", "batch2.example.com"}
	err = s.storage.BatchDeleteRecords(ctx, namesToDelete, types.TYPE_A)
	assert.NoError(t, err, "Should batch delete records without error")

	// Verify deletion
	for _, name := range namesToDelete {
		_, err := s.storage.GetRecord(ctx, name, types.TYPE_A)
		assert.ErrorIs(t, err, storage.ErrRecordNotFound)
	}

	// Verify other records still exist
	retrieved, err := s.storage.GetRecord(ctx, "batch3.example.com", types.TYPE_A)
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)

	// Cleanup remaining records
	s.storage.DeleteRecord(ctx, "batch3.example.com", 0)
	s.storage.DeleteRecord(ctx, "batch1.example.com", types.TYPE_AAAA)
	s.storage.DeleteRecord(ctx, "batch-cname.example.com", types.TYPE_CNAME)
}

// TestZoneOperations tests zone-related functionality
func (s *StorageTestSuite) TestZoneOperations() {
	t := s.t
	ctx := s.ctx

	// Setup records in different zones
	zoneRecords := []records.DNSRecord{
		mustCreateARecord("host1.zone1.com", "192.168.1.1", 300),
		mustCreateARecord("host2.zone1.com", "192.168.1.2", 300),
		mustCreateARecord("host1.zone2.com", "192.168.2.1", 300),
		mustCreateARecord("subdomain.host1.zone1.com", "192.168.1.11", 300),
		records.NewCNAMERecord("www.zone1.com", "zone1.com", 300),
	}

	for _, r := range zoneRecords {
		require.NoError(t, s.storage.PutRecord(ctx, r))
	}

	// Test GetZones
	zones, err := s.storage.GetZones(ctx)
	assert.NoError(t, err)
	assert.Contains(t, zones, "zone1.com")
	assert.Contains(t, zones, "zone2.com")

	// Test ListRecordsByZone
	zone1Records, err := s.storage.ListRecordsByZone(ctx, "zone1.com")
	assert.NoError(t, err)
	assert.Len(t, zone1Records, 4, "Should return all records in zone1.com")

	zone2Records, err := s.storage.ListRecordsByZone(ctx, "zone2.com")
	assert.NoError(t, err)
	assert.Len(t, zone2Records, 1, "Should return all records in zone2.com")

	// Cleanup
	for _, r := range zoneRecords {
		s.storage.DeleteRecord(ctx, r.Name(), r.Type())
	}
}

// TestValidation tests validation of invalid records
func (s *StorageTestSuite) TestValidation() {
	t := s.t
	ctx := s.ctx

	// Test invalid domain names
	invalidNames := []string{
		"",                        // Empty name
		"invalid..double.dot.com", // Double dots
		"invalid-.hyphen.com",     // Label starting with hyphen
		"invalid.-hyphen.com",     // Label ending with hyphen
		"toolong" + string(make([]byte, 250)) + ".com", // Too long
	}

	for _, name := range invalidNames {
		// Try creating an A record with invalid name
		err := s.storage.PutRecord(ctx, &testRecord{
			name:       name,
			recordType: types.TYPE_A,
			ttl:        300,
		})
		assert.Error(t, err, "Should reject invalid domain name: %s", name)
	}

	// Test invalid TTL (if validation is enabled)
	err := s.storage.PutRecord(ctx, &testRecord{
		name:       "valid.example.com",
		recordType: types.TYPE_A,
		ttl:        999999999, // Way too large
	})
	// This might or might not error depending on validation config
	if err != nil {
		assert.Contains(t, err.Error(), "TTL", "Error should mention TTL if validation is enabled")
	}

	// Test nil record
	err = s.storage.PutRecord(ctx, nil)
	assert.ErrorIs(t, err, storage.ErrInvalidRecord, "Should reject nil record")
}

// TestEdgeCases tests various edge cases
func (s *StorageTestSuite) TestEdgeCases() {
	t := s.t
	ctx := s.ctx

	// Test case-insensitive domain names
	upper, _ := records.NewARecordFromString("UPPER.EXAMPLE.COM", "192.168.1.1", 300)
	lower, _ := records.NewARecordFromString("upper.example.com", "192.168.1.2", 300)

	require.NoError(t, s.storage.PutRecord(ctx, upper))
	require.NoError(t, s.storage.PutRecord(ctx, lower))

	// Should treat as same domain (case-insensitive)
	recs, err := s.storage.GetRecords(ctx, "upper.example.com", types.TYPE_A)
	assert.NoError(t, err)
	// Most DNS storage should be case-insensitive
	assert.GreaterOrEqual(t, len(recs), 1, "Should find record regardless of case")

	// Test empty batch operations
	err = s.storage.BatchPutRecords(ctx, []records.DNSRecord{})
	assert.NoError(t, err, "Empty batch put should not error")

	err = s.storage.BatchDeleteRecords(ctx, []string{}, types.TYPE_A)
	assert.NoError(t, err, "Empty batch delete should not error")

	// Test ListRecords on empty storage (after cleanup)
	s.storage.DeleteRecord(ctx, "upper.example.com", 0)

	allRecords, err := s.storage.ListRecords(ctx)
	assert.NoError(t, err, "ListRecords on empty storage should not error")
	assert.NotNil(t, allRecords, "Should return non-nil slice")

	// Test deleting non-existent record
	err = s.storage.DeleteRecord(ctx, "nonexistent.example.com", types.TYPE_A)
	// Some implementations might return ErrRecordNotFound, others might succeed
	if err != nil {
		assert.ErrorIs(t, err, storage.ErrRecordNotFound)
	}
}

// Helper functions

func mustCreateARecord(name, ip string, ttl uint32) records.DNSRecord {
	r, err := records.NewARecordFromString(name, ip, ttl)
	if err != nil {
		panic(err)
	}
	return r
}

func mustCreateAAAARecord(name, ip string, ttl uint32) records.DNSRecord {
	r, err := records.NewAAAARecordFromString(name, ip, ttl)
	if err != nil {
		panic(err)
	}
	return r
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
