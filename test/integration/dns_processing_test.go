package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vadim-su/dnska/internal/storage"
	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// TestDNSQueryProcessingPipeline tests the complete DNS query processing flow
func TestDNSQueryProcessingPipeline(t *testing.T) {
	// Setup storage with test data
	s := setupTestStorage(t)
	defer s.Close()

	ctx := context.Background()

	t.Run("A record query resolution", func(t *testing.T) {
		// Query for A record
		results, err := s.GetRecords(ctx, "www.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.Len(t, results, 1)

		aRecord := results[0].(*records.ARecord)
		assert.Equal(t, "192.168.1.10", aRecord.IP().String())
	})

	t.Run("CNAME chain resolution", func(t *testing.T) {
		// Add CNAME chain
		cnameRecords := []records.DNSRecord{
			records.NewCNAMERecord("alias1.example.com", "alias2.example.com", 300),
			records.NewCNAMERecord("alias2.example.com", "alias3.example.com", 300),
			records.NewCNAMERecord("alias3.example.com", "www.example.com", 300),
		}

		for _, r := range cnameRecords {
			require.NoError(t, s.PutRecord(ctx, r))
		}

		// Query should follow CNAME chain
		cname, err := s.GetRecord(ctx, "alias1.example.com", types.TYPE_CNAME)
		assert.NoError(t, err)
		assert.Equal(t, "alias2.example.com", cname.(*records.CNAMERecord).Target())

		// Eventually resolves to www.example.com which has an A record
		// In a real DNS server, this would be recursive resolution
	})

	t.Run("wildcard record matching", func(t *testing.T) {
		// Add wildcard record
		wildcardRecord, err := records.NewARecordFromString("*.example.com", "192.168.1.100", 300)
		require.NoError(t, err)
		require.NoError(t, s.PutRecord(ctx, wildcardRecord))

		// Query for non-existent subdomain should match wildcard
		// Note: This is simplified - real DNS wildcard matching is more complex
		results, err := s.GetRecords(ctx, "*.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.Len(t, results, 1)
	})

	t.Run("multiple record types for same name", func(t *testing.T) {
		// Add multiple record types for same domain
		multiRecords := []records.DNSRecord{
			mustCreateARecord(t, "multi.example.com", "192.168.1.20", 300),
			mustCreateAAAARecord(t, "multi.example.com", "2001:db8::20", 300),
			records.NewMXRecord("multi.example.com", "mail.example.com", 10, 300),
			records.NewTXTRecordFromString("multi.example.com", "v=spf1 +all", 300),
		}

		for _, r := range multiRecords {
			require.NoError(t, s.PutRecord(ctx, r))
		}

		// Query for specific type
		aRecords, err := s.GetRecords(ctx, "multi.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.Len(t, aRecords, 1)

		// Query for all types
		allRecords, err := s.GetRecords(ctx, "multi.example.com", 0)
		assert.NoError(t, err)
		assert.Len(t, allRecords, 4)
	})
}

// TestDNSResponseBuilding tests building DNS responses from storage data
func TestDNSResponseBuilding(t *testing.T) {
	s := setupTestStorage(t)
	defer s.Close()

	ctx := context.Background()

	t.Run("answer section population", func(t *testing.T) {
		// Add multiple A records for round-robin
		rrRecords := []records.DNSRecord{
			mustCreateARecord(t, "lb.example.com", "192.168.1.1", 300),
			mustCreateARecord(t, "lb.example.com", "192.168.1.2", 300),
			mustCreateARecord(t, "lb.example.com", "192.168.1.3", 300),
		}

		for _, r := range rrRecords {
			require.NoError(t, s.PutRecord(ctx, r))
		}

		// All records should be in answer section
		results, err := s.GetRecords(ctx, "lb.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.Len(t, results, 3, "All A records should be returned for round-robin")
	})

	t.Run("authority section with SOA", func(t *testing.T) {
		// Add SOA record for zone
		soaRecord := records.NewSOARecord(
			"example.com",
			"ns1.example.com",
			"admin.example.com",
			2024010101,
			7200,   // refresh
			3600,   // retry
			604800, // expire
			86400,  // minimum
			300,
		)
		require.NoError(t, s.PutRecord(ctx, soaRecord))

		// Query for SOA
		soa, err := s.GetRecord(ctx, "example.com", types.TYPE_SOA)
		assert.NoError(t, err)
		assert.NotNil(t, soa)

		soaTyped := soa.(*records.SOARecord)
		assert.Equal(t, "ns1.example.com", soaTyped.PrimaryNS())
		assert.Equal(t, uint32(2024010101), soaTyped.Serial())
	})

	t.Run("additional section with glue records", func(t *testing.T) {
		// Add NS records and glue A records
		nsRecords := []records.DNSRecord{
			records.NewNSRecord("example.com", "ns1.example.com", 300),
			records.NewNSRecord("example.com", "ns2.example.com", 300),
			mustCreateARecord(t, "ns1.example.com", "192.168.1.53", 300),
			mustCreateARecord(t, "ns2.example.com", "192.168.1.54", 300),
		}

		for _, r := range nsRecords {
			require.NoError(t, s.PutRecord(ctx, r))
		}

		// Query NS records
		ns, err := s.GetRecords(ctx, "example.com", types.TYPE_NS)
		assert.NoError(t, err)
		assert.Len(t, ns, 2)

		// Glue records should be available
		glue1, err := s.GetRecord(ctx, "ns1.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.NotNil(t, glue1)

		glue2, err := s.GetRecord(ctx, "ns2.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.NotNil(t, glue2)
	})

	t.Run("MX record priority handling", func(t *testing.T) {
		// Add MX records with different priorities
		mxRecords := []records.DNSRecord{
			records.NewMXRecord("example.com", "mail1.example.com", 10, 300),
			records.NewMXRecord("example.com", "mail2.example.com", 20, 300),
			records.NewMXRecord("example.com", "mail3.example.com", 30, 300),
		}

		for _, r := range mxRecords {
			require.NoError(t, s.PutRecord(ctx, r))
		}

		// Query MX records
		mx, err := s.GetRecords(ctx, "example.com", types.TYPE_MX)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(mx), 3, "Should have at least 3 MX records")

		// Check priorities are preserved
		priorities := make(map[uint16]string)
		for _, r := range mx {
			mxRecord := r.(*records.MXRecord)
			priorities[mxRecord.Preference()] = mxRecord.MailServer()
		}

		assert.Equal(t, "mail1.example.com", priorities[10])
		assert.Equal(t, "mail2.example.com", priorities[20])
		assert.Equal(t, "mail3.example.com", priorities[30])
	})
}

// TestDNSErrorHandling tests various error conditions
func TestDNSErrorHandling(t *testing.T) {
	s := setupTestStorage(t)
	defer s.Close()

	ctx := context.Background()

	t.Run("NXDOMAIN for non-existent domain", func(t *testing.T) {
		// Query for non-existent domain
		results, err := s.GetRecords(ctx, "nonexistent.example.com", types.TYPE_A)
		assert.NoError(t, err) // Storage returns empty slice, not error
		assert.Len(t, results, 0)

		// GetRecord should return ErrRecordNotFound
		_, err = s.GetRecord(ctx, "nonexistent.example.com", types.TYPE_A)
		assert.ErrorIs(t, err, storage.ErrRecordNotFound)
	})

	t.Run("NODATA for domain without requested type", func(t *testing.T) {
		// Add only A record
		require.NoError(t, s.PutRecord(ctx,
			mustCreateARecord(t, "nodata.example.com", "192.168.1.1", 300)))

		// Query for AAAA record
		results, err := s.GetRecords(ctx, "nodata.example.com", types.TYPE_AAAA)
		assert.NoError(t, err)
		assert.Len(t, results, 0, "Should return empty for non-existent record type")

		// But domain exists (can query A record)
		aResults, err := s.GetRecords(ctx, "nodata.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.Len(t, aResults, 1)
	})

	t.Run("invalid query parameters", func(t *testing.T) {
		// Query with invalid domain name
		_, err := s.GetRecords(ctx, "invalid..domain", types.TYPE_A)
		assert.Error(t, err, "Should reject invalid domain name")

		// Query with empty domain
		_, err = s.GetRecords(ctx, "", types.TYPE_A)
		assert.Error(t, err, "Should reject empty domain name")
	})

	t.Run("storage errors propagation", func(t *testing.T) {
		// Close storage to simulate failure
		require.NoError(t, s.Close())

		// Queries should fail
		_, err := s.GetRecords(ctx, "example.com", types.TYPE_A)
		assert.ErrorIs(t, err, storage.ErrStorageClosed)

		err = s.PutRecord(ctx, mustCreateARecord(t, "test.example.com", "192.168.1.1", 300))
		assert.ErrorIs(t, err, storage.ErrStorageClosed)
	})
}

// TestRecordTypesProcessing tests handling of different DNS record types
func TestRecordTypesProcessing(t *testing.T) {
	s := setupTestStorage(t)
	defer s.Close()

	ctx := context.Background()

	t.Run("A and AAAA records", func(t *testing.T) {
		// IPv4
		aRecord := mustCreateARecord(t, "ipv4.example.com", "192.168.1.1", 300)
		require.NoError(t, s.PutRecord(ctx, aRecord))

		// IPv6
		aaaaRecord := mustCreateAAAARecord(t, "ipv6.example.com", "2001:db8::1", 300)
		require.NoError(t, s.PutRecord(ctx, aaaaRecord))

		// Dual stack
		require.NoError(t, s.PutRecord(ctx,
			mustCreateARecord(t, "dual.example.com", "192.168.1.2", 300)))
		require.NoError(t, s.PutRecord(ctx,
			mustCreateAAAARecord(t, "dual.example.com", "2001:db8::2", 300)))

		// Verify retrieval
		a, err := s.GetRecord(ctx, "ipv4.example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.Equal(t, "192.168.1.1", a.(*records.ARecord).IP().String())

		aaaa, err := s.GetRecord(ctx, "ipv6.example.com", types.TYPE_AAAA)
		assert.NoError(t, err)
		assert.Equal(t, "2001:db8::1", aaaa.(*records.AAAARecord).IP().String())
	})

	t.Run("CNAME records", func(t *testing.T) {
		// CNAME record
		cname := records.NewCNAMERecord("www.example.com", "example.com", 300)
		require.NoError(t, s.PutRecord(ctx, cname))

		// CNAME conflicts - can't have other records at same name
		// This should ideally be prevented by validation
		aRecord := mustCreateARecord(t, "www.example.com", "192.168.1.1", 300)
		err := s.PutRecord(ctx, aRecord)
		// Current implementation allows this, but real DNS servers shouldn't
		assert.NoError(t, err) // This is a limitation of current implementation
	})

	t.Run("TXT records", func(t *testing.T) {
		// Simple TXT
		txt1 := records.NewTXTRecordFromString("txt.example.com", "Simple text", 300)
		require.NoError(t, s.PutRecord(ctx, txt1))

		// SPF record
		spf := records.NewTXTRecordFromString("example.com", "v=spf1 include:_spf.example.com ~all", 300)
		require.NoError(t, s.PutRecord(ctx, spf))

		// DMARC record (with underscore)
		dmarc := records.NewTXTRecordFromString("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:dmarc@example.com", 300)
		// This will fail without AllowUnderscore in validation config
		err := s.PutRecord(ctx, dmarc)
		assert.Error(t, err, "Should reject underscore without proper config")
	})

	t.Run("PTR records", func(t *testing.T) {
		// Reverse DNS PTR record
		ptr := records.NewPTRRecord("1.1.168.192.in-addr.arpa", "host1.example.com", 300)
		require.NoError(t, s.PutRecord(ctx, ptr))

		retrieved, err := s.GetRecord(ctx, "1.1.168.192.in-addr.arpa", types.TYPE_PTR)
		assert.NoError(t, err)
		assert.Equal(t, "host1.example.com", retrieved.(*records.PTRRecord).Target())
	})

	t.Run("SRV records", func(t *testing.T) {
		// SRV records typically have underscores
		// Would need special validation config
		// Example: _http._tcp.example.com
	})
}

// TestZoneTransferData tests preparing data for zone transfers
func TestZoneTransferData(t *testing.T) {
	s := setupTestStorage(t)
	defer s.Close()

	ctx := context.Background()

	// Setup a complete zone
	zoneRecords := []records.DNSRecord{
		// SOA (must be first in zone transfer)
		records.NewSOARecord("example.com", "ns1.example.com", "admin.example.com",
			2024010101, 7200, 3600, 604800, 86400, 300),

		// NS records
		records.NewNSRecord("example.com", "ns1.example.com", 300),
		records.NewNSRecord("example.com", "ns2.example.com", 300),

		// A records
		mustCreateARecord(t, "example.com", "192.168.1.1", 300),
		mustCreateARecord(t, "www.example.com", "192.168.1.10", 300),
		mustCreateARecord(t, "mail.example.com", "192.168.1.20", 300),
		mustCreateARecord(t, "ns1.example.com", "192.168.1.53", 300),
		mustCreateARecord(t, "ns2.example.com", "192.168.1.54", 300),

		// MX records
		records.NewMXRecord("example.com", "mail.example.com", 10, 300),

		// CNAME records
		records.NewCNAMERecord("ftp.example.com", "www.example.com", 300),

		// TXT records
		records.NewTXTRecordFromString("example.com", "v=spf1 mx ~all", 300),
	}

	for _, r := range zoneRecords {
		require.NoError(t, s.PutRecord(ctx, r))
	}

	t.Run("full zone transfer (AXFR)", func(t *testing.T) {
		// Get all records for zone
		allRecords, err := s.ListRecordsByZone(ctx, "example.com")
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(allRecords), 11, "Should have all zone records")

		// Verify SOA exists
		hasSOA := false
		for _, r := range allRecords {
			if r.Type() == types.TYPE_SOA {
				hasSOA = true
				break
			}
		}
		assert.True(t, hasSOA, "Zone must have SOA record")
	})

	t.Run("incremental zone transfer preparation", func(t *testing.T) {
		// Get SOA for serial number
		soa, err := s.GetRecord(ctx, "example.com", types.TYPE_SOA)
		assert.NoError(t, err)

		soaRecord := soa.(*records.SOARecord)
		originalSerial := soaRecord.Serial()
		assert.Equal(t, uint32(2024010101), originalSerial)

		// Add new record (would trigger serial increment in real implementation)
		newRecord := mustCreateARecord(t, "new.example.com", "192.168.1.100", 300)
		require.NoError(t, s.PutRecord(ctx, newRecord))

		// In real implementation, SOA serial should be incremented
		// This is application logic, not storage responsibility
	})
}

// Helper function to setup test storage with common records
func setupTestStorage(t *testing.T) storage.Storage {
	s, err := storage.NewMemoryStorage(&storage.ValidationConfig{
		Enabled:         true,
		AllowUnderscore: false,
		MinTTL:          60,
		MaxTTL:          86400,
	})
	require.NoError(t, err)

	ctx := context.Background()

	// Add some basic test records
	baseRecords := []records.DNSRecord{
		mustCreateARecord(t, "example.com", "192.168.1.1", 300),
		mustCreateARecord(t, "www.example.com", "192.168.1.10", 300),
		mustCreateAAAARecord(t, "example.com", "2001:db8::1", 300),
		records.NewMXRecord("example.com", "mail.example.com", 10, 300),
		records.NewNSRecord("example.com", "ns1.example.com", 300),
	}

	for _, r := range baseRecords {
		require.NoError(t, s.PutRecord(ctx, r))
	}

	return s
}
