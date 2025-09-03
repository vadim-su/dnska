package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vadim-su/dnska/internal/storage"
	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
	"gopkg.in/yaml.v3"
)

// TestConfigLoadingAndStorageInit tests configuration loading and storage initialization
func TestConfigLoadingAndStorageInit(t *testing.T) {
	t.Run("memory storage configuration", func(t *testing.T) {
		config := &storage.StorageConfig{
			Type: storage.StorageTypeMemory,
			ValidationConfig: &storage.ValidationConfig{
				Enabled:         true,
				AllowUnderscore: true,
				MinTTL:          60,
				MaxTTL:          3600,
				AllowedTypes:    []string{"A", "AAAA", "CNAME", "MX"},
			},
		}

		ctx := context.Background()
		s, err := storage.NewStorage(ctx, config)
		assert.NoError(t, err)
		assert.NotNil(t, s)
		defer s.Close()

		// Test that configuration is applied
		// Try to add allowed record type
		aRecord := mustCreateARecord(t, "test.example.com", "192.168.1.1", 300)
		err = s.PutRecord(ctx, aRecord)
		assert.NoError(t, err)

		// Try to add disallowed record type
		txtRecord := records.NewTXTRecordFromString("test.example.com", "test", 300)
		err = s.PutRecord(ctx, txtRecord)
		assert.Error(t, err, "Should reject TXT record as it's not in allowed types")
		assert.Contains(t, err.Error(), "not allowed")
	})

	t.Run("storage configuration from YAML", func(t *testing.T) {
		yamlConfig := `
type: memory
validation:
  enabled: true
  allow_underscore: true
  min_ttl: 120
  max_ttl: 7200
  allowed_types:
    - A
    - AAAA
    - CNAME
`
		var config storage.StorageConfig
		err := yaml.Unmarshal([]byte(yamlConfig), &config)
		assert.NoError(t, err)
		assert.Equal(t, storage.StorageTypeMemory, config.Type)
		assert.True(t, config.ValidationConfig.Enabled)
		assert.True(t, config.ValidationConfig.AllowUnderscore)
		assert.Equal(t, uint32(120), config.ValidationConfig.MinTTL)
		assert.Equal(t, uint32(7200), config.ValidationConfig.MaxTTL)
		assert.Contains(t, config.ValidationConfig.AllowedTypes, "A")
		assert.Contains(t, config.ValidationConfig.AllowedTypes, "AAAA")
		assert.Contains(t, config.ValidationConfig.AllowedTypes, "CNAME")

		// Create storage from parsed config
		ctx := context.Background()
		s, err := storage.NewStorage(ctx, &config)
		assert.NoError(t, err)
		assert.NotNil(t, s)
		defer s.Close()
	})

	t.Run("validation config defaults", func(t *testing.T) {
		// Config without validation section should use defaults
		config := &storage.StorageConfig{
			Type: storage.StorageTypeMemory,
		}

		ctx := context.Background()
		s, err := storage.NewStorage(ctx, config)
		assert.NoError(t, err)
		assert.NotNil(t, s)
		defer s.Close()

		// Should have validation enabled by default
		// Try invalid domain
		err = s.PutRecord(ctx, &testRecord{
			name:       "invalid..domain",
			recordType: types.TYPE_A,
			ttl:        300,
			data:       []byte{192, 168, 1, 1},
		})
		assert.Error(t, err, "Should reject invalid domain with default validation")
	})

	t.Run("storage type selection", func(t *testing.T) {
		configs := []storage.StorageConfig{
			{
				Type: storage.StorageTypeMemory,
			},
			// SurrealDB config would go here if we want to test it
			// But it requires external database
		}

		ctx := context.Background()
		for _, config := range configs {
			s, err := storage.NewStorage(ctx, &config)
			if config.Type == storage.StorageTypeMemory {
				assert.NoError(t, err)
				assert.NotNil(t, s)
				s.Close()
			}
		}
	})
}

// TestZoneFileLoading tests loading DNS records from zone files
func TestZoneFileLoading(t *testing.T) {
	// Create temporary directory for test files
	tempDir := t.TempDir()

	t.Run("load single zone file", func(t *testing.T) {
		// Create a simple zone file
		zoneContent := `
; Zone file for example.com
$ORIGIN example.com.
$TTL 3600

@       IN      SOA     ns1.example.com. admin.example.com. (
                        2024010101 ; serial
                        7200       ; refresh
                        3600       ; retry
                        604800     ; expire
                        86400 )    ; minimum

@       IN      NS      ns1.example.com.
@       IN      NS      ns2.example.com.

@       IN      A       192.168.1.1
www     IN      A       192.168.1.10
mail    IN      A       192.168.1.20
ns1     IN      A       192.168.1.53
ns2     IN      A       192.168.1.54

@       IN      MX      10 mail.example.com.
@       IN      TXT     "v=spf1 mx ~all"
`
		zoneFile := filepath.Join(tempDir, "example.com.zone")
		err := os.WriteFile(zoneFile, []byte(zoneContent), 0644)
		require.NoError(t, err)

		// This would be the zone loader implementation
		// For now, we'll simulate it
		s, err := storage.NewMemoryStorage(&storage.ValidationConfig{
			Enabled: true,
		})
		require.NoError(t, err)
		defer s.Close()

		// In real implementation, a zone file parser would read the file
		// and populate storage
	})

	t.Run("load multiple zone files", func(t *testing.T) {
		// Create multiple zone files
		zones := map[string]string{
			"example.com": `
$ORIGIN example.com.
$TTL 300
@       IN      A       192.168.1.1
www     IN      A       192.168.1.10
`,
			"example.org": `
$ORIGIN example.org.
$TTL 300
@       IN      A       192.168.2.1
www     IN      A       192.168.2.10
`,
		}

		for domain, content := range zones {
			zoneFile := filepath.Join(tempDir, domain+".zone")
			err := os.WriteFile(zoneFile, []byte(content), 0644)
			require.NoError(t, err)
		}

		// Load all zone files
		zoneFiles, err := filepath.Glob(filepath.Join(tempDir, "*.zone"))
		assert.NoError(t, err)
		assert.Len(t, zoneFiles, 2, "Should find both zone files")
	})

	t.Run("handle invalid zone file", func(t *testing.T) {
		// Create an invalid zone file
		invalidContent := `
This is not a valid zone file
Random content here
`
		invalidFile := filepath.Join(tempDir, "invalid.zone")
		err := os.WriteFile(invalidFile, []byte(invalidContent), 0644)
		require.NoError(t, err)

		// Zone loader should reject invalid files
		// Implementation would return error
	})

	t.Run("zone file reload", func(t *testing.T) {
		zoneFile := filepath.Join(tempDir, "dynamic.zone")

		// Initial content
		initialContent := `
$ORIGIN dynamic.com.
$TTL 300
@       IN      A       192.168.1.1
`
		err := os.WriteFile(zoneFile, []byte(initialContent), 0644)
		require.NoError(t, err)

		// Simulate loading
		s, err := storage.NewMemoryStorage(&storage.ValidationConfig{
			Enabled: true,
		})
		require.NoError(t, err)
		defer s.Close()

		ctx := context.Background()

		// Add initial record
		record1 := mustCreateARecord(t, "dynamic.com", "192.168.1.1", 300)
		require.NoError(t, s.PutRecord(ctx, record1))

		// Update zone file
		updatedContent := `
$ORIGIN dynamic.com.
$TTL 300
@       IN      A       192.168.1.1
www     IN      A       192.168.1.2
`
		err = os.WriteFile(zoneFile, []byte(updatedContent), 0644)
		require.NoError(t, err)

		// Simulate reload - would need to:
		// 1. Parse new file
		// 2. Diff with existing records
		// 3. Update storage
		// 4. Not lose runtime updates

		// Add the new record manually for now
		record2 := mustCreateARecord(t, "www.dynamic.com", "192.168.1.2", 300)
		require.NoError(t, s.PutRecord(ctx, record2))

		// Verify both records exist
		records, err := s.ListRecordsByZone(ctx, "dynamic.com")
		assert.NoError(t, err)
		assert.Len(t, records, 2)
	})
}

// TestConfigReload tests configuration reload without service interruption
func TestConfigReload(t *testing.T) {
	t.Run("storage config reload", func(t *testing.T) {
		// Start with initial config
		initialConfig := &storage.StorageConfig{
			Type: storage.StorageTypeMemory,
			ValidationConfig: &storage.ValidationConfig{
				Enabled: true,
				MinTTL:  60,
				MaxTTL:  3600,
			},
		}

		ctx := context.Background()
		s1, err := storage.NewStorage(ctx, initialConfig)
		require.NoError(t, err)

		// Add some records
		record := mustCreateARecord(t, "test.example.com", "192.168.1.1", 300)
		require.NoError(t, s1.PutRecord(ctx, record))

		// Close first storage
		s1.Close()

		// Create new storage with updated config
		updatedConfig := &storage.StorageConfig{
			Type: storage.StorageTypeMemory,
			ValidationConfig: &storage.ValidationConfig{
				Enabled: true,
				MinTTL:  120,  // Changed
				MaxTTL:  7200, // Changed
			},
		}

		s2, err := storage.NewStorage(ctx, updatedConfig)
		require.NoError(t, err)
		defer s2.Close()

		// New storage starts empty (data not persisted in memory storage)
		records, err := s2.ListRecords(ctx)
		assert.NoError(t, err)
		assert.Len(t, records, 0)

		// Test new validation rules
		shortTTLRecord := mustCreateARecord(t, "test.example.com", "192.168.1.1", 60)
		err = s2.PutRecord(ctx, shortTTLRecord)
		assert.Error(t, err, "Should reject TTL below new minimum")
	})

	t.Run("validation rules update", func(t *testing.T) {
		ctx := context.Background()

		// Start with strict validation
		strictConfig := &storage.StorageConfig{
			Type: storage.StorageTypeMemory,
			ValidationConfig: &storage.ValidationConfig{
				Enabled:      true,
				AllowedTypes: []string{"A", "AAAA"},
			},
		}

		s1, err := storage.NewStorage(ctx, strictConfig)
		require.NoError(t, err)

		// Can't add MX record
		mxRecord := records.NewMXRecord("example.com", "mail.example.com", 10, 300)
		err = s1.PutRecord(ctx, mxRecord)
		assert.Error(t, err)

		s1.Close()

		// Reload with relaxed validation
		relaxedConfig := &storage.StorageConfig{
			Type: storage.StorageTypeMemory,
			ValidationConfig: &storage.ValidationConfig{
				Enabled: true,
				// No AllowedTypes restriction
			},
		}

		s2, err := storage.NewStorage(ctx, relaxedConfig)
		require.NoError(t, err)
		defer s2.Close()

		// Now can add MX record
		err = s2.PutRecord(ctx, mxRecord)
		assert.NoError(t, err)
	})
}

// TestMultiStorageBackends tests switching between different storage backends
func TestMultiStorageBackends(t *testing.T) {
	t.Run("migrate from memory to memory", func(t *testing.T) {
		ctx := context.Background()

		// Create source storage
		source, err := storage.NewMemoryStorage(&storage.ValidationConfig{
			Enabled: true,
		})
		require.NoError(t, err)

		// Add test data
		testRecords := []records.DNSRecord{
			mustCreateARecord(t, "example.com", "192.168.1.1", 300),
			mustCreateAAAARecord(t, "example.com", "2001:db8::1", 300),
			records.NewMXRecord("example.com", "mail.example.com", 10, 300),
			records.NewCNAMERecord("www.example.com", "example.com", 300),
		}

		for _, r := range testRecords {
			require.NoError(t, source.PutRecord(ctx, r))
		}

		// Create destination storage
		dest, err := storage.NewMemoryStorage(&storage.ValidationConfig{
			Enabled: true,
		})
		require.NoError(t, err)
		defer dest.Close()

		// Migrate data
		allRecords, err := source.ListRecords(ctx)
		assert.NoError(t, err)

		for _, record := range allRecords {
			err := dest.PutRecord(ctx, record)
			assert.NoError(t, err)
		}

		source.Close()

		// Verify migration
		migratedRecords, err := dest.ListRecords(ctx)
		assert.NoError(t, err)
		assert.Len(t, migratedRecords, len(testRecords))

		// Verify specific records
		aRecord, err := dest.GetRecord(ctx, "example.com", types.TYPE_A)
		assert.NoError(t, err)
		assert.Equal(t, "192.168.1.1", aRecord.(*records.ARecord).IP().String())
	})

	t.Run("storage backend compatibility", func(t *testing.T) {
		ctx := context.Background()

		// Test that different storage backends support the same interface
		configs := []storage.StorageConfig{
			{
				Type: storage.StorageTypeMemory,
				ValidationConfig: &storage.ValidationConfig{
					Enabled: true,
				},
			},
			// Add other storage types here when available
		}

		for _, config := range configs {
			s, err := storage.NewStorage(ctx, &config)
			if err != nil {
				continue // Skip unavailable backends
			}

			// All backends should support basic operations
			testRecord := mustCreateARecord(t, "test.example.com", "192.168.1.1", 300)

			// Put
			err = s.PutRecord(ctx, testRecord)
			assert.NoError(t, err)

			// Get
			retrieved, err := s.GetRecord(ctx, "test.example.com", types.TYPE_A)
			assert.NoError(t, err)
			assert.NotNil(t, retrieved)

			// List
			records, err := s.ListRecords(ctx)
			assert.NoError(t, err)
			assert.NotEmpty(t, records)

			// Delete
			err = s.DeleteRecord(ctx, "test.example.com", types.TYPE_A)
			assert.NoError(t, err)

			s.Close()
		}
	})
}
