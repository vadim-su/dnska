package storage

import (
	"context"
	"errors"

	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

var (
	// ErrRecordNotFound is returned when a record is not found
	ErrRecordNotFound = errors.New("record not found")
	// ErrRecordExists is returned when trying to create a record that already exists
	ErrRecordExists = errors.New("record already exists")
	// ErrInvalidRecord is returned when a record is invalid
	ErrInvalidRecord = errors.New("invalid record")
	// ErrInvalidName is returned when a domain name is invalid
	ErrInvalidName = errors.New("invalid domain name")
	// ErrInvalidZone is returned when a zone name is invalid
	ErrInvalidZone = errors.New("invalid zone name")
	// ErrInvalidTTL is returned when a TTL value is invalid
	ErrInvalidTTL = errors.New("invalid TTL value")
	// ErrStorageClosed is returned when operations are attempted on closed storage
	ErrStorageClosed = errors.New("storage is closed")
)

// Storage defines the unified interface for DNS record storage
// All implementations must validate records before storing them
type Storage interface {
	// Core CRUD operations

	// GetRecords returns all records for a given domain name and record type
	// If recordType is 0, returns all record types
	GetRecords(ctx context.Context, name string, recordType types.DNSType) ([]records.DNSRecord, error)

	// GetRecord returns a single record for a given domain name and record type
	GetRecord(ctx context.Context, name string, recordType types.DNSType) (records.DNSRecord, error)

	// PutRecord stores or updates a DNS record
	// Implementation MUST validate the record before storage
	PutRecord(ctx context.Context, record records.DNSRecord) error

	// DeleteRecord removes a DNS record
	// If recordType is 0, deletes all records for the name
	DeleteRecord(ctx context.Context, name string, recordType types.DNSType) error

	// Query operations

	// ListRecords returns all records in the storage
	ListRecords(ctx context.Context) ([]records.DNSRecord, error)

	// ListRecordsByZone returns all records for a specific zone
	ListRecordsByZone(ctx context.Context, zone string) ([]records.DNSRecord, error)

	// GetZones returns all available zones
	GetZones(ctx context.Context) ([]string, error)

	// QueryRecords performs a filtered query with optional pagination
	QueryRecords(ctx context.Context, options QueryOptions) ([]records.DNSRecord, error)

	// Batch operations

	// BatchPutRecords stores multiple records in a single operation
	// All records are validated before any are stored (atomic operation)
	BatchPutRecords(ctx context.Context, records []records.DNSRecord) error

	// BatchDeleteRecords deletes multiple records in a single operation
	BatchDeleteRecords(ctx context.Context, names []string, recordType types.DNSType) error

	// Lifecycle

	// Close closes the storage connection and cleans up resources
	Close() error
}

// QueryOptions defines options for record queries
type QueryOptions struct {
	// Filter criteria
	Name       string        // Domain name filter (exact match)
	NamePrefix string        // Domain name prefix filter
	RecordType types.DNSType // Record type filter (0 = all types)
	Zone       string        // Zone filter

	// Pagination
	Limit  int // Maximum number of records to return (0 = no limit)
	Offset int // Number of records to skip

	// Sorting
	SortBy    string // Field to sort by: "name", "type", "ttl"
	SortOrder string // Sort order: "asc" or "desc"
}

// StorageType represents the type of storage backend
type StorageType string

const (
	// StorageTypeMemory represents in-memory storage
	StorageTypeMemory StorageType = "memory"
	// StorageTypeSurrealDB represents SurrealDB storage
	StorageTypeSurrealDB StorageType = "surrealdb"
)

// StorageConfig holds configuration for storage backends
type StorageConfig struct {
	Type             StorageType    `yaml:"type" json:"type"`
	ConnectionString string         `yaml:"connection_string,omitempty" json:"connection_string,omitempty"`
	Options          map[string]any `yaml:"options,omitempty" json:"options,omitempty"`

	// Validation configuration
	ValidationConfig *ValidationConfig `yaml:"validation,omitempty" json:"validation,omitempty"`
}

// ValidationConfig holds validation configuration
type ValidationConfig struct {
	// Enable strict validation (default: true)
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Allow underscore in domain names (for DKIM, SRV records)
	AllowUnderscore bool `yaml:"allow_underscore" json:"allow_underscore"`

	// TTL limits (0 means use defaults)
	MinTTL uint32 `yaml:"min_ttl,omitempty" json:"min_ttl,omitempty"`
	MaxTTL uint32 `yaml:"max_ttl,omitempty" json:"max_ttl,omitempty"`

	// Allowed record types (empty means all types allowed)
	AllowedTypes []string `yaml:"allowed_types,omitempty" json:"allowed_types,omitempty"`
}

// NewStorage creates a new storage instance based on the provided configuration
func NewStorage(ctx context.Context, config *StorageConfig) (Storage, error) {
	if config == nil {
		return nil, errors.New("storage config is required")
	}

	// Set validation defaults if not specified
	if config.ValidationConfig == nil {
		config.ValidationConfig = &ValidationConfig{
			Enabled: true,
		}
	}

	switch config.Type {
	case StorageTypeMemory:
		return NewMemoryStorage(config.ValidationConfig)
	case StorageTypeSurrealDB:
		return NewSurrealDBStorage(ctx, config)
	default:
		return nil, errors.New("unsupported storage type: " + string(config.Type))
	}
}

// StorageStats represents storage statistics
type StorageStats struct {
	TotalRecords int            // Total number of records
	TotalZones   int            // Total number of zones
	RecordTypes  map[string]int // Count by record type
	LastUpdated  int64          // Unix timestamp of last update
}

// StorageWithStats extends Storage with statistics capabilities
type StorageWithStats interface {
	Storage

	// GetStats returns storage statistics
	GetStats(ctx context.Context) (*StorageStats, error)
}
