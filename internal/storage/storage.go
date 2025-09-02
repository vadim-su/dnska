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
)

// Storage defines the interface for DNS record storage backends
type Storage interface {
	// GetRecords returns all records for a given domain name and record type
	// If recordType is 0, returns all record types
	GetRecords(ctx context.Context, name string, recordType types.DNSType) ([]records.DNSRecord, error)

	// GetRecord returns a single record for a given domain name and record type
	GetRecord(ctx context.Context, name string, recordType types.DNSType) (records.DNSRecord, error)

	// PutRecord stores or updates a DNS record
	PutRecord(ctx context.Context, record records.DNSRecord) error

	// DeleteRecord removes a DNS record
	DeleteRecord(ctx context.Context, name string, recordType types.DNSType) error

	// ListRecords returns all records in the storage
	ListRecords(ctx context.Context) ([]records.DNSRecord, error)

	// ListRecordsByZone returns all records for a specific zone
	ListRecordsByZone(ctx context.Context, zone string) ([]records.DNSRecord, error)

	// GetZones returns all available zones
	GetZones(ctx context.Context) ([]string, error)

	// Close closes the storage connection and cleans up resources
	Close() error
}

// RecordFilter defines criteria for filtering records
type RecordFilter struct {
	Name       string         // Domain name filter
	RecordType types.DNSType  // Record type filter (0 = all types)
	Class      types.DNSClass // DNS class filter (0 = all classes)
	Zone       string         // Zone filter
}

// QueryOptions defines options for record queries
type QueryOptions struct {
	Filter *RecordFilter // Filter criteria
	Limit  int           // Maximum number of records to return (0 = no limit)
	Offset int           // Number of records to skip
}

// AdvancedStorage extends the basic Storage interface with advanced query capabilities
type AdvancedStorage interface {
	Storage

	// QueryRecords performs an advanced query with filtering and pagination
	QueryRecords(ctx context.Context, options *QueryOptions) ([]records.DNSRecord, error)

	// BatchPutRecords stores multiple records in a single operation
	BatchPutRecords(ctx context.Context, records []records.DNSRecord) error

	// BatchDeleteRecords deletes multiple records in a single operation
	BatchDeleteRecords(ctx context.Context, names []string, recordType types.DNSType) error

	// GetRecordCount returns the total number of records matching the filter
	GetRecordCount(ctx context.Context, filter *RecordFilter) (int, error)
}
