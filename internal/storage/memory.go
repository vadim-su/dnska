package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// MemoryStorage implements the Storage interface using in-memory storage
type MemoryStorage struct {
	mu        sync.RWMutex
	records   map[string]map[types.DNSType][]records.DNSRecord // name -> type -> records
	zones     map[string]bool                                  // set of zones
	validator *Validator
	converter *RecordConverter
	closed    bool
	stats     StorageStats
}

// NewMemoryStorage creates a new in-memory storage instance with validation
func NewMemoryStorage(validationConfig *ValidationConfig) (*MemoryStorage, error) {
	return &MemoryStorage{
		records:   make(map[string]map[types.DNSType][]records.DNSRecord),
		zones:     make(map[string]bool),
		validator: NewValidator(validationConfig),
		converter: NewRecordConverter(),
	}, nil
}

// GetRecords returns all records for a given domain name and record type
// normalizeDomainName ensures the domain name has a trailing dot
func normalizeDomainName(name string) string {
	name = strings.ToLower(name)
	if name != "" && name[len(name)-1] != '.' {
		name = name + "."
	}
	return name
}

func (s *MemoryStorage) GetRecords(ctx context.Context, name string, recordType types.DNSType) ([]records.DNSRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	// Validate input
	if err := s.validator.ValidateName(name); err != nil {
		return nil, err
	}

	name = normalizeDomainName(name)

	nameRecords, exists := s.records[name]
	if !exists {
		return []records.DNSRecord{}, nil
	}

	if recordType == 0 {
		// Return all record types
		var allRecords []records.DNSRecord
		for _, typeRecords := range nameRecords {
			allRecords = append(allRecords, typeRecords...)
		}
		return allRecords, nil
	}

	typeRecords, exists := nameRecords[recordType]
	if !exists {
		return []records.DNSRecord{}, nil
	}

	// Return a copy to prevent external modifications
	result := make([]records.DNSRecord, len(typeRecords))
	copy(result, typeRecords)
	return result, nil
}

// GetRecord returns a single record for a given domain name and record type
func (s *MemoryStorage) GetRecord(ctx context.Context, name string, recordType types.DNSType) (records.DNSRecord, error) {
	records, err := s.GetRecords(ctx, name, recordType)
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, ErrRecordNotFound
	}

	return records[0], nil
}

// PutRecord stores or updates a DNS record with validation
func (s *MemoryStorage) PutRecord(ctx context.Context, record records.DNSRecord) error {
	// Validate record first
	if err := s.validator.ValidateRecord(record); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	name := strings.ToLower(record.Name())

	// Initialize maps if they don't exist
	if s.records[name] == nil {
		s.records[name] = make(map[types.DNSType][]records.DNSRecord)
	}

	recordType := record.Type()
	typeRecords := s.records[name][recordType]

	// Check if record already exists (update vs insert)
	updated := false
	for i, existingRecord := range typeRecords {
		if s.recordsMatch(existingRecord, record) {
			// Update existing record
			typeRecords[i] = record
			updated = true
			break
		}
	}

	if !updated {
		// Add new record
		s.records[name][recordType] = append(typeRecords, record)
		s.stats.TotalRecords++
	}

	// Update zones
	s.updateZones(name)
	s.stats.LastUpdated = time.Now().Unix()

	return nil
}

// DeleteRecord removes a DNS record
func (s *MemoryStorage) DeleteRecord(ctx context.Context, name string, recordType types.DNSType) error {
	// Validate input
	if err := s.validator.ValidateName(name); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	name = normalizeDomainName(name)

	nameRecords, exists := s.records[name]
	if !exists {
		return ErrRecordNotFound
	}

	if recordType == 0 {
		// Delete all records for this name
		for _, typeRecords := range nameRecords {
			s.stats.TotalRecords -= len(typeRecords)
		}
		delete(s.records, name)
		s.updateZonesOnDelete(name)
		s.stats.LastUpdated = time.Now().Unix()
		return nil
	}

	typeRecords, exists := nameRecords[recordType]
	if !exists || len(typeRecords) == 0 {
		return ErrRecordNotFound
	}

	// Remove all records of this type
	s.stats.TotalRecords -= len(typeRecords)
	delete(nameRecords, recordType)

	// If no records left for this name, remove the name entry
	if len(nameRecords) == 0 {
		delete(s.records, name)
		s.updateZonesOnDelete(name)
	}

	s.stats.LastUpdated = time.Now().Unix()
	return nil
}

// ListRecords returns all records in the storage
func (s *MemoryStorage) ListRecords(ctx context.Context) ([]records.DNSRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	allRecords := make([]records.DNSRecord, 0)
	for _, nameRecords := range s.records {
		for _, typeRecords := range nameRecords {
			allRecords = append(allRecords, typeRecords...)
		}
	}

	return allRecords, nil
}

// ListRecordsByZone returns all records for a specific zone
func (s *MemoryStorage) ListRecordsByZone(ctx context.Context, zone string) ([]records.DNSRecord, error) {
	// Validate zone
	if err := s.validator.ValidateZone(zone); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	zone = normalizeDomainName(zone)
	var zoneRecords []records.DNSRecord

	for name, nameRecords := range s.records {
		if s.isInZone(name, zone) {
			for _, typeRecords := range nameRecords {
				zoneRecords = append(zoneRecords, typeRecords...)
			}
		}
	}

	return zoneRecords, nil
}

// GetZones returns all available zones
func (s *MemoryStorage) GetZones(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	zones := make([]string, 0, len(s.zones))
	for zone := range s.zones {
		zones = append(zones, zone)
	}

	sort.Strings(zones)
	return zones, nil
}

// QueryRecords performs a filtered query with optional pagination
func (s *MemoryStorage) QueryRecords(ctx context.Context, options QueryOptions) ([]records.DNSRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	// Collect matching records
	var results []records.DNSRecord

	// Normalize query options
	queryName := options.Name
	if queryName != "" {
		queryName = normalizeDomainName(queryName)
	}
	queryPrefix := options.NamePrefix
	if queryPrefix != "" {
		queryPrefix = normalizeDomainName(queryPrefix)
	}
	queryZone := options.Zone
	if queryZone != "" {
		queryZone = normalizeDomainName(queryZone)
	}

	for name, nameRecords := range s.records {
		// Apply name filters
		if queryName != "" && !strings.EqualFold(name, queryName) {
			continue
		}
		if queryPrefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(queryPrefix)) {
			continue
		}
		if queryZone != "" && !s.isInZone(name, queryZone) {
			continue
		}

		// Collect records by type
		for recordType, typeRecords := range nameRecords {
			if options.RecordType != 0 && recordType != options.RecordType {
				continue
			}
			results = append(results, typeRecords...)
		}
	}

	// Sort results
	s.sortRecords(results, options.SortBy, options.SortOrder)

	// Apply pagination
	if options.Offset > 0 {
		if options.Offset >= len(results) {
			return []records.DNSRecord{}, nil
		}
		results = results[options.Offset:]
	}

	if options.Limit > 0 && options.Limit < len(results) {
		results = results[:options.Limit]
	}

	return results, nil
}

// BatchPutRecords stores multiple records in a single operation
func (s *MemoryStorage) BatchPutRecords(ctx context.Context, recordList []records.DNSRecord) error {
	if len(recordList) == 0 {
		return nil
	}

	// Validate all records first
	if errs := s.validator.ValidateBatch(recordList); len(errs) > 0 {
		return fmt.Errorf("validation failed: %v", errs[0])
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	// Store all records
	for _, record := range recordList {
		name := strings.ToLower(record.Name())

		if s.records[name] == nil {
			s.records[name] = make(map[types.DNSType][]records.DNSRecord)
		}

		recordType := record.Type()
		s.records[name][recordType] = append(s.records[name][recordType], record)
		s.updateZones(name)
		s.stats.TotalRecords++
	}

	s.stats.LastUpdated = time.Now().Unix()
	return nil
}

// BatchDeleteRecords deletes multiple records in a single operation
func (s *MemoryStorage) BatchDeleteRecords(ctx context.Context, names []string, recordType types.DNSType) error {
	if len(names) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return ErrStorageClosed
	}

	deletedCount := 0
	for _, name := range names {
		name = normalizeDomainName(name)

		if nameRecords, exists := s.records[name]; exists {
			if recordType == 0 {
				// Delete all records for this name
				for _, typeRecords := range nameRecords {
					deletedCount += len(typeRecords)
				}
				delete(s.records, name)
				s.updateZonesOnDelete(name)
			} else if typeRecords, exists := nameRecords[recordType]; exists {
				deletedCount += len(typeRecords)
				delete(nameRecords, recordType)

				if len(nameRecords) == 0 {
					delete(s.records, name)
					s.updateZonesOnDelete(name)
				}
			}
		}
	}

	if deletedCount > 0 {
		s.stats.TotalRecords -= deletedCount
		s.stats.LastUpdated = time.Now().Unix()
	}

	return nil
}

// Close closes the storage connection and cleans up resources
func (s *MemoryStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.records = make(map[string]map[types.DNSType][]records.DNSRecord)
	s.zones = make(map[string]bool)
	s.closed = true

	return nil
}

// GetStats returns storage statistics
func (s *MemoryStorage) GetStats(ctx context.Context) (*StorageStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, ErrStorageClosed
	}

	stats := s.stats
	stats.TotalZones = len(s.zones)

	// Count records by type
	stats.RecordTypes = make(map[string]int)
	for _, nameRecords := range s.records {
		for recordType, typeRecords := range nameRecords {
			stats.RecordTypes[recordType.String()] += len(typeRecords)
		}
	}

	return &stats, nil
}

// Helper methods

// recordsMatch checks if two records match for update purposes
func (s *MemoryStorage) recordsMatch(r1, r2 records.DNSRecord) bool {
	// Match by name, type, and data content
	// This allows multiple records of the same type with different data
	if !strings.EqualFold(r1.Name(), r2.Name()) || r1.Type() != r2.Type() {
		return false
	}

	// Compare the actual data
	data1 := r1.Data()
	data2 := r2.Data()

	if len(data1) != len(data2) {
		return false
	}

	for i := range data1 {
		if data1[i] != data2[i] {
			return false
		}
	}

	return true
}

// isInZone checks if a name belongs to a zone
func (s *MemoryStorage) isInZone(name, zone string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// updateZones updates the zones map based on record names
func (s *MemoryStorage) updateZones(name string) {
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := len(parts) - 1; i >= 0; i-- {
		zone := strings.Join(parts[i:], ".")
		if zone != "" {
			s.zones[zone] = true
		}
	}
}

// updateZonesOnDelete removes zones that no longer have records
func (s *MemoryStorage) updateZonesOnDelete(deletedName string) {
	// Rebuild zones from remaining records
	s.zones = make(map[string]bool)
	for name := range s.records {
		s.updateZones(name)
	}
}

// sortRecords sorts records based on the specified field and order
func (s *MemoryStorage) sortRecords(records []records.DNSRecord, sortBy, sortOrder string) {
	sort.Slice(records, func(i, j int) bool {
		var less bool

		switch sortBy {
		case "type":
			less = records[i].Type() < records[j].Type()
		case "ttl":
			less = records[i].TTL() < records[j].TTL()
		default: // "name" or empty
			less = strings.Compare(records[i].Name(), records[j].Name()) < 0
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})
}

// String returns a string representation of the storage for debugging
func (s *MemoryStorage) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("MemoryStorage{records:%d, zones:%d, closed:%v}\n",
		s.stats.TotalRecords, len(s.zones), s.closed))

	for name, nameRecords := range s.records {
		sb.WriteString(fmt.Sprintf("  %s:\n", name))
		for recordType, typeRecords := range nameRecords {
			sb.WriteString(fmt.Sprintf("    %s: %d records\n", recordType.String(), len(typeRecords)))
		}
	}

	return sb.String()
}

// Ensure MemoryStorage implements Storage interface
var _ Storage = (*MemoryStorage)(nil)
var _ StorageWithStats = (*MemoryStorage)(nil)
