package storage

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// MemoryStorage implements the Storage interface using in-memory storage
type MemoryStorage struct {
	mu      sync.RWMutex
	records map[string]map[types.DNSType][]records.DNSRecord // name -> type -> records
	zones   map[string]bool                                  // set of zones
}

// NewMemoryStorage creates a new in-memory storage instance
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		records: make(map[string]map[types.DNSType][]records.DNSRecord),
		zones:   make(map[string]bool),
	}
}

// GetRecords returns all records for a given domain name and record type
func (s *MemoryStorage) GetRecords(ctx context.Context, name string, recordType types.DNSType) ([]records.DNSRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	name = strings.ToLower(name)

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

// PutRecord stores or updates a DNS record
func (s *MemoryStorage) PutRecord(ctx context.Context, record records.DNSRecord) error {
	if record == nil {
		return ErrInvalidRecord
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	name := strings.ToLower(record.Name())

	// Initialize maps if they don't exist
	if s.records[name] == nil {
		s.records[name] = make(map[types.DNSType][]records.DNSRecord)
	}

	recordType := record.Type()
	typeRecords := s.records[name][recordType]

	// Check if record already exists (by name and type)
	for i, existingRecord := range typeRecords {
		if existingRecord.Name() == record.Name() && existingRecord.Type() == record.Type() {
			// Update existing record
			typeRecords[i] = record
			return nil
		}
	}

	// Add new record
	s.records[name][recordType] = append(typeRecords, record)

	// Update zones
	s.updateZones(name)

	return nil
}

// DeleteRecord removes a DNS record
func (s *MemoryStorage) DeleteRecord(ctx context.Context, name string, recordType types.DNSType) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = strings.ToLower(name)

	nameRecords, exists := s.records[name]
	if !exists {
		return ErrRecordNotFound
	}

	if recordType == 0 {
		// Delete all records for this name
		delete(s.records, name)
		s.updateZonesOnDelete(name)
		return nil
	}

	typeRecords, exists := nameRecords[recordType]
	if !exists || len(typeRecords) == 0 {
		return ErrRecordNotFound
	}

	// Remove all records of this type
	delete(nameRecords, recordType)

	// If no records left for this name, remove the name entry
	if len(nameRecords) == 0 {
		delete(s.records, name)
		s.updateZonesOnDelete(name)
	}

	return nil
}

// ListRecords returns all records in the storage
func (s *MemoryStorage) ListRecords(ctx context.Context) ([]records.DNSRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var allRecords []records.DNSRecord
	for _, nameRecords := range s.records {
		for _, typeRecords := range nameRecords {
			allRecords = append(allRecords, typeRecords...)
		}
	}

	return allRecords, nil
}

// ListRecordsByZone returns all records for a specific zone
func (s *MemoryStorage) ListRecordsByZone(ctx context.Context, zone string) ([]records.DNSRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	zone = strings.ToLower(zone)
	var zoneRecords []records.DNSRecord

	for name, nameRecords := range s.records {
		if strings.HasSuffix(name, "."+zone) || name == zone {
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

	zones := make([]string, 0, len(s.zones))
	for zone := range s.zones {
		zones = append(zones, zone)
	}

	return zones, nil
}

// Close closes the storage connection and cleans up resources
func (s *MemoryStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = make(map[string]map[types.DNSType][]records.DNSRecord)
	s.zones = make(map[string]bool)

	return nil
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

// String returns a string representation of the storage for debugging
func (s *MemoryStorage) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("MemoryStorage{records:%d, zones:%d}\n", len(s.records), len(s.zones)))

	for name, nameRecords := range s.records {
		sb.WriteString(fmt.Sprintf("  %s:\n", name))
		for recordType, typeRecords := range nameRecords {
			sb.WriteString(fmt.Sprintf("    %s: %d records\n", recordType.String(), len(typeRecords)))
		}
	}

	return sb.String()
}
