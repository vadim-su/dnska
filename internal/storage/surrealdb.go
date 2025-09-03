package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	surrealdb "github.com/surrealdb/surrealdb.go"
	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// SurrealDBStorage implements the Storage interface using SurrealDB as the backend
type SurrealDBStorage struct {
	db        *surrealdb.DB
	validator *Validator
	converter *RecordConverter
	config    *SurrealDBConfig
	closed    bool
}

// SurrealDBConfig holds configuration for SurrealDB connection
type SurrealDBConfig struct {
	// EndpointURL is the SurrealDB connection URL (ws://... or http://...)
	EndpointURL string
	// Namespace for the SurrealDB instance
	Namespace string
	// Database name within the namespace
	Database string
	// Authentication credentials
	Username string
	Password string
	// Optional: Access method for record-based authentication
	Access string
	// Validation configuration
	ValidationConfig *ValidationConfig
}

// NewSurrealDBStorage creates a new SurrealDB storage instance from configuration
func NewSurrealDBStorage(ctx context.Context, config *StorageConfig) (*SurrealDBStorage, error) {
	if config == nil {
		return nil, fmt.Errorf("storage config is required")
	}

	// Parse SurrealDB specific configuration
	surrealConfig := &SurrealDBConfig{
		EndpointURL:      config.ConnectionString,
		ValidationConfig: config.ValidationConfig,
	}

	// Extract configuration from options if available
	if config.Options != nil {
		if namespace, ok := config.Options["namespace"].(string); ok {
			surrealConfig.Namespace = namespace
		}
		if database, ok := config.Options["database"].(string); ok {
			surrealConfig.Database = database
		}
		if username, ok := config.Options["username"].(string); ok {
			surrealConfig.Username = username
		}
		if password, ok := config.Options["password"].(string); ok {
			surrealConfig.Password = password
		}
		if access, ok := config.Options["access"].(string); ok {
			surrealConfig.Access = access
		}
	}

	// Set defaults if not provided
	if surrealConfig.Namespace == "" {
		surrealConfig.Namespace = "dns"
	}
	if surrealConfig.Database == "" {
		surrealConfig.Database = "records"
	}

	return NewSurrealDBStorageWithConfig(ctx, surrealConfig)
}

// NewSurrealDBStorageWithConfig creates a new SurrealDB storage instance with specific config
func NewSurrealDBStorageWithConfig(ctx context.Context, config *SurrealDBConfig) (*SurrealDBStorage, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	db, err := surrealdb.FromEndpointURLString(ctx, config.EndpointURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SurrealDB: %w", err)
	}

	// Set namespace and database
	if err := db.Use(ctx, config.Namespace, config.Database); err != nil {
		db.Close(ctx)
		return nil, fmt.Errorf("failed to use namespace/database: %w", err)
	}

	// Authenticate if credentials are provided
	if config.Username != "" && config.Password != "" {
		auth := surrealdb.Auth{
			Namespace: config.Namespace,
			Database:  config.Database,
			Username:  config.Username,
			Password:  config.Password,
		}

		if config.Access != "" {
			auth.Access = config.Access
		}

		if _, err := db.SignIn(ctx, auth); err != nil {
			db.Close(ctx)
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}

	storage := &SurrealDBStorage{
		db:        db,
		validator: NewValidator(config.ValidationConfig),
		converter: NewRecordConverter(),
		config:    config,
	}

	// Initialize the schema
	if err := storage.initSchema(ctx); err != nil {
		db.Close(ctx)
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return storage, nil
}

// initSchema creates the necessary tables and indexes for DNS records
func (s *SurrealDBStorage) initSchema(ctx context.Context) error {
	schemaQueries := []string{
		// Define the dns_records table
		`DEFINE TABLE IF NOT EXISTS dns_records SCHEMAFULL;`,

		// Define fields for DNS records
		`DEFINE FIELD IF NOT EXISTS name ON dns_records TYPE string;`,
		`DEFINE FIELD IF NOT EXISTS record_type ON dns_records TYPE int;`,
		`DEFINE FIELD IF NOT EXISTS class ON dns_records TYPE int;`,
		`DEFINE FIELD IF NOT EXISTS ttl ON dns_records TYPE int;`,
		`DEFINE FIELD IF NOT EXISTS data ON dns_records TYPE string;`,
		`DEFINE FIELD IF NOT EXISTS zone ON dns_records TYPE string;`,
		`DEFINE FIELD IF NOT EXISTS created_at ON dns_records TYPE datetime DEFAULT time::now();`,
		`DEFINE FIELD IF NOT EXISTS updated_at ON dns_records TYPE datetime DEFAULT time::now();`,

		// Define indexes for efficient querying
		`DEFINE INDEX IF NOT EXISTS name_type_idx ON dns_records FIELDS name, record_type UNIQUE;`,
		`DEFINE INDEX IF NOT EXISTS zone_idx ON dns_records FIELDS zone;`,
		`DEFINE INDEX IF NOT EXISTS name_idx ON dns_records FIELDS name;`,
		`DEFINE INDEX IF NOT EXISTS type_idx ON dns_records FIELDS record_type;`,
	}

	for _, query := range schemaQueries {
		if _, err := surrealdb.Query[any](ctx, s.db, query, nil); err != nil {
			return err
		}
	}

	return nil
}

// GetRecords returns all records for a given domain name and record type
func (s *SurrealDBStorage) GetRecords(ctx context.Context, name string, recordType types.DNSType) ([]records.DNSRecord, error) {
	if s.closed {
		return nil, ErrStorageClosed
	}

	// Validate input
	if err := s.validator.ValidateName(name); err != nil {
		return nil, err
	}

	name = strings.ToLower(name)

	var query string
	vars := map[string]any{
		"name": name,
	}

	if recordType == 0 {
		query = "SELECT * FROM dns_records WHERE name = $name"
	} else {
		query = "SELECT * FROM dns_records WHERE name = $name AND record_type = $record_type"
		vars["record_type"] = int(recordType)
	}

	result, err := surrealdb.Query[[]SurrealDBRecord](ctx, s.db, query, vars)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	if len(*result) == 0 || len((*result)[0].Result) == 0 {
		return []records.DNSRecord{}, nil
	}

	return s.convertToRecords((*result)[0].Result)
}

// GetRecord returns a single record for a given domain name and record type
func (s *SurrealDBStorage) GetRecord(ctx context.Context, name string, recordType types.DNSType) (records.DNSRecord, error) {
	if s.closed {
		return nil, ErrStorageClosed
	}

	// Validate input
	if err := s.validator.ValidateName(name); err != nil {
		return nil, err
	}

	name = strings.ToLower(name)

	query := "SELECT * FROM dns_records WHERE name = $name AND record_type = $record_type LIMIT 1"
	vars := map[string]any{
		"name":        name,
		"record_type": int(recordType),
	}

	result, err := surrealdb.Query[[]SurrealDBRecord](ctx, s.db, query, vars)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	if len(*result) == 0 || len((*result)[0].Result) == 0 {
		return nil, ErrRecordNotFound
	}

	recordsList, err := s.convertToRecords((*result)[0].Result)
	if err != nil {
		return nil, err
	}

	return recordsList[0], nil
}

// PutRecord stores or updates a DNS record with validation
func (s *SurrealDBStorage) PutRecord(ctx context.Context, record records.DNSRecord) error {
	if s.closed {
		return ErrStorageClosed
	}

	// Validate record
	if err := s.validator.ValidateRecord(record); err != nil {
		return err
	}

	recordData, err := s.converter.ToStorageFormat(record)
	if err != nil {
		return err
	}

	query := `
		UPSERT dns_records
		SET name = $name,
		    record_type = $record_type,
		    class = $class,
		    ttl = $ttl,
		    data = $data,
		    zone = $zone,
		    updated_at = time::now()
		WHERE name = $name AND record_type = $record_type
	`

	_, err = surrealdb.Query[any](ctx, s.db, query, map[string]any{
		"name":        recordData.Name,
		"record_type": recordData.RecordType,
		"class":       recordData.Class,
		"ttl":         recordData.TTL,
		"data":        recordData.Data,
		"zone":        recordData.Zone,
	})

	if err != nil {
		return fmt.Errorf("failed to store record: %w", err)
	}

	return nil
}

// DeleteRecord removes a DNS record
func (s *SurrealDBStorage) DeleteRecord(ctx context.Context, name string, recordType types.DNSType) error {
	if s.closed {
		return ErrStorageClosed
	}

	// Validate input
	if err := s.validator.ValidateName(name); err != nil {
		return err
	}

	name = strings.ToLower(name)

	var query string
	vars := map[string]any{
		"name": name,
	}

	if recordType == 0 {
		query = "DELETE FROM dns_records WHERE name = $name"
	} else {
		query = "DELETE FROM dns_records WHERE name = $name AND record_type = $record_type"
		vars["record_type"] = int(recordType)
	}

	_, err := surrealdb.Query[any](ctx, s.db, query, vars)
	if err != nil {
		return fmt.Errorf("delete failed: %w", err)
	}

	return nil
}

// ListRecords returns all records in the storage
func (s *SurrealDBStorage) ListRecords(ctx context.Context) ([]records.DNSRecord, error) {
	if s.closed {
		return nil, ErrStorageClosed
	}

	query := "SELECT * FROM dns_records ORDER BY name, record_type"

	result, err := surrealdb.Query[[]SurrealDBRecord](ctx, s.db, query, nil)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	if len(*result) == 0 {
		return []records.DNSRecord{}, nil
	}

	return s.convertToRecords((*result)[0].Result)
}

// ListRecordsByZone returns all records for a specific zone
func (s *SurrealDBStorage) ListRecordsByZone(ctx context.Context, zone string) ([]records.DNSRecord, error) {
	if s.closed {
		return nil, ErrStorageClosed
	}

	// Validate zone
	if err := s.validator.ValidateZone(zone); err != nil {
		return nil, err
	}

	zone = strings.ToLower(zone)

	query := "SELECT * FROM dns_records WHERE zone = $zone ORDER BY name, record_type"
	vars := map[string]any{
		"zone": zone,
	}

	result, err := surrealdb.Query[[]SurrealDBRecord](ctx, s.db, query, vars)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	if len(*result) == 0 {
		return []records.DNSRecord{}, nil
	}

	return s.convertToRecords((*result)[0].Result)
}

// GetZones returns all available zones
func (s *SurrealDBStorage) GetZones(ctx context.Context) ([]string, error) {
	if s.closed {
		return nil, ErrStorageClosed
	}

	query := "SELECT DISTINCT zone FROM dns_records WHERE zone IS NOT NULL ORDER BY zone"

	type ZoneResult struct {
		Zone string `json:"zone"`
	}

	result, err := surrealdb.Query[[]ZoneResult](ctx, s.db, query, nil)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	if len(*result) == 0 {
		return []string{}, nil
	}

	zones := make([]string, len((*result)[0].Result))
	for i, zoneData := range (*result)[0].Result {
		zones[i] = zoneData.Zone
	}

	return zones, nil
}

// QueryRecords performs a filtered query with optional pagination
func (s *SurrealDBStorage) QueryRecords(ctx context.Context, options QueryOptions) ([]records.DNSRecord, error) {
	if s.closed {
		return nil, ErrStorageClosed
	}

	query := "SELECT * FROM dns_records"
	vars := map[string]any{}
	conditions := []string{}

	// Build filter conditions
	if options.Name != "" {
		conditions = append(conditions, "name = $name")
		vars["name"] = strings.ToLower(options.Name)
	}

	if options.NamePrefix != "" {
		conditions = append(conditions, "string::startsWith(name, $prefix)")
		vars["prefix"] = strings.ToLower(options.NamePrefix)
	}

	if options.RecordType != 0 {
		conditions = append(conditions, "record_type = $record_type")
		vars["record_type"] = int(options.RecordType)
	}

	if options.Zone != "" {
		conditions = append(conditions, "zone = $zone")
		vars["zone"] = strings.ToLower(options.Zone)
	}

	// Add WHERE clause if conditions exist
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	// Add sorting
	sortField := "name"
	switch options.SortBy {
	case "type":
		sortField = "record_type"
	case "ttl":
		sortField = "ttl"
	}

	if options.SortOrder == "desc" {
		query += fmt.Sprintf(" ORDER BY %s DESC", sortField)
	} else {
		query += fmt.Sprintf(" ORDER BY %s ASC", sortField)
	}

	// Add pagination
	if options.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", options.Limit)
		if options.Offset > 0 {
			query += fmt.Sprintf(" START %d", options.Offset)
		}
	}

	result, err := surrealdb.Query[[]SurrealDBRecord](ctx, s.db, query, vars)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	if len(*result) == 0 {
		return []records.DNSRecord{}, nil
	}

	return s.convertToRecords((*result)[0].Result)
}

// BatchPutRecords stores multiple records in a single operation
func (s *SurrealDBStorage) BatchPutRecords(ctx context.Context, recordsList []records.DNSRecord) error {
	if s.closed {
		return ErrStorageClosed
	}

	if len(recordsList) == 0 {
		return nil
	}

	// Validate all records first
	if errs := s.validator.ValidateBatch(recordsList); len(errs) > 0 {
		return fmt.Errorf("validation failed: %v", errs[0])
	}

	// Convert records to storage format
	recordsData, err := s.converter.BatchToStorageFormat(recordsList)
	if err != nil {
		return err
	}

	// Build batch insert data
	insertData := make([]map[string]any, len(recordsData))
	for i, data := range recordsData {
		insertData[i] = map[string]any{
			"name":        data.Name,
			"record_type": data.RecordType,
			"class":       data.Class,
			"ttl":         data.TTL,
			"data":        data.Data,
			"zone":        data.Zone,
			"created_at":  "time::now()",
			"updated_at":  "time::now()",
		}
	}

	query := "INSERT INTO dns_records $records ON DUPLICATE KEY UPDATE data = $input.data, ttl = $input.ttl, updated_at = time::now()"
	vars := map[string]any{
		"records": insertData,
	}

	_, err = surrealdb.Query[any](ctx, s.db, query, vars)
	if err != nil {
		return fmt.Errorf("batch insert failed: %w", err)
	}

	return nil
}

// BatchDeleteRecords deletes multiple records in a single operation
func (s *SurrealDBStorage) BatchDeleteRecords(ctx context.Context, names []string, recordType types.DNSType) error {
	if s.closed {
		return ErrStorageClosed
	}

	if len(names) == 0 {
		return nil
	}

	// Lowercase all names
	lowerNames := make([]string, len(names))
	for i, name := range names {
		lowerNames[i] = strings.ToLower(name)
	}

	query := "DELETE FROM dns_records WHERE name IN $names"
	vars := map[string]any{
		"names": lowerNames,
	}

	if recordType != 0 {
		query += " AND record_type = $record_type"
		vars["record_type"] = int(recordType)
	}

	_, err := surrealdb.Query[any](ctx, s.db, query, vars)
	if err != nil {
		return fmt.Errorf("batch delete failed: %w", err)
	}

	return nil
}

// Close closes the storage connection and cleans up resources
func (s *SurrealDBStorage) Close() error {
	if s.closed {
		return nil
	}

	s.closed = true
	return s.db.Close(context.Background())
}

// Helper types and methods

// SurrealDBRecord represents a DNS record in SurrealDB format
type SurrealDBRecord struct {
	ID         any       `json:"id,omitempty"`
	Name       string    `json:"name"`
	RecordType int       `json:"record_type"`
	Class      int       `json:"class"`
	TTL        uint32    `json:"ttl"`
	Data       string    `json:"data"`
	Zone       string    `json:"zone"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

// convertToRecords converts SurrealDB records to DNS records
func (s *SurrealDBStorage) convertToRecords(data []SurrealDBRecord) ([]records.DNSRecord, error) {
	result := make([]records.DNSRecord, 0, len(data))

	for _, surrealRecord := range data {
		// Convert SurrealDBRecord to RecordData
		recordData := &RecordData{
			ID:         fmt.Sprintf("%v", surrealRecord.ID),
			Name:       surrealRecord.Name,
			RecordType: surrealRecord.RecordType,
			Class:      surrealRecord.Class,
			TTL:        surrealRecord.TTL,
			Data:       surrealRecord.Data,
			Zone:       surrealRecord.Zone,
			CreatedAt:  surrealRecord.CreatedAt,
			UpdatedAt:  surrealRecord.UpdatedAt,
		}

		record, err := s.converter.FromStorageFormat(recordData)
		if err != nil {
			// Skip invalid records rather than failing entirely
			continue
		}
		result = append(result, record)
	}

	return result, nil
}

// GetStats returns storage statistics (if implemented)
func (s *SurrealDBStorage) GetStats(ctx context.Context) (*StorageStats, error) {
	if s.closed {
		return nil, ErrStorageClosed
	}

	stats := &StorageStats{
		RecordTypes: make(map[string]int),
		LastUpdated: time.Now().Unix(),
	}

	// Count total records
	countQuery := "SELECT COUNT() as count FROM dns_records"
	type CountResult struct {
		Count int `json:"count"`
	}

	countRes, err := surrealdb.Query[[]CountResult](ctx, s.db, countQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get record count: %w", err)
	}

	if len(*countRes) > 0 && len((*countRes)[0].Result) > 0 {
		stats.TotalRecords = (*countRes)[0].Result[0].Count
	}

	// Count zones
	zoneCountQuery := "SELECT COUNT(DISTINCT zone) as count FROM dns_records WHERE zone IS NOT NULL"
	zoneRes, err := surrealdb.Query[[]CountResult](ctx, s.db, zoneCountQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get zone count: %w", err)
	}

	if len(*zoneRes) > 0 && len((*zoneRes)[0].Result) > 0 {
		stats.TotalZones = (*zoneRes)[0].Result[0].Count
	}

	// Count by record type
	typeQuery := "SELECT record_type, COUNT() as count FROM dns_records GROUP BY record_type"
	type TypeCount struct {
		RecordType int `json:"record_type"`
		Count      int `json:"count"`
	}

	typeRes, err := surrealdb.Query[[]TypeCount](ctx, s.db, typeQuery, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get type counts: %w", err)
	}

	if len(*typeRes) > 0 {
		for _, tc := range (*typeRes)[0].Result {
			typeName := types.DNSType(tc.RecordType).String()
			stats.RecordTypes[typeName] = tc.Count
		}
	}

	return stats, nil
}

// Ensure SurrealDBStorage implements Storage interface
var _ Storage = (*SurrealDBStorage)(nil)
var _ StorageWithStats = (*SurrealDBStorage)(nil)
