package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Validator handles configuration validation
type Validator struct{}

// NewValidator creates a new configuration validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateConfig performs comprehensive validation of the configuration
func (v *Validator) ValidateConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Validate server configuration
	if err := v.ValidateServerConfig(&config.Server); err != nil {
		return fmt.Errorf("server config validation failed: %w", err)
	}

	// Validate resolver configuration
	if err := v.ValidateResolverConfig(&config.Resolver); err != nil {
		return fmt.Errorf("resolver config validation failed: %w", err)
	}

	// Validate storage configuration
	if err := v.ValidateStorageConfig(&config.Storage); err != nil {
		return fmt.Errorf("storage config validation failed: %w", err)
	}

	// Validate API configuration
	if err := v.ValidateAPIConfig(&config.API); err != nil {
		return fmt.Errorf("API config validation failed: %w", err)
	}

	// Validate logging configuration
	if err := v.ValidateLoggingConfig(&config.Logging); err != nil {
		return fmt.Errorf("logging config validation failed: %w", err)
	}

	// Validate cache configuration
	if err := v.ValidateCacheConfig(&config.Cache); err != nil {
		return fmt.Errorf("cache config validation failed: %w", err)
	}

	// Validate zones
	for i, zone := range config.Zones {
		if err := v.ValidateZoneConfig(&zone); err != nil {
			return fmt.Errorf("zone %d (%s) validation failed: %w", i, zone.Name, err)
		}
	}

	return nil
}

// ValidateServerConfig validates server-specific configuration
func (v *Validator) ValidateServerConfig(config *ServerConfig) error {
	// Validate address
	if config.Address == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	host, port, err := net.SplitHostPort(config.Address)
	if err != nil {
		return fmt.Errorf("invalid server address format: %w", err)
	}

	if net.ParseIP(host) == nil && host != "localhost" && host != "" {
		return fmt.Errorf("invalid server host: %s", host)
	}

	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid server port: %s", port)
	}

	// Validate timeouts
	if config.ReadTimeout < 0 {
		return fmt.Errorf("read timeout cannot be negative")
	}
	if config.WriteTimeout < 0 {
		return fmt.Errorf("write timeout cannot be negative")
	}

	// Validate connection limits
	if config.MaxConnections < 0 {
		return fmt.Errorf("max connections cannot be negative")
	}

	return nil
}

// ValidateResolverConfig validates resolver-specific configuration
func (v *Validator) ValidateResolverConfig(config *ResolverConfig) error {
	// Validate resolver type
	validTypes := map[string]bool{
		"recursive": true,
		"forward":   true,
		"cache":     true,
	}
	if !validTypes[config.Type] {
		return fmt.Errorf("invalid resolver type: %s (must be recursive, forward, or cache)", config.Type)
	}

	// Validate timeout
	if config.Timeout <= 0 {
		return fmt.Errorf("resolver timeout must be positive")
	}

	// Validate max retries
	if config.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}

	// Validate forward servers
	for i, server := range config.ForwardServers {
		if err := v.validateServerAddress(server); err != nil {
			return fmt.Errorf("invalid forward server %d: %w", i, err)
		}
	}

	// Validate root servers
	for i, server := range config.RootServers {
		if err := v.validateServerAddress(server); err != nil {
			return fmt.Errorf("invalid root server %d: %w", i, err)
		}
	}

	// Validate recursion depth
	if config.RecursionDepth < 0 {
		return fmt.Errorf("recursion depth cannot be negative")
	}
	if config.RecursionDepth > 50 {
		return fmt.Errorf("recursion depth too high: %d (max recommended: 50)", config.RecursionDepth)
	}

	return nil
}

// ValidateStorageConfig validates storage-specific configuration
func (v *Validator) ValidateStorageConfig(config *StorageConfig) error {
	// Validate storage type
	validTypes := map[string]bool{
		"memory":   true,
		"sqlite":   true,
		"postgres": true,
		"redis":    true,
	}
	if !validTypes[config.Type] {
		return fmt.Errorf("invalid storage type: %s (must be memory, sqlite, postgres, or redis)", config.Type)
	}

	// Validate DSN based on storage type
	switch config.Type {
	case "sqlite":
		if config.DSN == "" {
			return fmt.Errorf("DSN required for SQLite storage")
		}
		if !strings.HasSuffix(config.DSN, ".db") && !strings.Contains(config.DSN, ":memory:") {
			return fmt.Errorf("invalid SQLite DSN format")
		}
	case "postgres":
		if config.DSN == "" {
			return fmt.Errorf("DSN required for PostgreSQL storage")
		}
		if !strings.Contains(config.DSN, "postgres://") && !strings.Contains(config.DSN, "postgresql://") {
			return fmt.Errorf("invalid PostgreSQL DSN format")
		}
	case "redis":
		if config.DSN == "" {
			return fmt.Errorf("DSN required for Redis storage")
		}
		if _, err := url.Parse(config.DSN); err != nil {
			return fmt.Errorf("invalid Redis DSN format: %w", err)
		}
	}

	// Validate max connections
	if config.MaxConns < 0 {
		return fmt.Errorf("max connections cannot be negative")
	}

	return nil
}

// ValidateAPIConfig validates API-specific configuration
func (v *Validator) ValidateAPIConfig(config *APIConfig) error {
	if !config.Enabled {
		return nil // Skip validation if API is disabled
	}

	// Validate address
	if config.Address == "" {
		return fmt.Errorf("API address cannot be empty when API is enabled")
	}

	host, port, err := net.SplitHostPort(config.Address)
	if err != nil {
		return fmt.Errorf("invalid API address format: %w", err)
	}

	if net.ParseIP(host) == nil && host != "localhost" && host != "" {
		return fmt.Errorf("invalid API host: %s", host)
	}

	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid API port: %s", port)
	}

	return nil
}

// ValidateLoggingConfig validates logging-specific configuration
func (v *Validator) ValidateLoggingConfig(config *LoggingConfig) error {
	// Validate log level
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLevels[config.Level] {
		return fmt.Errorf("invalid log level: %s (must be debug, info, warn, or error)", config.Level)
	}

	// Validate log format
	validFormats := map[string]bool{
		"json": true,
		"text": true,
	}
	if !validFormats[config.Format] {
		return fmt.Errorf("invalid log format: %s (must be json or text)", config.Format)
	}

	// Validate output (basic check)
	if config.Output == "" {
		return fmt.Errorf("log output cannot be empty")
	}

	return nil
}

// ValidateCacheConfig validates cache-specific configuration
func (v *Validator) ValidateCacheConfig(config *CacheConfig) error {
	// Validate cache type
	validTypes := map[string]bool{
		"lru": true,
		"lfu": true,
		"ttl": true,
	}
	if !validTypes[config.Type] {
		return fmt.Errorf("invalid cache type: %s (must be lru, lfu, or ttl)", config.Type)
	}

	// Validate cache size
	if config.Size < 0 {
		return fmt.Errorf("cache size cannot be negative")
	}

	// Validate TTL
	if config.TTL < 0 {
		return fmt.Errorf("cache TTL cannot be negative")
	}

	return nil
}

// ValidateZoneConfig validates zone-specific configuration
func (v *Validator) ValidateZoneConfig(config *ZoneConfig) error {
	// Validate zone name
	if config.Name == "" {
		return fmt.Errorf("zone name cannot be empty")
	}

	// Basic domain name validation
	if !v.isValidDomainName(config.Name) {
		return fmt.Errorf("invalid zone name: %s", config.Name)
	}

	// Validate zone file if specified
	if config.File != "" {
		if !strings.HasSuffix(config.File, ".zone") {
			return fmt.Errorf("zone file must have .zone extension: %s", config.File)
		}
	}

	// Validate records
	for i, record := range config.Records {
		if err := v.ValidateRecordConfig(&record); err != nil {
			return fmt.Errorf("record %d validation failed: %w", i, err)
		}
	}

	return nil
}

// ValidateRecordConfig validates individual record configuration
func (v *Validator) ValidateRecordConfig(config *RecordConfig) error {
	// Validate record name
	if config.Name == "" {
		return fmt.Errorf("record name cannot be empty")
	}

	// Validate record type
	validTypes := map[string]bool{
		"A":     true,
		"AAAA":  true,
		"CNAME": true,
		"MX":    true,
		"NS":    true,
		"SOA":   true,
		"TXT":   true,
		"PTR":   true,
	}
	if !validTypes[strings.ToUpper(config.Type)] {
		return fmt.Errorf("invalid record type: %s", config.Type)
	}

	// Validate record value
	if config.Value == "" {
		return fmt.Errorf("record value cannot be empty")
	}

	// Type-specific validation
	switch strings.ToUpper(config.Type) {
	case "A":
		if net.ParseIP(config.Value) == nil || net.ParseIP(config.Value).To4() == nil {
			return fmt.Errorf("invalid IPv4 address for A record: %s", config.Value)
		}
	case "AAAA":
		if net.ParseIP(config.Value) == nil || net.ParseIP(config.Value).To16() == nil {
			return fmt.Errorf("invalid IPv6 address for AAAA record: %s", config.Value)
		}
	case "MX":
		// MX record format: preference space domain
		parts := strings.Fields(config.Value)
		if len(parts) != 2 {
			return fmt.Errorf("invalid MX record format (expected: preference domain): %s", config.Value)
		}
		if _, err := strconv.Atoi(parts[0]); err != nil {
			return fmt.Errorf("invalid MX preference (must be integer): %s", parts[0])
		}
	}

	// Validate TTL
	if config.TTL == 0 {
		return fmt.Errorf("TTL cannot be zero")
	}

	return nil
}

// validateServerAddress validates a DNS server address
func (v *Validator) validateServerAddress(address string) error {
	if address == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	if net.ParseIP(host) == nil && host != "localhost" {
		return fmt.Errorf("invalid host: %s", host)
	}

	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port: %s", port)
	}

	return nil
}

// isValidDomainName performs basic domain name validation
func (v *Validator) isValidDomainName(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		// Check for valid characters (simplified)
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				return false
			}
		}
		// Label cannot start or end with hyphen
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}

	return true
}
