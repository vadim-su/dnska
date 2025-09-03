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

	// Validate logging configuration
	if err := v.ValidateLoggingConfig(&config.Logging); err != nil {
		return fmt.Errorf("logging config validation failed: %w", err)
	}

	// Validate cache configuration
	if err := v.ValidateCacheConfig(&config.Cache); err != nil {
		return fmt.Errorf("cache config validation failed: %w", err)
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

// validateServerAddress validates a DNS server address
func (v *Validator) validateServerAddress(address string) error {
	if address == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	if net.ParseIP(host) == nil && host != "localhost" && host != "" {
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

	labels := strings.SplitSeq(domain, ".")
	for label := range labels {
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
