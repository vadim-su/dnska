package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Loader handles configuration loading from multiple sources
type Loader struct {
	configPaths []string
	envPrefix   string
}

// NewLoader creates a new configuration loader
func NewLoader() *Loader {
	return &Loader{
		configPaths: []string{
			"./dnska.yaml",
		},
		envPrefix: "DNSKA_",
	}
}

// Load loads configuration from all available sources
func (l *Loader) Load() (*Config, error) {
	config := DefaultConfig()

	// Load from file
	if err := l.loadFromFile(config); err != nil {
		return nil, fmt.Errorf("failed to load config from file: %w", err)
	}

	// Override with environment variables
	if err := l.loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load config from environment: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// LoadFromPath loads configuration from a specific file path
func (l *Loader) LoadFromPath(path string) (*Config, error) {
	config := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// Override with environment variables
	if err := l.loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load config from environment: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// loadFromFile attempts to load configuration from default file locations
func (l *Loader) loadFromFile(config *Config) error {
	for _, path := range l.configPaths {
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read config file %s: %w", path, err)
			}

			err = yaml.Unmarshal(data, config)
			if err != nil {
				return fmt.Errorf("failed to parse config file %s: %w", path, err)
			}

			return nil
		}
	}

	// No config file found, use defaults
	return nil
}

// loadFromEnv loads configuration overrides from environment variables
func (l *Loader) loadFromEnv(config *Config) error {
	// Server configuration
	if addr := os.Getenv(l.envPrefix + "SERVER_ADDRESS"); addr != "" {
		config.Server.Address = addr
	}
	if timeout := os.Getenv(l.envPrefix + "SERVER_READ_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.Server.ReadTimeout = d
		}
	}
	if timeout := os.Getenv(l.envPrefix + "SERVER_WRITE_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.Server.WriteTimeout = d
		}
	}
	if conns := os.Getenv(l.envPrefix + "SERVER_MAX_CONNECTIONS"); conns != "" {
		if i, err := strconv.Atoi(conns); err == nil {
			config.Server.MaxConnections = i
		}
	}

	// Resolver configuration - type no longer configurable
	if timeout := os.Getenv(l.envPrefix + "RESOLVER_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.Resolver.Timeout = d
		}
	}
	if servers := os.Getenv(l.envPrefix + "RESOLVER_FORWARD_SERVERS"); servers != "" {
		config.Resolver.ForwardServers = strings.Split(servers, ",")
		for i, server := range config.Resolver.ForwardServers {
			config.Resolver.ForwardServers[i] = strings.TrimSpace(server)
		}
	}

	// Storage configuration
	if storageType := os.Getenv(l.envPrefix + "STORAGE_TYPE"); storageType != "" {
		config.Storage.Type = storageType
	}
	if dsn := os.Getenv(l.envPrefix + "STORAGE_DSN"); dsn != "" {
		config.Storage.DSN = dsn
	}

	// Logging configuration
	if level := os.Getenv(l.envPrefix + "LOG_LEVEL"); level != "" {
		config.Logging.Level = level
	}
	if format := os.Getenv(l.envPrefix + "LOG_FORMAT"); format != "" {
		config.Logging.Format = format
	}
	if output := os.Getenv(l.envPrefix + "LOG_OUTPUT"); output != "" {
		config.Logging.Output = output
	}

	// Cache configuration
	if enabled := os.Getenv(l.envPrefix + "CACHE_ENABLED"); enabled != "" {
		if b, err := strconv.ParseBool(enabled); err == nil {
			config.Cache.Enabled = b
		}
	}
	if size := os.Getenv(l.envPrefix + "CACHE_SIZE"); size != "" {
		if i, err := strconv.Atoi(size); err == nil {
			config.Cache.Size = i
		}
	}
	if ttl := os.Getenv(l.envPrefix + "CACHE_TTL"); ttl != "" {
		if d, err := time.ParseDuration(ttl); err == nil {
			config.Cache.TTL = d
		}
	}

	return nil
}

// parseDuration parses a duration string with various units
func parseDuration(s string) (time.Duration, error) {
	// Handle simple cases like "5s", "10m", etc.
	if strings.Contains(s, "s") || strings.Contains(s, "m") || strings.Contains(s, "h") {
		return time.ParseDuration(s)
	}

	// Handle numeric values as seconds
	if sec, err := strconv.Atoi(s); err == nil {
		return time.Duration(sec) * time.Second, nil
	}

	return 0, fmt.Errorf("invalid duration format: %s", s)
}

// SetConfigPaths sets the configuration file search paths
func (l *Loader) SetConfigPaths(paths []string) {
	l.configPaths = paths
}

// AddConfigPath adds a configuration file search path
func (l *Loader) AddConfigPath(path string) {
	l.configPaths = append(l.configPaths, path)
}

// SetEnvPrefix sets the environment variable prefix
func (l *Loader) SetEnvPrefix(prefix string) {
	l.envPrefix = prefix
}

// FindConfigFile searches for a configuration file in the configured paths
func (l *Loader) FindConfigFile() (string, error) {
	for _, path := range l.configPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no configuration file found in paths: %v", l.configPaths)
}

// CreateDefaultConfig creates a default configuration file
func (l *Loader) CreateDefaultConfig(path string) error {
	config := DefaultConfig()

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return config.SaveToFile(path)
}

// WatchConfig watches for configuration file changes (placeholder for future implementation)
func (l *Loader) WatchConfig(path string, callback func(*Config)) error {
	// This would implement file watching using fsnotify or similar
	// For now, return not implemented
	return fmt.Errorf("config watching not implemented")
}
