package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Resolver ResolverConfig `yaml:"resolver"`
	Storage  StorageConfig  `yaml:"storage"`
	API      APIConfig      `yaml:"api"`
	Logging  LoggingConfig  `yaml:"logging"`
	Zones    []ZoneConfig   `yaml:"zones"`
	Cache    CacheConfig    `yaml:"cache"`
}

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Address         string        `yaml:"address"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	MaxConnections  int           `yaml:"max_connections"`
	EnableTCP       bool          `yaml:"enable_tcp"`
	EnableUDP       bool          `yaml:"enable_udp"`
	EnableMetrics   bool          `yaml:"enable_metrics"`
	EnableHealth    bool          `yaml:"enable_health"`
}

// ResolverConfig holds resolver-specific configuration
type ResolverConfig struct {
	Type            string        `yaml:"type"` // "recursive", "forward", "cache"
	Timeout         time.Duration `yaml:"timeout"`
	MaxRetries      int           `yaml:"max_retries"`
	ForwardServers  []string      `yaml:"forward_servers"`
	RootServers     []string      `yaml:"root_servers"`
	RecursionDepth  int           `yaml:"recursion_depth"`
}

// StorageConfig holds storage backend configuration
type StorageConfig struct {
	Type     string `yaml:"type"` // "memory", "sqlite", "postgres", "redis"
	DSN      string `yaml:"dsn"`
	MaxConns int    `yaml:"max_conns"`
}

// APIConfig holds REST/gRPC API configuration
type APIConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Address     string `yaml:"address"`
	EnableREST  bool   `yaml:"enable_rest"`
	EnableGRPC  bool   `yaml:"enable_grpc"`
	AuthEnabled bool   `yaml:"auth_enabled"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"` // "debug", "info", "warn", "error"
	Format string `yaml:"format"` // "json", "text"
	Output string `yaml:"output"` // "stdout", "stderr", or file path
}

// ZoneConfig holds zone-specific configuration
type ZoneConfig struct {
	Name     string            `yaml:"name"`
	File     string            `yaml:"file"`
	Records  []RecordConfig    `yaml:"records"`
	Options  map[string]string `yaml:"options"`
}

// RecordConfig holds individual record configuration
type RecordConfig struct {
	Name  string `yaml:"name"`
	Type  string `yaml:"type"` // "A", "AAAA", "CNAME", "MX", etc.
	Value string `yaml:"value"`
	TTL   uint32 `yaml:"ttl"`
}

// CacheConfig holds cache configuration
type CacheConfig struct {
	Enabled bool          `yaml:"enabled"`
	Size    int           `yaml:"size"`
	TTL     time.Duration `yaml:"ttl"`
	Type    string        `yaml:"type"` // "lru", "lfu", "ttl"
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Address:        "127.0.0.1:53",
			ReadTimeout:    5 * time.Second,
			WriteTimeout:   5 * time.Second,
			MaxConnections: 1000,
			EnableTCP:      true,
			EnableUDP:      true,
			EnableMetrics:  true,
			EnableHealth:   true,
		},
		Resolver: ResolverConfig{
			Type:           "forward",
			Timeout:        5 * time.Second,
			MaxRetries:     3,
			ForwardServers: []string{"8.8.8.8:53", "8.8.4.4:53"},
			RootServers: []string{
				"a.root-servers.net:53",
				"b.root-servers.net:53",
				"c.root-servers.net:53",
			},
			RecursionDepth: 10,
		},
		Storage: StorageConfig{
			Type:     "memory",
			MaxConns: 10,
		},
		API: APIConfig{
			Enabled:     false,
			Address:     "127.0.0.1:8080",
			EnableREST:  true,
			EnableGRPC:  false,
			AuthEnabled: false,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
		Cache: CacheConfig{
			Enabled: true,
			Size:    1000,
			TTL:     300 * time.Second,
			Type:    "lru",
		},
	}
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := DefaultConfig()
	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// SaveToFile saves configuration to a YAML file
func (c *Config) SaveToFile(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server config
	if c.Server.Address == "" {
		return fmt.Errorf("server address cannot be empty")
	}

	// Validate resolver config
	if c.Resolver.Type != "recursive" && c.Resolver.Type != "forward" && c.Resolver.Type != "cache" {
		return fmt.Errorf("invalid resolver type: %s", c.Resolver.Type)
	}

	// Validate storage config
	if c.Storage.Type != "memory" && c.Storage.Type != "sqlite" && c.Storage.Type != "postgres" && c.Storage.Type != "redis" {
		return fmt.Errorf("invalid storage type: %s", c.Storage.Type)
	}

	// Validate logging config
	if c.Logging.Level != "debug" && c.Logging.Level != "info" && c.Logging.Level != "warn" && c.Logging.Level != "error" {
		return fmt.Errorf("invalid log level: %s", c.Logging.Level)
	}

	if c.Logging.Format != "json" && c.Logging.Format != "text" {
		return fmt.Errorf("invalid log format: %s", c.Logging.Format)
	}

	// Validate cache config
	if c.Cache.Type != "lru" && c.Cache.Type != "lfu" && c.Cache.Type != "ttl" {
		return fmt.Errorf("invalid cache type: %s", c.Cache.Type)
	}

	return nil
}

// GetServerAddress returns the server address with default port if not specified
func (c *Config) GetServerAddress() string {
	if c.Server.Address == "" {
		return "127.0.0.1:53"
	}
	return c.Server.Address
}

// IsResolverRecursive returns true if resolver type is recursive
func (c *Config) IsResolverRecursive() bool {
	return c.Resolver.Type == "recursive"
}

// IsResolverForward returns true if resolver type is forward
func (c *Config) IsResolverForward() bool {
	return c.Resolver.Type == "forward"
}

// IsResolverCache returns true if resolver type is cache
func (c *Config) IsResolverCache() bool {
	return c.Resolver.Type == "cache"
}

// IsStorageMemory returns true if storage type is memory
func (c *Config) IsStorageMemory() bool {
	return c.Storage.Type == "memory"
}

// IsStorageSQLite returns true if storage type is SQLite
func (c *Config) IsStorageSQLite() bool {
	return c.Storage.Type == "sqlite"
}

// IsStoragePostgres returns true if storage type is PostgreSQL
func (c *Config) IsStoragePostgres() bool {
	return c.Storage.Type == "postgres"
}

// IsStorageRedis returns true if storage type is Redis
func (c *Config) IsStorageRedis() bool {
	return c.Storage.Type == "redis"
}
