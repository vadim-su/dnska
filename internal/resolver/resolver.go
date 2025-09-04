package resolver

import (
	"context"
	"net"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/message"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// Resolver defines the interface for DNS resolution strategies
type Resolver interface {
	// Resolve performs DNS resolution for the given question
	Resolve(ctx context.Context, question message.DNSQuestion) ([]message.DNSAnswer, error)

	// ResolveAll performs DNS resolution for multiple questions
	ResolveAll(ctx context.Context, questions []message.DNSQuestion) ([]message.DNSAnswer, error)

	// Close closes the resolver and cleans up resources
	Close() error
}

// ResolutionResult represents the result of a DNS resolution
type ResolutionResult struct {
	Answers []message.DNSAnswer
	Error   error
	Source  string        // Source of the resolution (e.g., "cache", "recursive", "forward")
	TTL     time.Duration // Time taken for resolution
}

// ResolverConfig holds configuration for resolvers
type ResolverConfig struct {
	Timeout        time.Duration // Timeout for resolution attempts
	MaxRetries     int           // Maximum number of retries
	CacheEnabled   bool          // Whether caching is enabled
	CacheTTL       time.Duration // Default TTL for cached records
	ForwardServers []string      // List of forward DNS servers
	RootServers    []string      // List of root DNS servers
	RecursionDepth int           // Maximum recursion depth
}

// DefaultResolverConfig returns a default resolver configuration
func DefaultResolverConfig() *ResolverConfig {
	return &ResolverConfig{
		Timeout:        5 * time.Second,
		MaxRetries:     3,
		CacheEnabled:   true,
		CacheTTL:       300 * time.Second,                    // 5 minutes
		ForwardServers: []string{"8.8.8.8:53", "8.8.4.4:53"}, // Google DNS
		RootServers:    []string{},
		RecursionDepth: 10,
	}
}

// RecursiveResolver implements recursive DNS resolution
type RecursiveResolver struct {
	config     *ResolverConfig
	rootServer string
	client     *net.UDPConn
}

// NewRecursiveResolver creates a new recursive resolver
func NewRecursiveResolver(config *ResolverConfig) (*RecursiveResolver, error) {
	if config == nil {
		config = DefaultResolverConfig()
	}

	// Create UDP connection for DNS queries
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	resolver := &RecursiveResolver{
		config:     config,
		rootServer: config.RootServers[0], // Use first root server
		client:     conn,
	}

	return resolver, nil
}

// ForwardResolver implements forwarding DNS resolution
type ForwardResolver struct {
	config  *ResolverConfig
	servers []string
	client  *net.UDPConn
}

// NewForwardResolver creates a new forward resolver
func NewForwardResolver(config *ResolverConfig) (*ForwardResolver, error) {
	if config == nil {
		config = DefaultResolverConfig()
	}

	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}

	resolver := &ForwardResolver{
		config:  config,
		servers: config.ForwardServers,
		client:  conn,
	}

	return resolver, nil
}

// CacheResolver implements caching DNS resolution
type CacheResolver struct {
	config   *ResolverConfig
	cache    map[string]*CacheEntry
	resolver Resolver // Underlying resolver to use when cache misses
}

// CacheEntry represents a cached DNS resolution result
type CacheEntry struct {
	Answers   []message.DNSAnswer
	ExpiresAt time.Time
}

// NewCacheResolver creates a new caching resolver
func NewCacheResolver(config *ResolverConfig, underlying Resolver) *CacheResolver {
	return &CacheResolver{
		config:   config,
		cache:    make(map[string]*CacheEntry),
		resolver: underlying,
	}
}

// ResolutionError represents an error during DNS resolution
type ResolutionError struct {
	Type    types.DNSRCode
	Message string
	Cause   error
}

// Error implements the error interface
func (e *ResolutionError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// NewResolutionError creates a new resolution error
func NewResolutionError(rcode types.DNSRCode, message string, cause error) *ResolutionError {
	return &ResolutionError{
		Type:    rcode,
		Message: message,
		Cause:   cause,
	}
}
