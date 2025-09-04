package resolver

import (
	"context"
	"crypto/md5"
	"fmt"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/message"
)

// Resolve performs DNS resolution with caching
func (r *CacheResolver) Resolve(ctx context.Context, question message.DNSQuestion) ([]message.DNSAnswer, error) {
	var cacheKey string

	// Check cache first
	if r.config.CacheEnabled {
		cacheKey = r.generateCacheKey(question)
		if entry := r.getFromCache(cacheKey); entry != nil {
			return entry.Answers, nil
		}
	}

	// Cache miss - resolve using underlying resolver
	answers, err := r.resolver.Resolve(ctx, question)
	if err != nil {
		return nil, err
	}

	// Cache the result if caching is enabled
	if r.config.CacheEnabled && len(answers) > 0 {
		r.putInCache(cacheKey, answers)
	}

	return answers, nil
}

// ResolveAll performs DNS resolution for multiple questions with caching
func (r *CacheResolver) ResolveAll(ctx context.Context, questions []message.DNSQuestion) ([]message.DNSAnswer, error) {
	var allAnswers []message.DNSAnswer

	for _, question := range questions {
		answers, err := r.Resolve(ctx, question)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve question %v: %w", question, err)
		}
		allAnswers = append(allAnswers, answers...)
	}

	return allAnswers, nil
}

// Close closes the resolver and cleans up resources
func (r *CacheResolver) Close() error {
	// Clear cache
	r.cache = make(map[string]*CacheEntry)

	// Close underlying resolver
	if r.resolver != nil {
		return r.resolver.Close()
	}

	return nil
}

// generateCacheKey generates a unique cache key for a DNS question
func (r *CacheResolver) generateCacheKey(question message.DNSQuestion) string {
	// Create a unique key from question name, type, and class
	questionName := question.Name.String()
	questionType := uint16(question.Type[0])<<8 | uint16(question.Type[1])
	questionClass := uint16(question.Class[0])<<8 | uint16(question.Class[1])
	keyData := fmt.Sprintf("%s|%d|%d", questionName, questionType, questionClass)

	// Use MD5 hash for consistent key length
	hash := md5.Sum([]byte(keyData))
	return fmt.Sprintf("%x", hash)
}

// getFromCache retrieves an entry from the cache if it exists and hasn't expired
func (r *CacheResolver) getFromCache(key string) *CacheEntry {
	entry, exists := r.cache[key]
	if !exists {
		return nil
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		// Remove expired entry
		delete(r.cache, key)
		return nil
	}

	return entry
}

// putInCache stores an entry in the cache with appropriate TTL
func (r *CacheResolver) putInCache(key string, answers []message.DNSAnswer) {
	// Use configured cache TTL (simplified - doesn't extract TTL from answers)
	minTTL := r.config.CacheTTL

	entry := &CacheEntry{
		Answers:   answers,
		ExpiresAt: time.Now().Add(minTTL),
	}

	r.cache[key] = entry
}

// GetCacheStats returns statistics about the cache
func (r *CacheResolver) GetCacheStats() CacheStats {
	now := time.Now()
	totalEntries := len(r.cache)
	validEntries := 0
	expiredEntries := 0

	for _, entry := range r.cache {
		if now.After(entry.ExpiresAt) {
			expiredEntries++
		} else {
			validEntries++
		}
	}

	return CacheStats{
		TotalEntries:   totalEntries,
		ValidEntries:   validEntries,
		ExpiredEntries: expiredEntries,
	}
}

// CacheStats represents cache statistics
type CacheStats struct {
	TotalEntries   int
	ValidEntries   int
	ExpiredEntries int
}

// CleanExpiredEntries removes all expired entries from the cache
func (r *CacheResolver) CleanExpiredEntries() int {
	now := time.Now()
	removed := 0

	for key, entry := range r.cache {
		if now.After(entry.ExpiresAt) {
			delete(r.cache, key)
			removed++
		}
	}

	return removed
}

// SetCacheTTL updates the default cache TTL
func (r *CacheResolver) SetCacheTTL(ttl time.Duration) {
	r.config.CacheTTL = ttl
}

// EnableCache enables or disables caching
func (r *CacheResolver) EnableCache(enabled bool) {
	r.config.CacheEnabled = enabled

	// If disabling cache, clear existing entries
	if !enabled {
		r.cache = make(map[string]*CacheEntry)
	}
}
