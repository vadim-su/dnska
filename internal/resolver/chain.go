package resolver

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/message"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// ChainResolver implements a chain of responsibility pattern for DNS resolution
// It tries multiple resolvers in sequence until one succeeds
type ChainResolver struct {
	resolvers []ResolverWithPolicy
	config    *ResolverConfig
}

// ResolverWithPolicy wraps a resolver with additional policy information
type ResolverWithPolicy struct {
	Resolver    Resolver
	Name        string
	SkipOnError bool // If true, continue to next resolver on error
	Timeout     time.Duration
}

// ChainPolicy defines how the chain behaves
type ChainPolicy int

const (
	// ChainPolicyFirstSuccess stops at first successful resolution
	ChainPolicyFirstSuccess ChainPolicy = iota
	// ChainPolicyAllResolvers tries all resolvers and merges results
	ChainPolicyAllResolvers
	// ChainPolicyFallback only tries next resolver if previous returns NXDOMAIN
	ChainPolicyFallback
)

// ChainResolverConfig extends ResolverConfig with chain-specific settings
type ChainResolverConfig struct {
	*ResolverConfig
	Policy        ChainPolicy
	MergeResults  bool // Merge results from all successful resolvers
	StopOnSuccess bool // Stop at first successful resolution
	LogAttempts   bool // Log resolution attempts
	RetryOnError  bool // Retry failed resolvers
}

// NewChainResolver creates a new chain resolver with multiple resolvers
func NewChainResolver(config *ResolverConfig, resolvers ...Resolver) (*ChainResolver, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("at least one resolver is required")
	}

	if config == nil {
		config = DefaultResolverConfig()
	}

	// Wrap resolvers with default policies
	wrapped := make([]ResolverWithPolicy, len(resolvers))
	for i, resolver := range resolvers {
		wrapped[i] = ResolverWithPolicy{
			Resolver:    resolver,
			Name:        fmt.Sprintf("resolver-%d", i),
			SkipOnError: true,
			Timeout:     config.Timeout,
		}
	}

	return &ChainResolver{
		resolvers: wrapped,
		config:    config,
	}, nil
}

// NewChainResolverWithPolicies creates a chain resolver with specific policies for each resolver
func NewChainResolverWithPolicies(config *ResolverConfig, resolvers []ResolverWithPolicy) (*ChainResolver, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("at least one resolver is required")
	}

	if config == nil {
		config = DefaultResolverConfig()
	}

	return &ChainResolver{
		resolvers: resolvers,
		config:    config,
	}, nil
}

// Resolve performs DNS resolution by trying each resolver in the chain
func (r *ChainResolver) Resolve(ctx context.Context, question message.DNSQuestion) ([]message.DNSAnswer, error) {
	// Check context at the start
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	var lastError error
	var allAnswers []message.DNSAnswer

	for i, resolverPolicy := range r.resolvers {
		// Create a timeout context for this specific resolver
		resolverCtx := ctx
		if resolverPolicy.Timeout > 0 {
			var cancel context.CancelFunc
			resolverCtx, cancel = context.WithTimeout(ctx, resolverPolicy.Timeout)
			defer cancel()
		}

		// Log attempt if configured
		if r.config.CacheEnabled { // Using CacheEnabled as a proxy for verbose logging
			log.Printf("[ChainResolver] Trying resolver %s (%d/%d)",
				resolverPolicy.Name, i+1, len(r.resolvers))
		}

		// Try resolution with this resolver
		answers, err := resolverPolicy.Resolver.Resolve(resolverCtx, question)

		if err == nil && len(answers) > 0 {
			// Successful resolution
			allAnswers = append(allAnswers, answers...)

			// Log success
			if r.config.CacheEnabled {
				log.Printf("[ChainResolver] Resolver %s succeeded with %d answers",
					resolverPolicy.Name, len(answers))
			}

			// Return immediately if we don't need to try all resolvers
			if !r.shouldContinueAfterSuccess() {
				return answers, nil
			}
		} else if err != nil {
			// Handle error
			lastError = err

			// Log error
			if r.config.CacheEnabled {
				log.Printf("[ChainResolver] Resolver %s failed: %v",
					resolverPolicy.Name, err)
			}

			// Check if we should continue to next resolver
			if !resolverPolicy.SkipOnError {
				return nil, fmt.Errorf("resolver %s failed: %w", resolverPolicy.Name, err)
			}

			// Check if error is NXDOMAIN - might want different handling
			if resErr, ok := err.(*ResolutionError); ok {
				if resErr.Type == types.RCODE_NAME_ERROR {
					// NXDOMAIN - domain doesn't exist, no point trying other resolvers
					// unless specifically configured to do so
					if !r.shouldContinueOnNXDOMAIN() {
						return nil, err
					}
				}
			}
		}

		// Check context cancellation
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	// Return merged results if we have any
	if len(allAnswers) > 0 {
		return r.deduplicateAnswers(allAnswers), nil
	}

	// All resolvers failed
	if lastError != nil {
		return nil, fmt.Errorf("all resolvers in chain failed, last error: %w", lastError)
	}

	return nil, fmt.Errorf("no resolvers returned answers")
}

// ResolveAll performs DNS resolution for multiple questions
func (r *ChainResolver) ResolveAll(ctx context.Context, questions []message.DNSQuestion) ([]message.DNSAnswer, error) {
	var allAnswers []message.DNSAnswer

	for _, question := range questions {
		answers, err := r.Resolve(ctx, question)
		if err != nil {
			// Continue with other questions even if one fails
			log.Printf("[ChainResolver] Failed to resolve question %v: %v", question, err)
			continue
		}
		allAnswers = append(allAnswers, answers...)
	}

	if len(allAnswers) == 0 {
		return nil, fmt.Errorf("failed to resolve any questions")
	}

	return allAnswers, nil
}

// Close closes all resolvers in the chain
func (r *ChainResolver) Close() error {
	var errs []error

	for _, resolverPolicy := range r.resolvers {
		if err := resolverPolicy.Resolver.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close %s: %w",
				resolverPolicy.Name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing resolvers: %v", errs)
	}

	return nil
}

// AddResolver adds a new resolver to the chain
func (r *ChainResolver) AddResolver(resolver Resolver, name string) {
	r.resolvers = append(r.resolvers, ResolverWithPolicy{
		Resolver:    resolver,
		Name:        name,
		SkipOnError: true,
		Timeout:     r.config.Timeout,
	})
}

// RemoveResolver removes a resolver from the chain by name
func (r *ChainResolver) RemoveResolver(name string) bool {
	for i, resolverPolicy := range r.resolvers {
		if resolverPolicy.Name == name {
			r.resolvers = append(r.resolvers[:i], r.resolvers[i+1:]...)
			return true
		}
	}
	return false
}

// GetResolverCount returns the number of resolvers in the chain
func (r *ChainResolver) GetResolverCount() int {
	return len(r.resolvers)
}

// shouldContinueAfterSuccess determines if we should continue after a successful resolution
func (r *ChainResolver) shouldContinueAfterSuccess() bool {
	// This could be made configurable
	return false // Stop at first success by default
}

// shouldContinueOnNXDOMAIN determines if we should continue after NXDOMAIN
func (r *ChainResolver) shouldContinueOnNXDOMAIN() bool {
	// This could be made configurable
	return false // Stop on NXDOMAIN by default
}

// deduplicateAnswers removes duplicate answers from the merged results
func (r *ChainResolver) deduplicateAnswers(answers []message.DNSAnswer) []message.DNSAnswer {
	seen := make(map[string]bool)
	result := make([]message.DNSAnswer, 0, len(answers))

	for _, answer := range answers {
		// Convert answer to bytes to create a unique key
		answerBytes := answer.ToBytes()
		key := fmt.Sprintf("%x", answerBytes)
		if !seen[key] {
			seen[key] = true
			result = append(result, answer)
		}
	}

	return result
}

// CreateStandardChain creates a standard resolver chain with common patterns
func CreateStandardChain(config *ResolverConfig) (*ChainResolver, error) {
	// Create resolvers
	recursiveResolver, err := NewRecursiveResolver(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create recursive resolver: %w", err)
	}

	forwardResolver, err := NewForwardResolver(config)
	if err != nil {
		recursiveResolver.Close()
		return nil, fmt.Errorf("failed to create forward resolver: %w", err)
	}

	// Create chain: try recursive first, fallback to forward
	resolvers := []ResolverWithPolicy{
		{
			Resolver:    recursiveResolver,
			Name:        "recursive",
			SkipOnError: true,
			Timeout:     config.Timeout,
		},
		{
			Resolver:    forwardResolver,
			Name:        "forward",
			SkipOnError: false, // Don't skip on error for last resolver
			Timeout:     config.Timeout,
		},
	}

	return NewChainResolverWithPolicies(config, resolvers)
}

// CreateCachedChain creates a chain with caching on top
func CreateCachedChain(config *ResolverConfig) (*CacheResolver, error) {
	// Create the standard chain
	chainResolver, err := CreateStandardChain(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain resolver: %w", err)
	}

	// Wrap it with cache
	return NewCacheResolver(config, chainResolver), nil
}
