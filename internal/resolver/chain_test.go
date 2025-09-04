package resolver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/message"
	"github.com/vadim-su/dnska/pkg/dns/types"
	"github.com/vadim-su/dnska/pkg/dns/utils"
)

// MockResolver is a mock implementation of the Resolver interface for testing
type MockResolver struct {
	name          string
	shouldFail    bool
	failWithError error
	answers       []message.DNSAnswer
	callCount     int
	closeCalled   bool
}

func (m *MockResolver) Resolve(ctx context.Context, question message.DNSQuestion) ([]message.DNSAnswer, error) {
	m.callCount++

	if m.shouldFail {
		if m.failWithError != nil {
			return nil, m.failWithError
		}
		return nil, fmt.Errorf("mock resolver %s failed", m.name)
	}

	return m.answers, nil
}

func (m *MockResolver) ResolveAll(ctx context.Context, questions []message.DNSQuestion) ([]message.DNSAnswer, error) {
	var allAnswers []message.DNSAnswer

	for _, question := range questions {
		answers, err := m.Resolve(ctx, question)
		if err != nil {
			return nil, err
		}
		allAnswers = append(allAnswers, answers...)
	}

	return allAnswers, nil
}

func (m *MockResolver) Close() error {
	m.closeCalled = true
	return nil
}

func createTestQuestion() message.DNSQuestion {
	// Create domain name with proper format (length-prefixed labels)
	domainBytes := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	domainName, _, _ := utils.NewDomainName(domainBytes)
	return message.DNSQuestion{
		Name:  *domainName,
		Type:  types.DnsTypeClassToBytes(types.TYPE_A),
		Class: types.DnsTypeClassToBytes(types.CLASS_IN),
	}
}

func createTestAnswer() message.DNSAnswer {
	// Create domain name with proper format (length-prefixed labels)
	domainBytes := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	answer, _ := message.NewDNSAnswer(
		domainBytes,
		types.CLASS_IN,
		types.TYPE_A,
		300,
		[]byte{192, 0, 2, 1},
	)
	return *answer
}

func TestChainResolver_SingleResolver(t *testing.T) {
	// Create a mock resolver that succeeds
	mockResolver := &MockResolver{
		name:       "test-resolver",
		shouldFail: false,
		answers:    []message.DNSAnswer{createTestAnswer()},
	}

	// Create chain with single resolver
	chain, err := NewChainResolver(nil, mockResolver)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}
	defer chain.Close()

	// Test resolution
	ctx := context.Background()
	question := createTestQuestion()
	answers, err := chain.Resolve(ctx, question)

	if err != nil {
		t.Fatalf("Resolution failed: %v", err)
	}

	if len(answers) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(answers))
	}

	if mockResolver.callCount != 1 {
		t.Errorf("Expected resolver to be called once, called %d times", mockResolver.callCount)
	}
}

func TestChainResolver_Fallback(t *testing.T) {
	// Create two mock resolvers - first fails, second succeeds
	failingResolver := &MockResolver{
		name:       "failing-resolver",
		shouldFail: true,
	}

	successResolver := &MockResolver{
		name:       "success-resolver",
		shouldFail: false,
		answers:    []message.DNSAnswer{createTestAnswer()},
	}

	// Create chain
	chain, err := NewChainResolver(nil, failingResolver, successResolver)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}
	defer chain.Close()

	// Test resolution
	ctx := context.Background()
	question := createTestQuestion()
	answers, err := chain.Resolve(ctx, question)

	if err != nil {
		t.Fatalf("Resolution failed: %v", err)
	}

	if len(answers) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(answers))
	}

	// Both resolvers should have been called
	if failingResolver.callCount != 1 {
		t.Errorf("Expected failing resolver to be called once, called %d times", failingResolver.callCount)
	}

	if successResolver.callCount != 1 {
		t.Errorf("Expected success resolver to be called once, called %d times", successResolver.callCount)
	}
}

func TestChainResolver_StopsOnSuccess(t *testing.T) {
	// Create three mock resolvers - second one succeeds
	resolver1 := &MockResolver{
		name:       "resolver-1",
		shouldFail: true,
	}

	resolver2 := &MockResolver{
		name:       "resolver-2",
		shouldFail: false,
		answers:    []message.DNSAnswer{createTestAnswer()},
	}

	resolver3 := &MockResolver{
		name:       "resolver-3",
		shouldFail: false,
		answers:    []message.DNSAnswer{createTestAnswer()},
	}

	// Create chain
	chain, err := NewChainResolver(nil, resolver1, resolver2, resolver3)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}
	defer chain.Close()

	// Test resolution
	ctx := context.Background()
	question := createTestQuestion()
	answers, err := chain.Resolve(ctx, question)

	if err != nil {
		t.Fatalf("Resolution failed: %v", err)
	}

	if len(answers) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(answers))
	}

	// Check call counts
	if resolver1.callCount != 1 {
		t.Errorf("Expected resolver1 to be called once, called %d times", resolver1.callCount)
	}

	if resolver2.callCount != 1 {
		t.Errorf("Expected resolver2 to be called once, called %d times", resolver2.callCount)
	}

	// Resolver 3 should NOT be called since resolver 2 succeeded
	if resolver3.callCount != 0 {
		t.Errorf("Expected resolver3 to not be called, called %d times", resolver3.callCount)
	}
}

func TestChainResolver_NXDOMAIN(t *testing.T) {
	// Create a resolver that returns NXDOMAIN
	nxdomainResolver := &MockResolver{
		name:          "nxdomain-resolver",
		shouldFail:    true,
		failWithError: NewResolutionError(types.RCODE_NAME_ERROR, "domain not found", nil),
	}

	// Create chain with single resolver
	chain, err := NewChainResolver(nil, nxdomainResolver)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}
	defer chain.Close()

	// Test resolution
	ctx := context.Background()
	question := createTestQuestion()
	_, err = chain.Resolve(ctx, question)

	// Should get NXDOMAIN error
	if err == nil {
		t.Fatal("Expected NXDOMAIN error, got nil")
	}

	resErr, ok := err.(*ResolutionError)
	if !ok {
		t.Fatalf("Expected ResolutionError, got %T", err)
	}

	if resErr.Type != types.RCODE_NAME_ERROR {
		t.Errorf("Expected NXDOMAIN error code, got %v", resErr.Type)
	}
}

func TestChainResolver_AllFail(t *testing.T) {
	// Create multiple failing resolvers
	resolver1 := &MockResolver{
		name:       "resolver-1",
		shouldFail: true,
	}

	resolver2 := &MockResolver{
		name:       "resolver-2",
		shouldFail: true,
	}

	// Create chain
	chain, err := NewChainResolver(nil, resolver1, resolver2)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}
	defer chain.Close()

	// Test resolution
	ctx := context.Background()
	question := createTestQuestion()
	_, err = chain.Resolve(ctx, question)

	if err == nil {
		t.Fatal("Expected error when all resolvers fail")
	}

	// Both resolvers should have been tried
	if resolver1.callCount != 1 {
		t.Errorf("Expected resolver1 to be called once, called %d times", resolver1.callCount)
	}

	if resolver2.callCount != 1 {
		t.Errorf("Expected resolver2 to be called once, called %d times", resolver2.callCount)
	}
}

func TestChainResolver_ContextCancellation(t *testing.T) {
	// Create a slow resolver
	slowResolver := &MockResolver{
		name:       "slow-resolver",
		shouldFail: false,
		answers:    []message.DNSAnswer{createTestAnswer()},
	}

	// Create chain
	chain, err := NewChainResolver(nil, slowResolver)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}
	defer chain.Close()

	// Create context with immediate cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Test resolution with cancelled context
	question := createTestQuestion()
	_, err = chain.Resolve(ctx, question)

	if err == nil {
		t.Fatal("Expected error with cancelled context")
	}

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}
}

func TestChainResolver_AddRemoveResolver(t *testing.T) {
	// Create initial resolver
	resolver1 := &MockResolver{
		name:       "resolver-1",
		shouldFail: false,
		answers:    []message.DNSAnswer{createTestAnswer()},
	}

	// Create chain
	chain, err := NewChainResolver(nil, resolver1)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}
	defer chain.Close()

	// Check initial count
	if chain.GetResolverCount() != 1 {
		t.Errorf("Expected 1 resolver, got %d", chain.GetResolverCount())
	}

	// Add another resolver
	resolver2 := &MockResolver{
		name:       "resolver-2",
		shouldFail: false,
		answers:    []message.DNSAnswer{createTestAnswer()},
	}
	chain.AddResolver(resolver2, "resolver-2")

	if chain.GetResolverCount() != 2 {
		t.Errorf("Expected 2 resolvers after add, got %d", chain.GetResolverCount())
	}

	// Remove resolver
	removed := chain.RemoveResolver("resolver-2")
	if !removed {
		t.Error("Failed to remove resolver")
	}

	if chain.GetResolverCount() != 1 {
		t.Errorf("Expected 1 resolver after remove, got %d", chain.GetResolverCount())
	}

	// Try removing non-existent resolver
	removed = chain.RemoveResolver("non-existent")
	if removed {
		t.Error("Should not remove non-existent resolver")
	}
}

func TestChainResolver_Close(t *testing.T) {
	// Create multiple resolvers
	resolver1 := &MockResolver{name: "resolver-1"}
	resolver2 := &MockResolver{name: "resolver-2"}

	// Create chain
	chain, err := NewChainResolver(nil, resolver1, resolver2)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}

	// Close chain
	err = chain.Close()
	if err != nil {
		t.Errorf("Failed to close chain: %v", err)
	}

	// Check that all resolvers were closed
	if !resolver1.closeCalled {
		t.Error("Resolver1 was not closed")
	}

	if !resolver2.closeCalled {
		t.Error("Resolver2 was not closed")
	}
}

func TestChainResolver_WithPolicies(t *testing.T) {
	// Create resolvers with specific policies
	resolver1 := &MockResolver{
		name:       "resolver-1",
		shouldFail: true,
	}

	resolver2 := &MockResolver{
		name:       "resolver-2",
		shouldFail: false,
		answers:    []message.DNSAnswer{createTestAnswer()},
	}

	policies := []ResolverWithPolicy{
		{
			Resolver:    resolver1,
			Name:        "primary",
			SkipOnError: true,
			Timeout:     1 * time.Second,
		},
		{
			Resolver:    resolver2,
			Name:        "fallback",
			SkipOnError: false,
			Timeout:     2 * time.Second,
		},
	}

	// Create chain with policies
	chain, err := NewChainResolverWithPolicies(nil, policies)
	if err != nil {
		t.Fatalf("Failed to create chain resolver: %v", err)
	}
	defer chain.Close()

	// Test resolution
	ctx := context.Background()
	question := createTestQuestion()
	answers, err := chain.Resolve(ctx, question)

	if err != nil {
		t.Fatalf("Resolution failed: %v", err)
	}

	if len(answers) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(answers))
	}
}
