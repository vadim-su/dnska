package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/message"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

// Resolve performs DNS resolution for the given question by forwarding to configured servers
func (r *ForwardResolver) Resolve(ctx context.Context, question message.DNSQuestion) ([]message.DNSAnswer, error) {
	var lastErr error

	// Try each forward server
	for _, server := range r.servers {
		answers, err := r.resolveWithServer(ctx, question, server)
		if err == nil {
			return answers, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("all forward servers failed, last error: %w", lastErr)
}

// ResolveAll performs DNS resolution for multiple questions
func (r *ForwardResolver) ResolveAll(ctx context.Context, questions []message.DNSQuestion) ([]message.DNSAnswer, error) {
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
func (r *ForwardResolver) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// resolveWithServer attempts to resolve a question with a specific server
func (r *ForwardResolver) resolveWithServer(ctx context.Context, question message.DNSQuestion, server string) ([]message.DNSAnswer, error) {
	// Create DNS query
	query := message.GenerateDNSQuery(0, []message.DNSQuestion{question})

	// Send query with retries
	var response *message.DNSResponse
	var err error

	for attempt := 0; attempt <= r.config.MaxRetries; attempt++ {
		response, err = r.sendQuery(ctx, query, server)
		if err == nil {
			break
		}

		// If this was the last attempt, return the error
		if attempt == r.config.MaxRetries {
			return nil, fmt.Errorf("query failed after %d attempts: %w", r.config.MaxRetries+1, err)
		}

		// Wait before retrying (exponential backoff)
		select {
		case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Check response code
	if response.Header.Flags&types.FLAG_RCODE_NO_ERROR != types.FLAG_RCODE_NO_ERROR {
		return nil, NewResolutionError(types.DNSRCode(response.Header.Flags&0xF), "server returned error", nil)
	}

	return response.Answers, nil
}

// sendQuery sends a DNS query to a server and returns the response
func (r *ForwardResolver) sendQuery(ctx context.Context, query *message.DNSResponse, server string) (*message.DNSResponse, error) {
	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address %s: %w", server, err)
	}

	// Set deadline for the operation
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(r.config.Timeout)
	}

	err = r.client.SetWriteDeadline(deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Send query
	queryBytes := query.ToBytesWithCompression()
	_, err = r.client.WriteToUDP(queryBytes, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}

	// Set read deadline
	err = r.client.SetReadDeadline(deadline)
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Receive response
	buffer := make([]byte, 4096)
	size, _, err := r.client.ReadFromUDP(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to receive response: %w", err)
	}

	// Parse response
	response, err := message.NewDNSResponse(buffer[:size])
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return response, nil
}
