package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vadim-su/dnska/pkg/dns/message"
	"github.com/vadim-su/dnska/pkg/dns/types"
	"github.com/vadim-su/dnska/pkg/dns/utils"
)

// Resolve performs DNS resolution for the given question using recursive resolution
func (r *RecursiveResolver) Resolve(ctx context.Context, question message.DNSQuestion) ([]message.DNSAnswer, error) {
	return r.resolveRecursive(ctx, question, r.rootServer, 0)
}

// ResolveAll performs DNS resolution for multiple questions
func (r *RecursiveResolver) ResolveAll(ctx context.Context, questions []message.DNSQuestion) ([]message.DNSAnswer, error) {
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
func (r *RecursiveResolver) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// resolveRecursive performs recursive DNS resolution
func (r *RecursiveResolver) resolveRecursive(ctx context.Context, question message.DNSQuestion, server string, depth int) ([]message.DNSAnswer, error) {
	// Check recursion depth limit
	if depth >= r.config.RecursionDepth {
		return nil, NewResolutionError(types.RCODE_SERVER_FAILURE, "recursion depth limit exceeded", nil)
	}

	// Create DNS query
	query := message.GenerateDNSQuery(uint16(depth), []message.DNSQuestion{question})

	// Send query to server
	response, err := r.sendQuery(ctx, query, server)
	if err != nil {
		return nil, fmt.Errorf("failed to query server %s: %w", server, err)
	}

	// Check response code
	if response.Header.Flags&types.FLAG_RCODE_NO_ERROR != types.FLAG_RCODE_NO_ERROR {
		return nil, NewResolutionError(types.DNSRCode(response.Header.Flags&0xF), "server returned error", nil)
	}

	// If we have answers, return them
	if len(response.Answers) > 0 {
		return response.Answers, nil
	}

	// If we have authoritative answers but no answers, domain doesn't exist
	if response.Header.Flags&types.FLAG_AA_AUTHORITATIVE == types.FLAG_AA_AUTHORITATIVE {
		return nil, NewResolutionError(types.RCODE_NAME_ERROR, "domain not found", nil)
	}

	// For now, return server failure as we don't have authority/additional record parsing
	// This is a simplified implementation
	return nil, NewResolutionError(types.RCODE_SERVER_FAILURE, "no authoritative servers found", nil)
}

// sendQuery sends a DNS query to a server and returns the response
func (r *RecursiveResolver) sendQuery(ctx context.Context, query *message.DNSResponse, server string) (*message.DNSResponse, error) {
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

// Helper function to create a DNS question for NS resolution
func createNSQuestion(nsName string) (message.DNSQuestion, error) {
	domainName, _, err := utils.NewDomainName([]byte(nsName))
	if err != nil {
		return message.DNSQuestion{}, err
	}

	return message.DNSQuestion{
		Name:  *domainName,
		Type:  types.DnsTypeClassToBytes(types.TYPE_A),
		Class: types.DnsTypeClassToBytes(types.CLASS_IN),
	}, nil
}
