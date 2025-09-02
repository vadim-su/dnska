package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/vadim-su/dnska/pkg/dns"
)

const (
	serverAddress   = "127.0.0.1:2053"
	defaultResolver = "127.0.0.1:2053"
	bufferSize      = 512
	defaultTTL      = 60
)

var defaultIPAddress = []byte{8, 8, 8, 8} // 8.8.8.8

type DNSServer struct {
	address         string
	resolverAddr    string
	conn            *net.UDPConn
	resolverCon     *net.UDPConn
	resolverUDPAddr *net.UDPAddr
}

func NewDNSServer(address, resolverAddr string) (*DNSServer, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to address: %w", err)
	}

	resolverUDPAddr, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve resolver address: %w", err)
	}

	// Create a separate UDP connection for resolver communication
	resolverCon, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resolver connection: %w", err)
	}

	return &DNSServer{
		address,
		resolverAddr,
		udpConn,
		resolverCon,
		resolverUDPAddr,
	}, nil
}

func (s *DNSServer) Close() error {
	err_conn := s.conn.Close()
	err_resolver := s.resolverCon.Close()

	if err_conn != nil {
		return fmt.Errorf("failed to close server connection: %w", err_conn)
	}
	if err_resolver != nil {
		return fmt.Errorf("failed to close resolver connection: %w", err_resolver)
	}

	return nil
}

func (s *DNSServer) handleRequest(
	request *dns.DNSRequest,
	clientAddr *net.UDPAddr,
) error {
	log.Printf("Received query from %s, Query ID: 0x%04X", clientAddr, request.Header.ID)

	answers, err := s.createAnswers(request.Questions)
	if err != nil {
		return fmt.Errorf("failed to create answers: %w", err)
	}

	response := dns.GenerateDNSResponse(
		request.Header.ID,
		request.Header.Flags,
		request.Questions,
		answers,
	)

	responseBytes := response.ToBytesWithCompression()
	_, err = s.conn.WriteToUDP(responseBytes, clientAddr)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	log.Printf("Sent response to %s with %d answers", clientAddr, len(answers))
	return nil
}

func (s *DNSServer) createAnswers(questions []dns.DNSQuestion) ([]dns.DNSAnswer, error) {
	// Only try forwarding if resolver is not the same as server address
	if s.resolverAddr != s.address {
		answers := s.forwardRequest(questions)
		if len(answers) > 0 {
			return answers, nil
		}
	}

	// Fallback to default answers if forwarding fails or not configured
	fallbackAnswers := make([]dns.DNSAnswer, 0, len(questions))

	for _, question := range questions {
		answer, err := s.createAnswerForQuestion(question)
		if err != nil {
			log.Printf("Failed to create answer for question: %v", err)
			continue
		}
		fallbackAnswers = append(fallbackAnswers, *answer)
	}
	return fallbackAnswers, nil
}

func (s *DNSServer) forwardRequest(questions []dns.DNSQuestion) []dns.DNSAnswer {
	conn, err := net.DialTimeout("udp", s.resolverAddr, 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	request := dns.GenerateDNSQuery(0, questions)
	requestBytes := request.ToBytes()

	_, err = conn.Write(requestBytes)
	if err != nil {
		return nil
	}

	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return nil
	}

	buf := make([]byte, bufferSize)
	size, err := conn.Read(buf)
	if err != nil {
		return nil
	}

	response, err := dns.NewDNSResponse(buf[:size])
	if err != nil {
		return nil
	}
	return response.Answers
}

func (s *DNSServer) createAnswerForQuestion(question dns.DNSQuestion) (*dns.DNSAnswer, error) {
	return dns.NewDNSAnswer(
		question.Name.ToBytes(),
		dns.CLASS_IN,
		dns.TYPE_A,
		defaultTTL,
		defaultIPAddress,
	)
}

func (s *DNSServer) Start() error {
	log.Printf("DNS server starting on %s (resolver: %s)", s.address, s.resolverAddr)
	buf := make([]byte, bufferSize)

	for {
		if err := s.processNextRequest(buf); err != nil {
			log.Printf("Error processing request: %v", err)
		}
	}
}

func (s *DNSServer) processNextRequest(buf []byte) error {
	size, clientAddr, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("error receiving data: %w", err)
	}

	request, err := dns.NewDNSRequest(buf[:size])
	if err != nil {
		return fmt.Errorf("failed to parse DNS request: %w", err)
	}

	return s.handleRequest(request, clientAddr)
}

func main() {
	addres := flag.String("address", serverAddress, "server address")
	resolver := flag.String("resolver", defaultResolver, "resolver server")
	flag.Parse()

	server, err := NewDNSServer(*addres, *resolver)
	if err != nil {
		log.Fatalf("Failed to create DNS server: %v", err)
	}

	defer func() {
		if err := server.Close(); err != nil {
			log.Printf("Error closing server: %v", err)
		}
	}()

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
