package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/vadim-su/dnska/internal/config"
	"github.com/vadim-su/dnska/internal/resolver"
	"github.com/vadim-su/dnska/internal/storage"
	"github.com/vadim-su/dnska/pkg/dns/message"
	"github.com/vadim-su/dnska/pkg/dns/records"
	"github.com/vadim-su/dnska/pkg/dns/types"
)

const (
	defaultBufferSize = 512
	maxBufferSize     = 4096
)

type Server struct {
	config   *config.Config
	storage  storage.Storage
	resolver resolver.Resolver

	udpConn     *net.UDPConn
	tcpListener *net.TCPListener

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.RWMutex
	started bool
	closed  bool
}

func New(cfg *config.Config) (*Server, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:  cfg,
		ctx:     ctx,
		cancel:  cancel,
		started: false,
		closed:  false,
	}

	if err := s.initStorage(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	if err := s.initResolver(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize resolver: %w", err)
	}

	return s, nil
}

func NewWithDefaults() (*Server, error) {
	return New(config.DefaultConfig())
}

func (s *Server) initStorage() error {
	var err error

	switch s.config.Storage.Type {
	case "memory":
		validationConfig := &storage.ValidationConfig{
			Enabled:         true,
			AllowUnderscore: true,
		}
		s.storage, err = storage.NewMemoryStorage(validationConfig)
	case "surrealdb":
		storageConfig := &storage.StorageConfig{
			Type:             storage.StorageTypeSurrealDB,
			ConnectionString: s.config.Storage.DSN,
			ValidationConfig: &storage.ValidationConfig{
				Enabled:         true,
				AllowUnderscore: true,
			},
		}
		s.storage, err = storage.NewSurrealDBStorage(s.ctx, storageConfig)
	default:
		validationConfig := &storage.ValidationConfig{
			Enabled:         true,
			AllowUnderscore: true,
		}
		s.storage, err = storage.NewMemoryStorage(validationConfig)
	}

	if err != nil {
		return fmt.Errorf("failed to create %s storage: %w", s.config.Storage.Type, err)
	}

	log.Printf("Storage initialized: %s", s.config.Storage.Type)
	return nil
}

func (s *Server) initResolver() error {
	resolverConfig := &resolver.ResolverConfig{
		Timeout:        s.config.Resolver.Timeout,
		MaxRetries:     s.config.Resolver.MaxRetries,
		CacheTTL:       s.config.Cache.TTL,
		ForwardServers: s.config.Resolver.ForwardServers,
		RootServers:    s.config.Resolver.RootServers,
		RecursionDepth: s.config.Resolver.RecursionDepth,
	}

	forwardResolver, err := resolver.NewForwardResolver(resolverConfig)
	if err != nil {
		return fmt.Errorf("failed to create forward resolver: %w", err)
	}

	s.resolver = resolver.NewCacheResolver(resolverConfig, forwardResolver)

	log.Printf("Resolver initialized: cached forward resolver with servers %v", s.config.Resolver.ForwardServers)
	return nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("server has been closed")
	}
	s.started = true
	s.mu.Unlock()

	if s.config.Server.EnableUDP {
		if err := s.startUDP(); err != nil {
			return fmt.Errorf("failed to start UDP server: %w", err)
		}
	}

	if s.config.Server.EnableTCP {
		if err := s.startTCP(); err != nil {
			if s.udpConn != nil {
				s.udpConn.Close()
			}
			return fmt.Errorf("failed to start TCP server: %w", err)
		}
	}

	log.Printf("DNS server started on %s (UDP: %v, TCP: %v)",
		s.config.Server.Address,
		s.config.Server.EnableUDP,
		s.config.Server.EnableTCP)

	s.wg.Wait()
	return nil
}

func (s *Server) startUDP() error {
	addr, err := net.ResolveUDPAddr("udp", s.config.Server.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	s.udpConn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	s.wg.Add(1)
	go s.handleUDP()

	return nil
}

func (s *Server) startTCP() error {
	addr, err := net.ResolveTCPAddr("tcp", s.config.Server.Address)
	if err != nil {
		return fmt.Errorf("failed to resolve TCP address: %w", err)
	}

	s.tcpListener, err = net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on TCP: %w", err)
	}

	s.wg.Add(1)
	go s.handleTCP()

	return nil
}

func (s *Server) handleUDP() {
	defer s.wg.Done()

	buf := make([]byte, maxBufferSize)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if s.config.Server.ReadTimeout > 0 {
			s.udpConn.SetReadDeadline(time.Now().Add(s.config.Server.ReadTimeout))
		}

		n, clientAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if s.ctx.Err() != nil {
				return
			}
			log.Printf("UDP read error: %v", err)
			continue
		}

		s.wg.Add(1)
		go s.handleUDPRequest(buf[:n], clientAddr)
	}
}

func (s *Server) handleUDPRequest(data []byte, clientAddr *net.UDPAddr) {
	defer s.wg.Done()

	request, err := message.NewDNSRequest(data)
	if err != nil {
		log.Printf("Failed to parse DNS request from %s: %v", clientAddr, err)
		return
	}

	response, err := s.processRequest(request)
	if err != nil {
		log.Printf("Failed to process request from %s: %v", clientAddr, err)
		response = s.createErrorResponse(request, types.RCODE_SERVER_FAILURE)
	}

	responseBytes := response.ToBytesWithCompression()

	if s.config.Server.WriteTimeout > 0 {
		s.udpConn.SetWriteDeadline(time.Now().Add(s.config.Server.WriteTimeout))
	}

	if _, err := s.udpConn.WriteToUDP(responseBytes, clientAddr); err != nil {
		log.Printf("Failed to send response to %s: %v", clientAddr, err)
	}
}

func (s *Server) handleTCP() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		conn, err := s.tcpListener.AcceptTCP()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			log.Printf("TCP accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go s.handleTCPConnection(conn)
	}
}

func (s *Server) handleTCPConnection(conn *net.TCPConn) {
	defer s.wg.Done()
	defer conn.Close()

	if s.config.Server.ReadTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.config.Server.ReadTimeout))
	}

	lengthBuf := make([]byte, 2)
	if _, err := conn.Read(lengthBuf); err != nil {
		log.Printf("Failed to read message length: %v", err)
		return
	}

	length := (uint16(lengthBuf[0]) << 8) | uint16(lengthBuf[1])

	data := make([]byte, length)
	if _, err := conn.Read(data); err != nil {
		log.Printf("Failed to read message data: %v", err)
		return
	}

	request, err := message.NewDNSRequest(data)
	if err != nil {
		log.Printf("Failed to parse DNS request: %v", err)
		return
	}

	response, err := s.processRequest(request)
	if err != nil {
		log.Printf("Failed to process request: %v", err)
		response = s.createErrorResponse(request, types.RCODE_SERVER_FAILURE)
	}

	responseBytes := response.ToBytesWithCompression()
	responseLength := uint16(len(responseBytes))

	if s.config.Server.WriteTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(s.config.Server.WriteTimeout))
	}

	responseLengthBuf := []byte{byte(responseLength >> 8), byte(responseLength)}
	if _, err := conn.Write(responseLengthBuf); err != nil {
		log.Printf("Failed to write response length: %v", err)
		return
	}

	if _, err := conn.Write(responseBytes); err != nil {
		log.Printf("Failed to write response data: %v", err)
	}
}

func (s *Server) processRequest(request *message.DNSRequest) (*message.DNSResponse, error) {
	answers := make([]message.DNSAnswer, 0)

	for _, question := range request.Questions {
		questionAnswers, err := s.resolveQuestion(question)
		if err != nil {
			log.Printf("Failed to resolve question %s: %v", question.Name.String(), err)
			continue
		}
		answers = append(answers, questionAnswers...)
	}

	response := message.GenerateDNSResponse(
		request.Header.ID,
		request.Header.Flags,
		request.Questions,
		answers,
	)

	if len(answers) == 0 {
		// Set NXDOMAIN flag in response
		response.Header.Flags |= types.DNSFlag(types.RCODE_NAME_ERROR)
	}

	return response, nil
}

func (s *Server) resolveQuestion(question message.DNSQuestion) ([]message.DNSAnswer, error) {
	// Convert question type bytes to DNSType
	questionType := types.DNSType(uint16(question.Type[0])<<8 | uint16(question.Type[1]))
	questionName := question.Name.String()

	// Try to get records from storage first (for authoritative zones)
	storageRecords, err := s.storage.GetRecords(s.ctx, questionName, questionType)
	if err == nil && len(storageRecords) > 0 {
		return s.recordsToAnswers(storageRecords, question)
	}

	// If no records in storage and resolver is configured, use resolver
	if s.resolver != nil {
		resolverCtx, cancel := context.WithTimeout(s.ctx, s.config.Resolver.Timeout)
		defer cancel()

		answers, err := s.resolver.Resolve(resolverCtx, question)
		if err != nil {
			return nil, fmt.Errorf("resolver failed: %w", err)
		}
		return answers, nil
	}

	return nil, fmt.Errorf("no records found and no resolver configured")
}

func (s *Server) recordsToAnswers(storageRecords []records.DNSRecord, question message.DNSQuestion) ([]message.DNSAnswer, error) {
	answers := make([]message.DNSAnswer, 0, len(storageRecords))

	for _, record := range storageRecords {
		// Convert question.Class bytes to DNSClass
		questionClass := types.DNSClass(uint16(question.Class[0])<<8 | uint16(question.Class[1]))

		answer, err := message.NewDNSAnswer(
			question.Name.ToBytes(),
			questionClass,
			record.Type(),
			record.TTL(),
			record.Data(),
		)
		if err != nil {
			log.Printf("Failed to create answer for record %s: %v", record.Name(), err)
			continue
		}
		answers = append(answers, *answer)
	}

	return answers, nil
}

func (s *Server) createErrorResponse(request *message.DNSRequest, rcode types.DNSRCode) *message.DNSResponse {
	response := message.GenerateDNSResponse(
		request.Header.ID,
		request.Header.Flags,
		request.Questions,
		[]message.DNSAnswer{},
	)
	// Set the response code in flags
	response.Header.Flags = (response.Header.Flags & 0xFFF0) | types.DNSFlag(rcode)
	return response
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("server already closed")
	}
	s.closed = true
	s.mu.Unlock()

	s.cancel()

	var errs []error

	if s.udpConn != nil {
		if err := s.udpConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close UDP connection: %w", err))
		}
	}

	if s.tcpListener != nil {
		if err := s.tcpListener.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close TCP listener: %w", err))
		}
	}

	if s.resolver != nil {
		if err := s.resolver.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close resolver: %w", err))
		}
	}

	if s.storage != nil {
		if err := s.storage.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close storage: %w", err))
		}
	}

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		errs = append(errs, fmt.Errorf("timeout waiting for handlers to finish"))
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errs)
	}

	return nil
}

// AddRecord adds a DNS record to the storage (for dynamic updates)
func (s *Server) AddRecord(record records.DNSRecord) error {
	if s.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	return s.storage.PutRecord(s.ctx, record)
}

// RemoveRecord removes a DNS record from storage
func (s *Server) RemoveRecord(name string, recordType types.DNSType) error {
	if s.storage == nil {
		return fmt.Errorf("storage not initialized")
	}
	return s.storage.DeleteRecord(s.ctx, name, recordType)
}

// GetStorage returns the storage backend (for external management)
func (s *Server) GetStorage() storage.Storage {
	return s.storage
}

func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.started && !s.closed
}

func (s *Server) GetConfig() *config.Config {
	return s.config
}

func (s *Server) GetStats() ServerStats {
	return ServerStats{
		Running: s.IsRunning(),
		Address: s.config.Server.Address,
		Type:    "cached-forward", // Always using cached forward resolver
	}
}

type ServerStats struct {
	Running bool
	Address string
	Type    string
}
