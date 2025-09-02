# Build stage
FROM golang:1.25-alpine AS builder

# Set working directory
WORKDIR /app

# Install git and ca-certificates (needed for fetching dependencies)
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o dnska ./cmd/dnska

# Final stage
FROM scratch

# Import from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /app/dnska /dnska

# Expose DNS ports
EXPOSE 53/udp
EXPOSE 53/tcp

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/dnska", "health"]

# Set non-root user
USER 1000:1000

# Run the binary
ENTRYPOINT ["/dnska"]
CMD ["server"]
