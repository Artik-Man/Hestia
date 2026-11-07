// Package keeneticrci provides authenticated, bounded Keenetic RCI requests and typed router inventories.
package keeneticrci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

const tokenHeader = "X-NDMA-TKN"

const (
	defaultMaxResponseBytes int64 = 2 * 1024 * 1024
	maxResponseBytes        int64 = 16 * 1024 * 1024
	maxRequestBytes               = 1 * 1024 * 1024
)

// Method is an HTTP method accepted by the authenticated RCI client.
type Method string

const (
	// MethodGet reads one RCI resource without a request body.
	MethodGet Method = http.MethodGet
	// MethodPost sends an RCI JSON command; the operation declaration classifies its state effect.
	MethodPost Method = http.MethodPost
)

// ErrorKind identifies an RCI client failure without embedding credentials or response bodies.
type ErrorKind string

const (
	// ErrorInvalidConfig marks an invalid endpoint or client limit.
	ErrorInvalidConfig ErrorKind = "invalid_config"
	// ErrorTokenUnavailable marks a missing, unreadable, or invalid token.
	ErrorTokenUnavailable ErrorKind = "token_unavailable"
	// ErrorTokenPermissions marks a token file accessible to group or other users.
	ErrorTokenPermissions ErrorKind = "token_permissions"
	// ErrorInvalidOperation marks an invalid method, path, or payload declaration.
	ErrorInvalidOperation ErrorKind = "invalid_operation"
	// ErrorWriteNotAllowed marks a state-changing operation rejected by client policy.
	ErrorWriteNotAllowed ErrorKind = "write_not_allowed"
	// ErrorTransport marks an HTTP transport failure.
	ErrorTransport ErrorKind = "transport"
	// ErrorHTTPStatus marks a non-success HTTP response.
	ErrorHTTPStatus ErrorKind = "http_status"
	// ErrorContentType marks a response that is not JSON.
	ErrorContentType ErrorKind = "content_type"
	// ErrorInvalidJSON marks a malformed JSON response.
	ErrorInvalidJSON ErrorKind = "invalid_json"
	// ErrorResponseTooLarge marks a response exceeding the configured limit.
	ErrorResponseTooLarge ErrorKind = "response_too_large"
	// ErrorRequestTooLarge marks an operation payload exceeding the hard request limit.
	ErrorRequestTooLarge ErrorKind = "request_too_large"
	// ErrorSchema marks a JSON response that does not match the observed RCI contract.
	ErrorSchema ErrorKind = "schema"
)

// Error is a redacted RCI failure with a stable machine-readable category.
type Error struct {
	Kind   ErrorKind
	Status int
}

// Error returns a safe error string that contains no token or response body.
func (e *Error) Error() string {
	if e.Status != 0 {
		return string(e.Kind) + ":" + http.StatusText(e.Status)
	}
	return string(e.Kind)
}

// TokenSource supplies a fresh access token without exposing it to operation callers.
type TokenSource interface {
	// ReadToken returns a non-empty access token or a redacted error.
	ReadToken(context.Context) (string, error)
}

// FileTokenSource reads an owner-only token file for each request.
type FileTokenSource struct {
	Path string
}

// ReadToken returns the trimmed token after checking file type, size, and permissions.
func (s FileTokenSource) ReadToken(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", &Error{Kind: ErrorTokenUnavailable}
	}
	pathInfo, err := os.Lstat(s.Path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(pathInfo) {
		return "", &Error{Kind: ErrorTokenPermissions}
	}
	file, err := os.OpenFile(s.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", &Error{Kind: ErrorTokenUnavailable}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ownedByCurrentUser(info) || !os.SameFile(pathInfo, info) {
		return "", &Error{Kind: ErrorTokenUnavailable}
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return "", &Error{Kind: ErrorTokenUnavailable}
	}
	token := strings.TrimSpace(string(data))
	if token == "" || strings.ContainsAny(token, "\r\n\t ") {
		return "", &Error{Kind: ErrorTokenUnavailable}
	}
	for _, r := range token {
		if r < 0x21 || r > 0x7e {
			return "", &Error{Kind: ErrorTokenUnavailable}
		}
	}
	return token, nil
}

// ownedByCurrentUser confirms the token file belongs to the process reading it.
func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

// Operation names one RCI call and declares whether it may change router state, independent of HTTP method.
type Operation struct {
	Name         string
	Path         string
	Method       Method
	ChangesState bool
}

// Config defines the fixed RCI endpoint, token source, and request limits.
type Config struct {
	BaseURL          string
	TokenSource      TokenSource
	Timeout          time.Duration
	MaxResponseBytes int64
	AllowWrites      bool
}

// Response contains bounded JSON and safe transport metadata; it never contains the token.
type Response struct {
	Status      int
	ContentType string
	Body        json.RawMessage
	BodyBytes   int64
	BodySHA256  string
}

// Client injects the configured token into validated RCI operations.
type Client struct {
	baseURL          url.URL
	tokenSource      TokenSource
	httpClient       *http.Client
	maxResponseBytes int64
	allowWrites      bool
}

// NewClient validates endpoint policy and creates a no-redirect, no-proxy RCI client.
func NewClient(config Config) (*Client, error) {
	if config.TokenSource == nil {
		return nil, &Error{Kind: ErrorInvalidConfig}
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	parsed, err := url.Parse(config.BaseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, &Error{Kind: ErrorInvalidConfig}
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || config.Timeout <= 0 || config.MaxResponseBytes <= 0 || config.MaxResponseBytes > maxResponseBytes {
		return nil, &Error{Kind: ErrorInvalidConfig}
	}
	if parsed.Scheme == "http" {
		address := net.ParseIP(parsed.Hostname())
		if address == nil || !address.IsLoopback() {
			return nil, &Error{Kind: ErrorInvalidConfig}
		}
	}
	transport := &http.Transport{Proxy: nil}
	return &Client{
		baseURL:          *parsed,
		tokenSource:      config.TokenSource,
		httpClient:       &http.Client{Transport: transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		maxResponseBytes: config.MaxResponseBytes,
		allowWrites:      config.AllowWrites,
	}, nil
}

// Do executes one declared RCI operation with the configured token and returns validated JSON.
func (c *Client) Do(ctx context.Context, operation Operation, payload json.RawMessage) (Response, error) {
	if len(payload) > maxRequestBytes {
		return Response{}, &Error{Kind: ErrorRequestTooLarge}
	}
	if err := validateOperation(operation, payload); err != nil {
		return Response{}, err
	}
	if operation.ChangesState && !c.allowWrites {
		return Response{}, &Error{Kind: ErrorWriteNotAllowed}
	}
	token, err := c.tokenSource.ReadToken(ctx)
	if err != nil {
		return Response{}, &Error{Kind: ErrorTokenUnavailable}
	}
	endpoint := c.baseURL
	endpoint.Path = operation.Path
	requestBody := bytes.NewReader(payload)
	var body io.Reader
	if len(payload) > 0 {
		body = requestBody
	}
	request, err := http.NewRequestWithContext(ctx, string(operation.Method), endpoint.String(), body)
	if err != nil {
		return Response{}, &Error{Kind: ErrorInvalidOperation}
	}
	request.Header.Set(tokenHeader, token)
	request.Header.Set("Accept", "application/json")
	if len(payload) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	httpResponse, err := c.httpClient.Do(request)
	if err != nil {
		return Response{}, &Error{Kind: ErrorTransport}
	}
	defer httpResponse.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body, c.maxResponseBytes+1))
	if err != nil {
		return Response{}, &Error{Kind: ErrorTransport}
	}
	if int64(len(responseBody)) > c.maxResponseBytes {
		return Response{}, &Error{Kind: ErrorResponseTooLarge}
	}
	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		return Response{}, &Error{Kind: ErrorHTTPStatus, Status: httpResponse.StatusCode}
	}
	mediaType, _, err := mime.ParseMediaType(httpResponse.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return Response{}, &Error{Kind: ErrorContentType}
	}
	if !json.Valid(responseBody) {
		return Response{}, &Error{Kind: ErrorInvalidJSON}
	}
	digest := sha256.Sum256(responseBody)
	return Response{
		Status:      httpResponse.StatusCode,
		ContentType: httpResponse.Header.Get("Content-Type"),
		Body:        json.RawMessage(responseBody),
		BodyBytes:   int64(len(responseBody)),
		BodySHA256:  hex.EncodeToString(digest[:]),
	}, nil
}

// validateOperation rejects malformed paths, undeclared writes, and invalid JSON bodies.
func validateOperation(operation Operation, payload json.RawMessage) error {
	if operation.Name == "" || (operation.Method != MethodGet && operation.Method != MethodPost) || !validRCIPath(operation.Path) {
		return &Error{Kind: ErrorInvalidOperation}
	}
	if operation.Method == MethodGet && (len(payload) != 0 || operation.ChangesState) {
		return &Error{Kind: ErrorInvalidOperation}
	}
	if operation.Method == MethodPost && (len(payload) == 0 || !json.Valid(payload)) {
		return &Error{Kind: ErrorInvalidOperation}
	}
	if operation.Method == MethodPost && !operation.ChangesState && operation.Path != "/rci/show" {
		return &Error{Kind: ErrorInvalidOperation}
	}
	return nil
}

// validRCIPath accepts only absolute canonical RCI paths with command-safe ASCII segments.
func validRCIPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#%\\\r\n") {
		return false
	}
	segments := strings.Split(path[1:], "/")
	if len(segments) < 2 || segments[0] != "rci" {
		return false
	}
	for _, segment := range segments[1:] {
		if segment == "" {
			return false
		}
		for _, character := range segment {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') &&
				character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

// RciErrorKind returns the stable category for an error produced by this package.
func RciErrorKind(err error) (ErrorKind, bool) {
	var rciError *Error
	if !errors.As(err, &rciError) {
		return "", false
	}
	return rciError.Kind, true
}
