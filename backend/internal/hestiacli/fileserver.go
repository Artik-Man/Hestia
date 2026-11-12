// Package hestiacli provides the bounded HTTP file-transfer service used by hestia-cli.
package hestiacli

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const defaultMaxUploadBytes int64 = 128 << 20

var safeFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// FileServerConfig defines the listener, two fixed file roots, bearer-token file, and upload limit.
// Both roots must already exist as real directories and the token file must not be group/world accessible.
type FileServerConfig struct {
	Address        string
	UploadRoot     string
	DownloadRoot   string
	TokenFile      string
	MaxUploadBytes int64
}

// FileServer serves authenticated uploads and downloads confined to configured directory roots.
// It never executes uploaded files and owns the opened roots until Close is called.
type FileServer struct {
	uploadRoot   *os.Root
	downloadRoot *os.Root
	token        []byte
	maxUpload    int64
	handler      http.Handler
}

// uploadResponse reports the accepted filename and number of bytes written to the upload root.
type uploadResponse struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// errorResponse contains a stable public error message without local filesystem details.
type errorResponse struct {
	Error string `json:"error"`
}

// NewFileServer validates configuration, opens confined roots, and constructs the HTTP handler.
func NewFileServer(config FileServerConfig) (*FileServer, error) {
	if strings.TrimSpace(config.Address) == "" {
		return nil, errors.New("listen address is required")
	}
	if config.MaxUploadBytes == 0 {
		config.MaxUploadBytes = defaultMaxUploadBytes
	}
	if config.MaxUploadBytes < 1 || config.MaxUploadBytes > defaultMaxUploadBytes {
		return nil, fmt.Errorf("maximum upload size must be between 1 and %d bytes", defaultMaxUploadBytes)
	}
	if config.UploadRoot == config.DownloadRoot {
		return nil, errors.New("upload and download directories must be different")
	}
	token, err := readToken(config.TokenFile)
	if err != nil {
		return nil, err
	}
	uploadRoot, err := openDirectoryRoot(config.UploadRoot)
	if err != nil {
		return nil, fmt.Errorf("open upload directory: %w", err)
	}
	downloadRoot, err := openDirectoryRoot(config.DownloadRoot)
	if err != nil {
		_ = uploadRoot.Close()
		return nil, fmt.Errorf("open download directory: %w", err)
	}
	server := &FileServer{
		uploadRoot:   uploadRoot,
		downloadRoot: downloadRoot,
		token:        token,
		maxUpload:    config.MaxUploadBytes,
	}
	server.handler = server.routes()
	return server, nil
}

// Handler returns the authenticated HTTP handler for file-transfer endpoints.
func (server *FileServer) Handler() http.Handler {
	return server.handler
}

// Close releases the directory roots held by the server.
func (server *FileServer) Close() error {
	return errors.Join(server.uploadRoot.Close(), server.downloadRoot.Close())
}

// routes registers the fixed upload and download endpoints behind bearer-token authentication.
func (server *FileServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/files/upload/{name}", server.upload)
	mux.HandleFunc("GET /v1/files/download/{name}", server.download)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !server.authorized(request) {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="hestia-cli"`)
			writeError(writer, http.StatusUnauthorized, "unauthorized")
			return
		}
		mux.ServeHTTP(writer, request)
	})
}

// authorized compares the request bearer token with the configured secret without timing-sensitive equality.
func (server *FileServer) authorized(request *http.Request) bool {
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return false
	}
	provided := strings.TrimPrefix(value, "Bearer ")
	return len(provided) == len(server.token) && subtle.ConstantTimeCompare([]byte(provided), server.token) == 1
}

// upload atomically stores one bounded request body under a validated filename in the upload root.
func (server *FileServer) upload(writer http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if !validFileName(name) {
		writeError(writer, http.StatusBadRequest, "invalid filename")
		return
	}
	if request.ContentLength > server.maxUpload {
		writeError(writer, http.StatusRequestEntityTooLarge, "upload exceeds configured limit")
		return
	}
	temporary, file, err := server.createTemporaryUpload()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "cannot create upload")
		return
	}
	defer server.uploadRoot.Remove(temporary)
	written, copyErr := io.Copy(file, io.LimitReader(request.Body, server.maxUpload+1))
	if copyErr != nil {
		_ = file.Close()
		writeError(writer, http.StatusBadRequest, "cannot read upload")
		return
	}
	if written > server.maxUpload {
		_ = file.Close()
		writeError(writer, http.StatusRequestEntityTooLarge, "upload exceeds configured limit")
		return
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		writeError(writer, http.StatusInternalServerError, "cannot persist upload")
		return
	}
	if err := file.Close(); err != nil {
		writeError(writer, http.StatusInternalServerError, "cannot close upload")
		return
	}
	if err := server.uploadRoot.Rename(temporary, name); err != nil {
		writeError(writer, http.StatusInternalServerError, "cannot publish upload")
		return
	}
	writeJSON(writer, http.StatusCreated, uploadResponse{Name: name, Size: written})
}

// download streams one regular file from the configured download root without following symlinks.
func (server *FileServer) download(writer http.ResponseWriter, request *http.Request) {
	name := request.PathValue("name")
	if !validFileName(name) {
		writeError(writer, http.StatusBadRequest, "invalid filename")
		return
	}
	info, err := server.downloadRoot.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		writeError(writer, http.StatusNotFound, "file not found")
		return
	}
	file, err := server.downloadRoot.Open(name)
	if err != nil {
		writeError(writer, http.StatusNotFound, "file not found")
		return
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() {
		writeError(writer, http.StatusNotFound, "file not found")
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeContent(writer, request, name, openedInfo.ModTime(), file)
}

// createTemporaryUpload creates a private, collision-resistant file inside the configured upload root.
func (server *FileServer) createTemporaryUpload() (string, *os.File, error) {
	for range 8 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", nil, err
		}
		name := ".upload-" + hex.EncodeToString(suffix[:])
		file, err := server.uploadRoot.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return name, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, err
		}
	}
	return "", nil, errors.New("could not allocate a unique staging file")
}

// validFileName accepts one plain ASCII filename and rejects paths, hidden names, and control characters.
func validFileName(name string) bool {
	return safeFileName.MatchString(name) && filepath.Base(name) == name && name != "." && name != ".."
}

// openDirectoryRoot requires an existing absolute directory with no symlink components and opens it as a confined root.
func openDirectoryRoot(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("directory must be an absolute clean path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	if resolved != path {
		return nil, errors.New("directory path must not contain symlinks")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("directory must not be writable by group or other users")
	}
	return os.OpenRoot(path)
}

// readToken reads a nonempty bearer token from a regular file inaccessible to group and other users.
func readToken(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("token file must be an absolute clean path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("resolve token file: %w", err)
	}
	if resolved != path {
		return nil, errors.New("token file path must not contain symlinks")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read token file metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("token file must be a regular file with no group or other permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 4096 || strings.IndexFunc(token, func(character rune) bool {
		return character < 0x21 || character > 0x7e
	}) >= 0 {
		return nil, errors.New("token must contain 32 to 4096 printable non-space ASCII characters")
	}
	return []byte(token), nil
}

// writeError returns a small JSON error response without exposing filesystem paths or operating-system details.
func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, errorResponse{Error: message})
}

// writeJSON encodes a JSON response with the supplied HTTP status.
func writeJSON[T any](writer http.ResponseWriter, status int, value T) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
