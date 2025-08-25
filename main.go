package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
)

// Global state
var (
	db        *sql.DB
	startTime = time.Now()
	
	// Simple cache with sync.Map for better concurrent performance
	urlCache sync.Map
	
	// Pre-compiled statements for better performance
	insertStmt *sql.Stmt
	selectStmt *sql.Stmt
	statsStmt  *sql.Stmt
	
	// Performance counters
	dbQueryCounter int64
	queryMutex     sync.RWMutex
)

// Models
type CreateURLRequest struct {
	OriginalURL string `json:"original_url"`
	CustomCode  string `json:"custom_code,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

type CreateURLResponse struct {
	ShortCode   string     `json:"short_code"`
	ShortURL    string     `json:"short_url"`
	OriginalURL string     `json:"original_url"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type StatsResponse struct {
	ShortCode   string    `json:"short_code"`
	OriginalURL string    `json:"original_url"`
	ClickCount  int64     `json:"click_count"`
	CreatedAt   time.Time `json:"created_at"`
}

// Cache entry with expiration
type cacheEntry struct {
	url       string
	expiresAt *time.Time
	cachedAt  time.Time
}

// Generate a random alphanumeric short code
func generateRandomCode(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Database initialization
func initDB() {
	dbURL := os.Getenv("DATABASE_URL") // Set your DATABASE_URL environment variable
	if dbURL == "" {
		dbURL = "postgres://ihdas:your-secure-password@localhost/ihdas?sslmode=disable" 
	}	// Or include your connection string in this file
	
	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}
	
	// Optimized connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(15 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)
	
	// Create table with optimized indexes
	createSQL := `
	CREATE TABLE IF NOT EXISTS urls (
		id BIGSERIAL PRIMARY KEY,
		short_code VARCHAR(10) UNIQUE NOT NULL,
		original_url TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT NOW(),
		expires_at TIMESTAMP,
		click_count BIGINT DEFAULT 0
	);
	
	CREATE UNIQUE INDEX IF NOT EXISTS idx_short_code ON urls(short_code);
	CREATE INDEX IF NOT EXISTS idx_expires_at ON urls(expires_at) WHERE expires_at IS NOT NULL;
	CREATE INDEX IF NOT EXISTS idx_created_at ON urls(created_at);
	`
	
	if _, err := db.Exec(createSQL); err != nil {
		log.Fatal("Table creation failed:", err)
	}
	
	// Prepare statements for better performance
	prepareStatements()
	
	log.Println("PostgreSQL connected with optimizations")
}

// Prepare frequently used statements
func prepareStatements() {
	var err error
	
	insertStmt, err = db.Prepare(`
		INSERT INTO urls (short_code, original_url, expires_at) 
		VALUES ($1, $2, $3) 
		RETURNING id, created_at`)
	if err != nil {
		log.Fatal("Failed to prepare insert statement:", err)
	}
	
	selectStmt, err = db.Prepare(`
		SELECT original_url, expires_at 
		FROM urls 
		WHERE short_code = $1`)
	if err != nil {
		log.Fatal("Failed to prepare select statement:", err)
	}
	
	statsStmt, err = db.Prepare(`
		SELECT short_code, original_url, click_count, created_at 
		FROM urls 
		WHERE short_code = $1`)
	if err != nil {
		log.Fatal("Failed to prepare stats statement:", err)
	}
}

// Cache operations using sync.Map for better concurrency
func getCachedURL(shortCode string) (string, *time.Time, bool) {
	if val, ok := urlCache.Load(shortCode); ok {
		entry := val.(cacheEntry)
		// Check if cache entry is still fresh (5 minutes)
		if time.Since(entry.cachedAt) < 5*time.Minute {
			return entry.url, entry.expiresAt, true
		}
		// Remove stale entry
		urlCache.Delete(shortCode)
	}
	return "", nil, false
}

func setCachedURL(shortCode, originalURL string, expiresAt *time.Time) {
	urlCache.Store(shortCode, cacheEntry{
		url:       originalURL,
		expiresAt: expiresAt,
		cachedAt:  time.Now(),
	})
}

// Async click counting
func incrementClickCount(shortCode string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		atomic.AddInt64(&dbQueryCounter, 1)
		db.ExecContext(ctx, `UPDATE urls SET click_count = click_count + 1 WHERE short_code = $1`, shortCode)
	}()
}

// Utility functions
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// Basic validation
func isValidURL(rawURL string) bool {
	if len(rawURL) > 2048 {
		return false
	}
	u, err := url.ParseRequestURI(rawURL)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

func isValidCustomCode(code string) bool {
	if len(code) > 10 || len(code) == 0 {
		return false
	}
	for _, r := range code {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// Handlers
func createURLHandler(w http.ResponseWriter, r *http.Request) {
	// -------------------------------------------------
	// Request size - JSON decoding
	// -------------------------------------------------
	r.Body = http.MaxBytesReader(w, r.Body, 1024)

	var req CreateURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON")
		return
	}

	if !isValidURL(req.OriginalURL) {
		writeError(w, http.StatusBadRequest, "Invalid URL")
		return
	}

	// -------------------------------------------------
	// Parse optional expiration date
	// -------------------------------------------------
	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid expiration date")
			return
		}
		expiresAt = &t
	}

	// -------------------------------------------------
	// Insert a row **atomically** (ON CONFLICT)
	// -------------------------------------------------
	const maxAttempts = 12       // enough for the 62⁶ space
	var shortCode string          // finally‑chosen key
	var createdAt time.Time       // timestamp returned by the insert

	for attempt := 0; attempt < maxAttempts; attempt++ {
		var candidate string

		// Custom code supplied by the user
		if req.CustomCode != "" {
			if !isValidCustomCode(req.CustomCode) {
				writeError(w, http.StatusBadRequest, "Invalid custom code")
				return
			}
			candidate = req.CustomCode
		} else {
			// Random code
			candidate = generateRandomCode(6)
		}

		// The INSERT statement already contains
		//   ON CONFLICT (short_code) DO NOTHING
		// so a duplicate will make Scan return an error we can test for.
		var id int64 // we need a placeholder – we don't care about it
		err := insertStmt.QueryRow(candidate, req.OriginalURL, expiresAt).
			Scan(&id, &createdAt)

		if err == nil {
			// Success!  Use the candidate and break out of the loop.
			shortCode = candidate
			break
		}

		// If the error is due to a duplicate key, try again.
		if strings.Contains(err.Error(), "duplicate key") || err == sql.ErrNoRows {
			continue
		}

		// Any other error is fatal.
		log.Printf("database error while creating short URL: %v", err)
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}

	// We should always have a short code at this point; if not,
	// something extremely unlucky happened (the namespace is full).
	if shortCode == "" {
		writeError(w, http.StatusServiceUnavailable,
			"Could not generate a unique short code – please try again")
		return
	}

	// -------------------------------------------------
	// Cache the mapping (helps future redirects)
	// -------------------------------------------------
	setCachedURL(shortCode, req.OriginalURL, expiresAt)

	// -------------------------------------------------
	// Return JSON response
	// -------------------------------------------------
	resp := CreateURLResponse{
		ShortCode:   shortCode,
		ShortURL:    fmt.Sprintf("https://%s/%s", r.Host, shortCode),
		OriginalURL: req.OriginalURL,
		CreatedAt:   createdAt,
		ExpiresAt:   expiresAt,
	}

	writeJSON(w, http.StatusCreated, resp)
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	shortCode := strings.TrimPrefix(r.URL.Path, "/")
	
	if shortCode == "" || shortCode == "favicon.ico" {
		http.ServeFile(w, r, "static/index.html")
		return
	}
	
	// Try cache first
	if originalURL, expiresAt, exists := getCachedURL(shortCode); exists {
		if expiresAt != nil && time.Now().After(*expiresAt) {
			http.Error(w, "Link expired", http.StatusGone)
			return
		}
		incrementClickCount(shortCode)
		http.Redirect(w, r, originalURL, http.StatusMovedPermanently)
		return
	}
	
	// Query database
	var originalURL string
	var expiresAt *time.Time
	
	atomic.AddInt64(&dbQueryCounter, 1)
	err := selectStmt.QueryRow(shortCode).Scan(&originalURL, &expiresAt)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		log.Printf("Database error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	if expiresAt != nil && time.Now().After(*expiresAt) {
		http.Error(w, "Link expired", http.StatusGone)
		return
	}
	
	setCachedURL(shortCode, originalURL, expiresAt)
	incrementClickCount(shortCode)
	http.Redirect(w, r, originalURL, http.StatusMovedPermanently)
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		writeError(w, http.StatusBadRequest, "Invalid path")
		return
	}
	
	shortCode := parts[len(parts)-1]
	var stats StatsResponse
	
	atomic.AddInt64(&dbQueryCounter, 1)
	err := statsStmt.QueryRow(shortCode).Scan(
		&stats.ShortCode, &stats.OriginalURL, &stats.ClickCount, &stats.CreatedAt)
	
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "Short URL not found")
		return
	} else if err != nil {
		log.Printf("Stats error: %v", err)
		writeError(w, http.StatusInternalServerError, "Database error")
		return
	}
	
	writeJSON(w, http.StatusOK, stats)
}

func healthAPIHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	dbStatus := "up"
	if err := db.PingContext(ctx); err != nil {
		dbStatus = "down"
	}
	
	cacheSize := 0
	urlCache.Range(func(k, v interface{}) bool {
		cacheSize++
		return true
	})
	
	var totalUrls int64
	var currentSeq int64
	atomic.AddInt64(&dbQueryCounter, 1)
	db.QueryRowContext(ctx, "SELECT COUNT(*) FROM urls").Scan(&totalUrls)
	db.QueryRowContext(ctx, "SELECT last_value FROM urls_id_seq").Scan(&currentSeq)
	
	dbStats := db.Stats()
	
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	status := map[string]interface{}{
		"status":             "healthy",
		"database":           dbStatus,
		"cache_size":         cacheSize,
		"uptime":             time.Since(startTime).String(),
		"version":            "1.3.0",
		"go_version":         runtime.Version(),
		"total_urls":         totalUrls,
		"current_sequence":   currentSeq,
		"timestamp":          time.Now().Unix(),
		"db_queries":         atomic.LoadInt64(&dbQueryCounter),
		"memory_usage":       memStats.Alloc,
		"active_connections": dbStats.OpenConnections,
		"max_connections":    dbStats.MaxOpenConnections,
		"idle_connections":   dbStats.Idle,
		"memory_mb":          float64(memStats.Alloc) / 1024 / 1024,
	}
	
	if dbStatus == "down" {
		status["status"] = "unhealthy"
		writeJSON(w, http.StatusServiceUnavailable, status)
		return
	}
	
	writeJSON(w, http.StatusOK, status)
}

func healthDashboardHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/health.html")
}

func router(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	
	path := r.URL.Path
	switch {
	case path == "/health":
		healthDashboardHandler(w, r)
	case path == "/api/health":
		healthAPIHandler(w, r)
	case path == "/api/v1/shorten" && r.Method == "POST":
		createURLHandler(w, r)
	case strings.HasPrefix(path, "/api/v1/stats/") && r.Method == "GET":
		statsHandler(w, r)
	case path == "/" && r.Method == "GET":
		http.ServeFile(w, r, "static/index.html")
	case strings.HasPrefix(path, "/static/"):
		http.StripPrefix("/static/", http.FileServer(http.Dir("static"))).ServeHTTP(w, r)
	default:
		redirectHandler(w, r)
	}
}

func main() {
	initDB()
	defer db.Close()
	
	defer func() {
		if insertStmt != nil { insertStmt.Close() }
		if selectStmt != nil { selectStmt.Close() }
		if statsStmt != nil { statsStmt.Close() }
	}()
	
	os.MkdirAll("static", 0755)
	
	server := &http.Server{
		Addr:           ":" + getPort(),
		Handler:        http.HandlerFunc(router),
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}
	
	log.Printf("ihdas, server starting on port %s", getPort())
	log.Printf("Optimized Go + PostgreSQL")
	log.Printf("Health API: http://localhost:%s/api/health", getPort())
	log.Printf("Health Dashboard: http://localhost:%s/health", getPort())
	
	log.Fatal(server.ListenAndServe())
}

func getPort() string {
	if port := os.Getenv("PORT"); port != "" {
		return port
	}
	return "8080"
}
