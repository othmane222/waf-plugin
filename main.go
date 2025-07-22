package signature

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Logger for the plugin
var Logger = log.New(os.Stdout, "[Signature Verification Plugin] ", log.LstdFlags)

// Config holds the plugin configuration
type Config struct {
	// No configuration needed for signature verification only
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{}
}

// SignatureVerifier is the plugin implementation
type SignatureVerifier struct {
	next http.Handler
	name string
}

// New creates a new SignatureVerifier plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	Logger.Printf("Initializing Signature Verification plugin '%s'", name)
	return &SignatureVerifier{
		next: next,
		name: name,
	}, nil
}

// logDebug logs a message
func logDebug(format string, v ...interface{}) {
	Logger.Printf(format, v...)
}

// Map of accented characters to their non-accented equivalents
var accentedChars = map[rune]string{
	'à': "a", 'á': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a", 'æ': "ae", 'ç': "c", 'è': "e", 'é': "e", 'ê': "e",
	'ë': "e", 'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ð': "d", 'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o",
	'ø': "o", 'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ý': "y", 'ÿ': "y", 'š': "s", 'ž': "z", 'ñ': "n",
	'α': "a", 'β': "b", 'γ': "g", 'δ': "d", 'ε': "e", 'ζ': "z", 'η': "h", 'θ': "th", 'ι': "i", 'κ': "k", 'λ': "l",
	'μ': "m", 'ν': "n", 'ξ': "x", 'ο': "o", 'π': "p", 'ρ': "r", 'σ': "s", 'τ': "t", 'υ': "y", 'φ': "f", 'χ': "ch",
	'ψ': "ps", 'ω': "o",
	// Upper case versions
	'À': "a", 'Á': "a", 'Â': "a", 'Ã': "a", 'Ä': "a", 'Å': "a", 'Æ': "ae", 'Ç': "c", 'È': "e", 'É': "e", 'Ê': "e",
	'Ë': "e", 'Ì': "i", 'Í': "i", 'Î': "i", 'Ï': "i", 'Ò': "o", 'Ó': "o", 'Ô': "o", 'Õ': "o", 'Ö': "o",
	'Ø': "o", 'Ù': "u", 'Ú': "u", 'Û': "u", 'Ü': "u", 'Ý': "y",
}

// SignatureUtils contains methods for signature verification
type signatureUtils struct{}

// removeAccents removes accented characters from the string
func (su *signatureUtils) removeAccents(input string) string {
	var result strings.Builder
	for _, r := range input {
		if replacement, ok := accentedChars[r]; ok {
			result.WriteString(replacement)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// allowOnly filters the string to keep only allowed characters
func (su *signatureUtils) allowOnly(input string, allowedChars string) string {
	var result strings.Builder
	input = strings.ToLower(input)
	for _, r := range input {
		if strings.ContainsRune(allowedChars, r) {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// extractValues recursively extracts values from JSON
func (su *signatureUtils) extractValues(jsonObj interface{}) []string {
	var values []string

	switch v := jsonObj.(type) {
	case map[string]interface{}:
		// Get all keys and sort them
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Extract values in sorted key order
		for _, key := range keys {
			extracted := su.extractValues(v[key])
			values = append(values, extracted...)
		}
	case []interface{}:
		for _, item := range v {
			extracted := su.extractValues(item)
			values = append(values, extracted...)
		}
	case string:
		values = append(values, v)
	case float64:
		values = append(values, strconv.FormatFloat(v, 'f', -1, 64))
	case bool:
		if v {
			values = append(values, "true")
		} else {
			values = append(values, "false")
		}
	case nil:
		// Skip null values
	default:
		// Convert other types to string
		jsonBytes, _ := json.Marshal(v)
		values = append(values, string(jsonBytes))
	}

	return values
}

// concatenateAndHash implements the signature verification logic
func (su *signatureUtils) concatenateAndHash(guide string, timestamp string, jsonStr string) (string, error) {
	var jsonMap map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &jsonMap)
	if err != nil {
		return "", err
	}

	// Extract values from the JSON
	valuesArray := su.extractValues(jsonMap)
	
	logDebug("Values extracted from JSON: %v", valuesArray)

	// Define allowed characters
	allowedChars := "abcdefghijklmnopqrstuvwxyz0123456789-/."

	// Concatenate guide, timestamp, and values
	concatenatedString := guide + timestamp + strings.Join(valuesArray, "")
	
	logDebug("Concatenated string before processing: %s", concatenatedString)

	// Process the string (remove accents, allow only specific chars)
	concatenatedString = su.removeAccents(concatenatedString)
	concatenatedString = su.allowOnly(concatenatedString, allowedChars)
	
	logDebug("Processed string for hashing: %s", concatenatedString)

	// Hash using SHA-256
	hash := sha256.Sum256([]byte(concatenatedString))
	hashedString := hex.EncodeToString(hash[:])
	
	logDebug("SHA-256 hashed string (hex): %s", hashedString)

	// Base64 encode the hex string
	base64Signature := base64.StdEncoding.EncodeToString([]byte(hashedString))
	
	logDebug("Final base64 signature: %s", base64Signature)

	return base64Signature, nil
}

func (sv *SignatureVerifier) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	logDebug("Received request: %s %s", req.Method, req.URL.Path)
	
	// Read the original request body
	originalBodyBytes, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logDebug("Error reading request body: %v", err)
		http.Error(rw, "Error reading request body", http.StatusInternalServerError)
		return
	}
	
	// Reset the body so it can be read again by the next handler
	req.Body = ioutil.NopCloser(bytes.NewBuffer(originalBodyBytes))
	
	logDebug("Request body: %s", string(originalBodyBytes))

	// Parse the incoming request
	var requestData struct {
		RequestData   map[string]interface{} `json:"requestData"`
		ReferenceData struct {
			Channel   string `json:"channel"`
			DeviceID  string `json:"deviceId"`
			Lang      string `json:"lang"`
			Guide     string `json:"guide"`
			Version   string `json:"version"`
			Timestamp string `json:"timestamp"`
		} `json:"referenceData"`
	}

	if err := json.Unmarshal(originalBodyBytes, &requestData); err != nil {
		logDebug("Invalid request format: %v", err)
		http.Error(rw, "Invalid request format", http.StatusBadRequest)
		return
	}

	logDebug("Reference data extracted: Guide=%s, Timestamp=%s", 
		requestData.ReferenceData.Guide, 
		requestData.ReferenceData.Timestamp)

	// Extract signature from header
	providedSignature := req.Header.Get("x-signature")
	if providedSignature == "" {
		logDebug("Missing signature in request headers")
		http.Error(rw, "Missing signature", http.StatusBadRequest)
		return
	}
	
	logDebug("Provided signature: %s", providedSignature)

	// Generate expected signature
	utils := &signatureUtils{}
	requestDataJSON, err := json.Marshal(requestData.RequestData)
	if err != nil {
		logDebug("Error marshaling request data: %v", err)
		http.Error(rw, "Error marshaling request data", http.StatusInternalServerError)
		return
	}

	logDebug("Generating signature with Guide=%s, Timestamp=%s, RequestData=%s", 
		requestData.ReferenceData.Guide, 
		requestData.ReferenceData.Timestamp,
		string(requestDataJSON))

	expectedSignature, err := utils.concatenateAndHash(
		requestData.ReferenceData.Guide,
		requestData.ReferenceData.Timestamp,
		string(requestDataJSON),
	)
	if err != nil {
		logDebug("Error generating signature: %v", err)
		http.Error(rw, "Error generating signature", http.StatusInternalServerError)
		return
	}
	
	logDebug("Expected signature: %s", expectedSignature)

	// Verify signature
	if providedSignature != expectedSignature {
		logDebug("Invalid signature! Provided: %s, Expected: %s", providedSignature, expectedSignature)
		http.Error(rw, "Invalid signature", http.StatusUnauthorized)
		return
	}
	
	logDebug("✓ Signature verified successfully!")
	duration := time.Since(startTime)
	logDebug("Signature verification completed in %v", duration)

	// If signature is valid, pass the request to the next handler
	// Re-set the original body for downstream handlers
	req.Body = ioutil.NopCloser(bytes.NewBuffer(originalBodyBytes))
	sv.next.ServeHTTP(rw, req)
}