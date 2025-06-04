package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test Case 1: Valid Authorization header
	t.Run("Valid API Key", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Authorization", "ApiKey my_super_secret_key")

		apiKey, err := GetAPIKey(headers)

		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if apiKey != "my_super_secret_key" {
			t.Errorf("Expected API key 'my_super_secret_key', got '%s'", apiKey)
		}
	})

	// Test Case 2: No Authorization header
	t.Run("No Authorization Header", func(t *testing.T) {
		headers := make(http.Header) // Empty headers

		_, err := GetAPIKey(headers)

		if err == nil {
			t.Errorf("Expected an error, got nil")
		}
		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("Expected error '%v', got '%v'", ErrNoAuthHeaderIncluded, err)
		}
	})

	// Test Case 3: Malformed Authorization header (missing "ApiKey" prefix)
	t.Run("Malformed Header - Missing Prefix", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Authorization", "Bearer some_token")

		_, err := GetAPIKey(headers)

		if err == nil {
			t.Errorf("Expected an error, got nil")
		}
		expectedErr := "malformed authorization header"
		if err.Error() != expectedErr {
			t.Errorf("Expected error message '%s', got '%s'", expectedErr, err.Error())
		}
	})

	// Test Case 4: Malformed Authorization header (only "ApiKey" no key)
	t.Run("Malformed Header - Only ApiKey", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Authorization", "ApiKey")

		_, err := GetAPIKey(headers)

		if err == nil {
			t.Errorf("Expected an error, got nil")
		}
		expectedErr := "malformed authorization header"
		if err.Error() != expectedErr {
			t.Errorf("Expected error message '%s', got '%s'", expectedErr, err.Error())
		}
	})
}
