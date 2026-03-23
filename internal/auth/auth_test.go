package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantKey       string
		wantErrString string
	}{
		{
			name:    "Valid API Key",
			headers: http.Header{"Authorization": []string{"ApiKey secret-token-123"}},
			wantKey: "secret-token-123",
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			wantErrString: "no authorization header included",
		},
		{
			name:          "Malformed Header - Missing Prefix",
			headers:       http.Header{"Authorization": []string{"Bearer some-token"}},
			wantErrString: "malformed authorization header",
		},
		{
			name:          "Malformed Header - Only Prefix",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			wantErrString: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// Check for error expectations
			if tt.wantErrString != "" {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, wantErr %v", tt.wantErrString)
					return
				}
				if err.Error() != tt.wantErrString {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErrString)
					return
				}
				return
			}

			// Check for success expectations
			if err != nil {
				t.Fatalf("GetAPIKey() unexpected error: %v", err)
			}
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}