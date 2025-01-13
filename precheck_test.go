package main

import (
	"context"
	"net"
	"testing"
)

func TestPrecheck(t *testing.T) {
	// Save original PublicIPs, then restore after tests.
	originalPublicIPs := publicIPs
	defer func() {
		publicIPs = originalPublicIPs
	}()

	tests := []struct {
		name     string
		hostname string
		publicIP string
		wantErr  bool
	}{
		{
			name:     "BadHostname",
			hostname: "doesnotexist.invalid",
			publicIP: "127.0.0.1",
			wantErr:  true,
		},
		{
			name:     "ValidButNotLocal",
			hostname: "google.com",
			publicIP: "127.0.0.1",
			wantErr:  true,
		},
		{
			name:     "ValidAndLocal",
			hostname: "foo.localtest.me", // resolves to 127.0.0.1
			publicIP: "127.0.0.1",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set publicIPs to the value in the test case.
			publicIPs = []net.IP{net.ParseIP(tt.publicIP)}

			err := PreCheck(context.Background(), tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("Precheck(%q) error = %v, wantErr %v", tt.hostname, err, tt.wantErr)
			}
		})
	}
}
