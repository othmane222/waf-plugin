package signature

import (
	"context"
	"fmt"
)

// Config holds the middleware configuration
type Config struct {
	TokenEndpoint    string `json:"TokenEndpoint"`
	ClientID         string `json:"ClientID"`
	ClientSecret     string `json:"ClientSecret"`
	GrantType        string `json:"GrantType"`
}

// CreateConfig creates the default configuration
func CreateConfig() *Config {
	return &Config{
		TokenEndpoint: "http://192.168.1.130:30161/ga/external/getToken",
		ClientID:      "gateway-external-client",
		GrantType:     "client_credentials",
	}
}

// Validate checks the configuration
func (c *Config) Validate() error {
	if c.TokenEndpoint == "" {
		return fmt.Errorf("token endpoint cannot be empty")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client ID cannot be empty")
	}
	if c.GrantType == "" {
		return fmt.Errorf("grant type cannot be empty")
	}
	return nil
}