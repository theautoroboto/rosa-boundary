package aws

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// mockSTSClient implements the STSClient interface for testing
type mockSTSClient struct {
	assumeRoleFunc func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

func (m *mockSTSClient) AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	if m.assumeRoleFunc != nil {
		return m.assumeRoleFunc(ctx, params, optFns...)
	}
	return nil, errors.New("not implemented")
}

func TestAssumeRoleWithWebIdentityWithClient_Success(t *testing.T) {
	ctx := context.Background()
	roleARN := "arn:aws:iam::123456789012:role/test-role"
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	sessionName := "rosa-boundary-test"

	mockClient := &mockSTSClient{
		assumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
			// Verify input parameters
			if aws.ToString(params.RoleArn) != roleARN {
				t.Errorf("RoleArn = %q, want %q", aws.ToString(params.RoleArn), roleARN)
			}
			if aws.ToString(params.RoleSessionName) != sessionName {
				t.Errorf("RoleSessionName = %q, want %q", aws.ToString(params.RoleSessionName), sessionName)
			}
			if aws.ToString(params.WebIdentityToken) != idToken {
				t.Errorf("WebIdentityToken = %q, want %q", aws.ToString(params.WebIdentityToken), idToken)
			}

			// Return valid credentials
			return &sts.AssumeRoleWithWebIdentityOutput{
				Credentials: &types.Credentials{
					AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
					SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
					SessionToken:    aws.String("AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/L"),
				},
			}, nil
		},
	}

	creds, err := assumeRoleWithWebIdentityWithClient(ctx, mockClient, roleARN, idToken, sessionName)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if creds == nil {
		t.Fatal("Expected credentials, got nil")
	}

	if creds.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AccessKeyID = %q, want %q", creds.AccessKeyID, "AKIAIOSFODNN7EXAMPLE")
	}
	if creds.SecretAccessKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("SecretAccessKey = %q, want %q", creds.SecretAccessKey, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	}
	if creds.SessionToken != "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/L" {
		t.Errorf("SessionToken = %q, want %q", creds.SessionToken, "AQoEXAMPLEH4aoAH0gNCAPyJxz4BlCFFxWNE1OPTgk5TthT+FvwqnKwRcOIfrRh3c/L")
	}
}

func TestAssumeRoleWithWebIdentityWithClient_APIError(t *testing.T) {
	ctx := context.Background()
	roleARN := "arn:aws:iam::123456789012:role/test-role"
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	sessionName := "rosa-boundary-test"

	tests := []struct {
		name      string
		mockError error
		wantError string
	}{
		{
			name:      "network error",
			mockError: errors.New("network timeout"),
			wantError: "AssumeRoleWithWebIdentity failed: network timeout",
		},
		{
			name:      "invalid token error",
			mockError: errors.New("InvalidIdentityToken: Token is expired"),
			wantError: "AssumeRoleWithWebIdentity failed: InvalidIdentityToken: Token is expired",
		},
		{
			name:      "access denied",
			mockError: errors.New("AccessDenied: Not authorized to perform sts:AssumeRoleWithWebIdentity"),
			wantError: "AssumeRoleWithWebIdentity failed: AccessDenied: Not authorized to perform sts:AssumeRoleWithWebIdentity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockSTSClient{
				assumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return nil, tt.mockError
				},
			}

			creds, err := assumeRoleWithWebIdentityWithClient(ctx, mockClient, roleARN, idToken, sessionName)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if err.Error() != tt.wantError {
				t.Errorf("Error = %q, want %q", err.Error(), tt.wantError)
			}
			if creds != nil {
				t.Errorf("Expected nil credentials on error, got %+v", creds)
			}
		})
	}
}

func TestAssumeRoleWithWebIdentityWithClient_NilCredentials(t *testing.T) {
	ctx := context.Background()
	roleARN := "arn:aws:iam::123456789012:role/test-role"
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	sessionName := "rosa-boundary-test"

	mockClient := &mockSTSClient{
		assumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
			// STS returns success but with nil Credentials
			return &sts.AssumeRoleWithWebIdentityOutput{
				Credentials: nil,
			}, nil
		},
	}

	creds, err := assumeRoleWithWebIdentityWithClient(ctx, mockClient, roleARN, idToken, sessionName)
	if err == nil {
		t.Fatal("Expected error for nil credentials, got nil")
	}
	if err.Error() != "STS returned nil credentials" {
		t.Errorf("Error = %q, want %q", err.Error(), "STS returned nil credentials")
	}
	if creds != nil {
		t.Errorf("Expected nil credentials, got %+v", creds)
	}
}

func TestAssumeRoleWithWebIdentityWithClient_EmptyCredentialFields(t *testing.T) {
	ctx := context.Background()
	roleARN := "arn:aws:iam::123456789012:role/test-role"
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	sessionName := "rosa-boundary-test"

	tests := []struct {
		name        string
		credentials *types.Credentials
	}{
		{
			name: "empty AccessKeyId",
			credentials: &types.Credentials{
				AccessKeyId:     aws.String(""),
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				SessionToken:    aws.String("token123"),
			},
		},
		{
			name: "nil AccessKeyId pointer",
			credentials: &types.Credentials{
				AccessKeyId:     nil,
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				SessionToken:    aws.String("token123"),
			},
		},
		{
			name: "empty SecretAccessKey",
			credentials: &types.Credentials{
				AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: aws.String(""),
				SessionToken:    aws.String("token123"),
			},
		},
		{
			name: "nil SecretAccessKey pointer",
			credentials: &types.Credentials{
				AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: nil,
				SessionToken:    aws.String("token123"),
			},
		},
		{
			name: "empty SessionToken",
			credentials: &types.Credentials{
				AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				SessionToken:    aws.String(""),
			},
		},
		{
			name: "nil SessionToken pointer",
			credentials: &types.Credentials{
				AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
				SecretAccessKey: aws.String("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
				SessionToken:    nil,
			},
		},
		{
			name: "all empty",
			credentials: &types.Credentials{
				AccessKeyId:     aws.String(""),
				SecretAccessKey: aws.String(""),
				SessionToken:    aws.String(""),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &mockSTSClient{
				assumeRoleFunc: func(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
					return &sts.AssumeRoleWithWebIdentityOutput{
						Credentials: tt.credentials,
					}, nil
				},
			}

			creds, err := assumeRoleWithWebIdentityWithClient(ctx, mockClient, roleARN, idToken, sessionName)
			if err == nil {
				t.Fatal("Expected error for empty credential fields, got nil")
			}
			if err.Error() != "STS returned credentials with empty values" {
				t.Errorf("Error = %q, want %q", err.Error(), "STS returned credentials with empty values")
			}
			if creds != nil {
				t.Errorf("Expected nil credentials, got %+v", creds)
			}
		})
	}
}

func TestStaticCredentialsProvider(t *testing.T) {
	creds := &TemporaryCredentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "token123",
	}

	provider := StaticCredentialsProvider(creds)
	if provider == nil {
		t.Fatal("StaticCredentialsProvider returned nil")
	}

	// Retrieve credentials from the provider
	awsCreds, err := provider.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("Failed to retrieve credentials from provider: %v", err)
	}

	// Validate credentials match
	if awsCreds.AccessKeyID != creds.AccessKeyID {
		t.Errorf("AccessKeyID mismatch: got %q, want %q", awsCreds.AccessKeyID, creds.AccessKeyID)
	}
	if awsCreds.SecretAccessKey != creds.SecretAccessKey {
		t.Errorf("SecretAccessKey mismatch: got %q, want %q", awsCreds.SecretAccessKey, creds.SecretAccessKey)
	}
	if awsCreds.SessionToken != creds.SessionToken {
		t.Errorf("SessionToken mismatch: got %q, want %q", awsCreds.SessionToken, creds.SessionToken)
	}
}

func TestStaticCredentialsProvider_EmptyFields(t *testing.T) {
	creds := &TemporaryCredentials{
		AccessKeyID:     "",
		SecretAccessKey: "",
		SessionToken:    "",
	}

	// Provider creation should succeed (validation happens at Retrieve time)
	provider := StaticCredentialsProvider(creds)
	if provider == nil {
		t.Fatal("StaticCredentialsProvider returned nil")
	}

	// Retrieve should fail because AWS SDK validates credentials are non-empty
	_, err := provider.Retrieve(context.Background())
	if err == nil {
		t.Error("Expected error when retrieving empty credentials, got nil")
	}
	if err != nil && err.Error() != "static credentials are empty" {
		t.Logf("Got expected error: %v", err)
	}
}
