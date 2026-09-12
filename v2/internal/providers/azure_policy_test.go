package providers

import (
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturingTransport records the request headers and returns a 200 response.
type capturingTransport struct {
	captured http.Header
}

func (t *capturingTransport) Do(req *http.Request) (*http.Response, error) {
	t.captured = req.Header.Clone()
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func TestCorrelationIDPolicySetsHeader(t *testing.T) {
	correlationID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	transport := &capturingTransport{}
	pl := runtime.NewPipeline("test", "v0.0.0",
		runtime.PipelineOptions{},
		&policy.ClientOptions{
			PerCallPolicies: []policy.Policy{newCorrelationIDPolicy(correlationID)},
			Transport:       transport,
		},
	)

	req, err := runtime.NewRequest(t.Context(), http.MethodGet, "https://management.azure.com/test")
	require.NoError(t, err)

	_, err = pl.Do(req)
	require.NoError(t, err)
	assert.Equal(t, correlationID.String(), transport.captured.Get(headerXMSClientRequestID))
}

func TestCorrelationIDPolicyOverwritesExistingHeader(t *testing.T) {
	correlationID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")

	transport := &capturingTransport{}
	pl := runtime.NewPipeline("test", "v0.0.0",
		runtime.PipelineOptions{},
		&policy.ClientOptions{
			PerCallPolicies: []policy.Policy{newCorrelationIDPolicy(correlationID)},
			Transport:       transport,
		},
	)

	req, err := runtime.NewRequest(t.Context(), http.MethodGet, "https://management.azure.com/test")
	require.NoError(t, err)
	req.Raw().Header.Set(headerXMSClientRequestID, "old-value")

	_, err = pl.Do(req)
	require.NoError(t, err)
	assert.Equal(t, correlationID.String(), transport.captured.Get(headerXMSClientRequestID))
}
