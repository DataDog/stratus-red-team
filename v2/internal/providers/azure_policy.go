package providers

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/uuid"
)

const headerXMSClientRequestID = "x-ms-client-request-id"

type correlationIDPolicy struct {
	correlationID string
}

func newCorrelationIDPolicy(correlationID uuid.UUID) policy.Policy {
	return &correlationIDPolicy{correlationID: correlationID.String()}
}

func (p *correlationIDPolicy) Do(req *policy.Request) (*http.Response, error) {
	req.Raw().Header.Set(headerXMSClientRequestID, p.correlationID)
	return req.Next()
}
