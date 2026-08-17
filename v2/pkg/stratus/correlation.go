package stratus

import "github.com/google/uuid"

// CorrelationShortIDLength is the number of characters of CorrelationShortID.
const CorrelationShortIDLength = 8

// CorrelationShortID derives a short, name-safe token from a correlation ID.
func CorrelationShortID(id uuid.UUID) string {
	return id.String()[:CorrelationShortIDLength]
}
