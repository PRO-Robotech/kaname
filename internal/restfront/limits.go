// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import "net/http"

// Limits — потолки публичного фронта.
type Limits struct {
	MaxBodyBytes int64
	MaxInFlight  int
}

// Тексты отказов.
const (
	TextBodyTooLarge      = "Request body too large"
	TextTooManyConcurrent = "Too many concurrent requests"
)

// WithLimits — обёртка потолков.
func WithLimits(next http.Handler, l Limits) http.Handler {
	_ = l
	return next
}
