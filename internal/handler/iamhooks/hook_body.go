// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hook_body.go — bounded JSON body decode for the Hydra/Kratos hook endpoints.
//
// The three hook handlers (token/refresh/provision) live on the cluster-internal
// :9092 mux behind a constant-time bearer gate. Bearer auth runs BEFORE this, so
// an unauthenticated attacker can never reach the decode — but a compromised
// Ory component (or an insider holding the hook shared-secret) could still POST
// an arbitrarily large JSON body and force unbounded heap allocation during
// json.Decode, repeatedly, until the pod OOM-kills (CWE-770 / OWASP A05:2021).
// Wrapping the body in http.MaxBytesReader caps the post-auth allocation.
package iamhooks

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// maxHookBodyBytes — hard cap on a hook request body. The real payloads
// (token/refresh session envelopes, identity-provision jsonnet output) are a
// few KiB; 1 MiB is a generous ceiling that still bounds the allocation.
const maxHookBodyBytes int64 = 1 << 20

// decodeHookBody wraps r.Body in an http.MaxBytesReader cap and decodes it into
// dst. It MUST be called only after requireHookAuth has succeeded. On an
// over-cap body it writes 413; on any other decode error it writes 400. The
// decode error is logged at Warn under tag so a malformed/oversized hook call
// stays observable. Returns true only when dst was fully populated (the caller
// may proceed).
func decodeHookBody(w http.ResponseWriter, r *http.Request, dst any, logger *slog.Logger, tag string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxHookBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			if logger != nil {
				logger.Warn(tag+": payload too large", "limit_bytes", maxHookBodyBytes)
			}
			http.Error(w, `{"error":"payload_too_large"}`, http.StatusRequestEntityTooLarge)
			return false
		}
		if logger != nil {
			logger.Warn(tag+": invalid payload", "err", err)
		}
		http.Error(w, `{"error":"invalid_payload"}`, http.StatusBadRequest)
		return false
	}
	return true
}
