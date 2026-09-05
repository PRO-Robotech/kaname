// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hydra_login_sessions.go — the provider's login-session surface.
//
//	DELETE /admin/oauth2/auth/sessions/login?subject={sub}
//
// One call, used by admin force-logout. The self-service logout path at the
// edge already pulls this same lever for the caller's own subject; force-logout
// pulled nothing, so an administrator could record that a person was logged out
// while that person's browser still held a live session at the provider.
//
// Why the cutoff alone is not enough. With the session alive, the browser can
// obtain a fresh authorization code without re-authenticating, and the session
// it presents keeps its ORIGINAL authentication instant — so the cutoff refuses
// it, correctly, forever. The subject is then wedged: refused at every turn,
// with nothing prompting the re-authentication that would clear it. Ending the
// session is what turns a refusal into a logout.
package clients

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DeleteLoginSessions ends every login session the provider holds for a
// subject, so the next request must authenticate again.
//
// The subject is the EXTERNAL identity the provider knows (what it puts in
// `sub`), not a kacho `users.id` — the caller resolves that.
//
// Idempotent: "no such session" is success. Deleting sessions is a converging
// operation and the caller retries the whole force-logout, so a second call
// finding nothing left is the desired state reached, not a failure.
func (c *HydraAdminClient) DeleteLoginSessions(ctx context.Context, subject string) error {
	if subject == "" {
		return fmt.Errorf("hydra: delete login sessions: empty subject")
	}
	u, err := url.Parse(c.BaseURL + "/admin/oauth2/auth/sessions/login")
	if err != nil {
		return fmt.Errorf("hydra: parse admin url: %w", err)
	}
	q := u.Query()
	q.Set("subject", subject)
	u.RawQuery = q.Encode()

	// Own deadline on every outbound call: an unresponsive provider must not be
	// able to hold this request open indefinitely.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	if err != nil {
		return fmt.Errorf("hydra: build delete-sessions request: %w", err)
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("hydra: delete login sessions: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK, http.StatusNotFound:
		return nil
	}
	// The body is bounded and carries the provider's own diagnostic; it is an
	// admin-API error, not user content.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("hydra: delete login sessions: unexpected status=%d body=%q", resp.StatusCode, string(body))
}
