// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package loginlanehttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/stretchr/testify/require"
)

func TestAdmissionTerminalOutcomeHTTPContract(t *testing.T) {
	exhausted := errors.Join(iamerr.ErrAborted, errors.New("private-schema-secret"))
	for name, failure := range map[string]error{
		"exhausted": exhausted,
		"cancel": errors.Join(exhausted, context.Canceled),
		"unknown-commit": errors.New("private-connection-secret"),
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h := &Handler{}
			h.writeError(w, humansession.AdmissionWriteFailure(failure), humansession.TextRequestNotPerformed)
			if name == "exhausted" {
				require.Equal(t, http.StatusConflict, w.Code)
				require.JSONEq(t, `{"code":10,"message":"conflicting concurrent change, retry the request","details":[]}`, w.Body.String())
			} else {
				require.Equal(t, http.StatusServiceUnavailable, w.Code)
				require.JSONEq(t, `{"code":14,"message":"request not performed; try again later","details":[]}`, w.Body.String())
			}
			require.NotContains(t, w.Body.String(), "private-")
		})
	}
}
