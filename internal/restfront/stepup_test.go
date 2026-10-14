// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

// stepup_test.go — обработчик ошибок фронта рендерит указание повысить уровень
// (Р11, Ф11-49; PRO-Robotech/kaname#511) ТОЛЬКО по двум фактам сразу — код с
// текстом Р11 и вызов в хвосте ответа — и только на публичном фронте. Каждый
// близнец ниже отличается от указания ровно одним фактом и обязан уйти
// умолчанию библиотеки с голой подсказкой. Размещение (обработчик стоит на
// пути запроса, вызов доезжает хвостом от настоящего слушателя) держит сквозная
// проба — cmd/kaname/step_up_indication_test.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

const stepUpChallengeFixture = `Bearer error="insufficient_user_authentication", error_description="Required ACR 2 for this resource; presented ACR 1", acr_values="2"`

// renderThroughFront прогоняет обработчик ошибок за обёрткой подсказки, как на
// публичном фронте (wrapped) либо без неё, как на внутреннем.
func renderThroughFront(t *testing.T, wrapped bool, err error, trailer metadata.MD) *httptest.ResponseRecorder {
	t.Helper()
	mux := newMux()
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := runtime.NewServerMetadataContext(r.Context(), runtime.ServerMetadata{TrailerMD: trailer})
		stepUpErrorHandler(ctx, mux, &runtime.JSONPb{}, w, r, err)
	})
	if wrapped {
		h = withAuthenticationChallenge(h)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/v1/projects/prj-x", nil))
	return rec
}

func TestStepUp_IndicationIsRenderedWithTheChallenge(t *testing.T) {
	rec := renderThroughFront(t, true, status.Error(codes.Unauthenticated, iamerr.TextStepUpRequired),
		metadata.Pairs(iamerr.StepUpChallengeTrailer, stepUpChallengeFixture))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("статус %d, ожидался 401", rec.Code)
	}
	if got, want := rec.Body.String(), `{"code":16,"message":"`+iamerr.TextStepUpRequired+`","details":[]}`; got != want {
		t.Errorf("тело %q, ожидалось побайтово %q", got, want)
	}
	if got := rec.Header().Get(challengeHeader); got != stepUpChallengeFixture {
		t.Errorf("вызов %q, ожидался вызов указания %q", got, stepUpChallengeFixture)
	}
}

// Близнецы: отличие в одном факте — и ни вызова указания, ни его тела.
func TestStepUp_TwinsFallToTheDefault(t *testing.T) {
	trailer := metadata.Pairs(iamerr.StepUpChallengeTrailer, stepUpChallengeFixture)
	indicationBody := `{"code":16,"message":"` + iamerr.TextStepUpRequired + `","details":[]}`
	for _, c := range []struct {
		name    string
		wrapped bool
		err     error
		trailer metadata.MD
	}{
		{"иной текст 401", true, status.Error(codes.Unauthenticated, "credential is not accepted"), trailer},
		{"нет вызова в хвосте", true, status.Error(codes.Unauthenticated, iamerr.TextStepUpRequired), nil},
		{"иной код", true, status.Error(codes.PermissionDenied, iamerr.TextStepUpRequired), trailer},
		{"внутренний фронт: места для вызова нет", false, status.Error(codes.Unauthenticated, iamerr.TextStepUpRequired), trailer},
	} {
		rec := renderThroughFront(t, c.wrapped, c.err, c.trailer)
		if got := rec.Header().Get(challengeHeader); got == stepUpChallengeFixture {
			t.Errorf("%s: отрендерен вызов указания", c.name)
		}
		if rec.Body.String() == indicationBody {
			t.Errorf("%s: отрендерено тело указания — ответ обязан уйти умолчанию", c.name)
		}
		if c.wrapped && rec.Code == http.StatusUnauthorized && rec.Header().Get(challengeHeader) != AuthenticationChallenge {
			t.Errorf("%s: на 401 подсказка %q, ожидалась голая %q", c.name, rec.Header().Get(challengeHeader), AuthenticationChallenge)
		}
	}
}
