// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_revoke_idempotent_test.go — зеркало user_tokens для полосы машинного
// принципала (приёмка `docs/engineering/acceptance/credential-verbs-refusal-outcomes.md`,
// сценарии CVR-05 … CVR-08 и CVR-12, задача kaname#522). Полосы выдачи
// удостоверений две, и свойство, обязательное для одной, обязано быть
// проверено СРАВНЕНИЕМ полос (architecture.md §«Параллельные полосы одного
// механизма»).
//
// Отзыв ключа, которого у названной учётки нет, отвечает синхронным
// `NOT_FOUND` с текстом `SAKey <id> not found`, без операции и без события
// аудита. Три безрезультатных случая — никогда не было, уже снят, чужой —
// неразличимы (security.md §Hardening #6) и сверяются отпечатком.
package sa_keys

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// countingAudit — захватывает события аудита отзыва.
type countingAudit struct{ events int }

func (a *countingAudit) EmitTx(context.Context, service.Tx, service.AuditEvent) error {
	a.events++
	return nil
}

// keyRevokeObservation — наблюдаемое об исходе отзыва ключа.
type keyRevokeObservation struct {
	outcome   string
	opCreated bool
	deleted   bool
	audits    int
}

// revokeKeyOutcome — исход отзыва ключа, сведённый в одну строку, и его
// следствия. Названные вызывающим величины вычёркиваются: эхо собственного
// ввода не есть сведения.
func revokeKeyOutcome(t *testing.T, repo *stubSAClientRepo, svaID domain.ServiceAccountID, keyID domain.SAOAuthClientID) keyRevokeObservation {
	t.Helper()
	ops := &stubOpsRepo{}
	audit := &countingAudit{}
	uc := NewRevokeSAKeyUseCase(repo, &stubTx{}, ops).WithAuditEmitter(audit)

	redact := func(s string) string {
		s = strings.ReplaceAll(s, string(keyID), "<id>")
		return strings.ReplaceAll(s, string(svaID), "<sva>")
	}
	obs := func(outcome string) keyRevokeObservation {
		ops.mu.Lock()
		created := ops.created
		ops.mu.Unlock()
		return keyRevokeObservation{outcome: redact(outcome), opCreated: created, deleted: repo.deleted, audits: audit.events}
	}

	if _, err := uc.Execute(context.Background(), RevokeInput{ServiceAccountID: svaID, KeyID: keyID}); err != nil {
		st := grpcstatus.Convert(err)
		return obs(fmt.Sprintf("sync-отказ code=%v msg=%q details=%d", st.Code(), st.Message(), len(st.Details())))
	}
	waitForOp(t, ops)

	ops.mu.Lock()
	lastErr, lastResp := ops.lastErr, ops.lastResp
	ops.mu.Unlock()
	if lastErr != nil {
		return obs(fmt.Sprintf("op-отказ code=%v msg=%q details=%d",
			codes.Code(lastErr.GetCode()), lastErr.GetMessage(), len(lastErr.GetDetails())))
	}
	if lastResp == nil {
		return obs("op-успех БЕЗ ответа")
	}
	var resp iamv1.RevokeSAKeyResponse
	if err := lastResp.UnmarshalTo(&resp); err != nil {
		return obs(fmt.Sprintf("op-успех, ответ не разбирается: %v", err))
	}
	return obs(fmt.Sprintf("op-успех keyId=%q revokedAtSet=%v", resp.GetKeyId(), resp.GetRevokedAt() != nil))
}

// TestRevokeSAKey_RepeatAbsentAndForeignShareOneOutcome — CVR-05 … CVR-08.
// Имя функции — координата приёмки (DoD п.1).
func TestRevokeSAKey_RepeatAbsentAndForeignShareOneOutcome(t *testing.T) {
	const (
		caller  = domain.ServiceAccountID("sva00000000000000001")
		other   = domain.ServiceAccountID("sva00000000000000002")
		keyID   = domain.SAOAuthClientID("soc00000000000000009")
		neverID = domain.SAOAuthClientID("soc00000000000000404")
	)
	const refusal = `sync-отказ code=NotFound msg="SAKey <id> not found" details=0`

	// ── CVR-05, ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
	own := &stubSAClientRepo{getRow: domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindSecret,
		ID:             keyID,
		SvaID:          caller,
	}}
	ownObs := revokeKeyOutcome(t, own, caller, keyID)
	if want := `op-успех keyId="<id>" revokedAtSet=true`; ownObs.outcome != want {
		t.Fatalf("CVR-05: свой живой ключ — исход %s, ожидался %s", ownObs.outcome, want)
	}
	if !ownObs.deleted || ownObs.audits != 1 {
		t.Fatalf("CVR-05: свой живой ключ — снят=%v, событий аудита %d; ожидалось снят и ровно одно",
			ownObs.deleted, ownObs.audits)
	}

	// ── CVR-07: ПОВТОРНЫЙ отзыв.
	repeated := revokeKeyOutcome(t, &stubSAClientRepo{
		getErr: iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient %s not found", keyID),
	}, caller, keyID)
	// ── CVR-06: никогда не существовавший идентификатор.
	never := revokeKeyOutcome(t, &stubSAClientRepo{
		getErr: iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient %s not found", neverID),
	}, caller, neverID)
	// ── CVR-08: ЧУЖОЙ ключ.
	foreign := revokeKeyOutcome(t, &stubSAClientRepo{getRow: domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindSecret,
		ID:             keyID,
		SvaID:          other,
	}}, caller, keyID)

	for name, o := range map[string]keyRevokeObservation{
		"CVR-06 никогда-не-было": never,
		"CVR-07 повторный":       repeated,
		"CVR-08 чужой":           foreign,
	} {
		if o.outcome != refusal {
			t.Errorf("%s: исход %s, приёмка (Р1, Р2) требует %s", name, o.outcome, refusal)
		}
		if o.opCreated {
			t.Errorf("%s: заведена операция — отказ обязан быть синхронным", name)
		}
		if o.deleted {
			t.Errorf("%s: строка снята", name)
		}
		if o.audits != 0 {
			t.Errorf("%s: событий аудита %d", name, o.audits)
		}
	}
	if never.outcome != repeated.outcome || foreign.outcome != repeated.outcome {
		t.Errorf("ОРАКУЛ: исходы различимы — никогда-не-было %s · повторный %s · чужой %s",
			never.outcome, repeated.outcome, foreign.outcome)
	}
}

// TestRevokeSAKey_CVR12_UnansweredStoreIsUnavailableNotNotFound — CVR-12 для
// учётки: неполученный ответ хранилища — `UNAVAILABLE`, а не «нет». Близнец —
// CVR-06 на том же входе.
func TestRevokeSAKey_CVR12_UnansweredStoreIsUnavailableNotNotFound(t *testing.T) {
	const (
		caller = domain.ServiceAccountID("sva00000000000000001")
		keyID  = domain.SAOAuthClientID("soc00000000000000404")
	)
	t.Run("близнец CVR-06: хранилище ответило «нет»", func(t *testing.T) {
		o := revokeKeyOutcome(t, &stubSAClientRepo{
			getErr: iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient %s not found", keyID),
		}, caller, keyID)
		if want := `sync-отказ code=NotFound msg="SAKey <id> not found" details=0`; o.outcome != want {
			t.Fatalf("исход %s, ожидался %s", o.outcome, want)
		}
	})
	t.Run("CVR-12: хранилище не ответило", func(t *testing.T) {
		o := revokeKeyOutcome(t, &stubSAClientRepo{
			readErr: iamerr.Wrapf(iamerr.ErrUnavailable, "pool exhausted: %v", errors.New("dial tcp 10.0.0.9:5432")),
		}, caller, keyID)
		if !strings.HasPrefix(o.outcome, "sync-отказ code=Unavailable ") {
			t.Fatalf("исход %s, ожидался синхронный UNAVAILABLE (fail-closed мутации)", o.outcome)
		}
		if strings.Contains(o.outcome, "10.0.0.9") {
			t.Errorf("текст отказа несёт причину чужой стороны: %s", o.outcome)
		}
		if o.opCreated || o.deleted || o.audits != 0 {
			t.Errorf("CVR-12: операция=%v снято=%v аудит=%d", o.opCreated, o.deleted, o.audits)
		}
	})
}
