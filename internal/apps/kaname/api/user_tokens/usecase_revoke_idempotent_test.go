// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_revoke_idempotent_test.go — исход отзыва на УРОВНЕ ГЛАГОЛА
// (приёмка `docs/engineering/acceptance/credential-verbs-refusal-outcomes.md`,
// сценарии CVR-01 … CVR-04 и CVR-12, задача kaname#522).
//
// Отзыв удостоверения, которого у названного человека нет, отвечает синхронным
// `NOT_FOUND` с текстом `UserToken <id> not found`, без операции и без события
// аудита (Р1, Р2). «Нет» объединяет три случая — никогда не существовало, уже
// снято, принадлежит другому человеку, — и три случая НЕРАЗЛИЧИМЫ: иначе по
// различию исходов вызывающий узнавал бы, существует ли ЧУЖОЕ удостоверение
// (security.md §Hardening #6). Поэтому исходы сверяются ОТПЕЧАТКОМ, а не по
// одному коду.
//
// Прежний исход — успех с отметкой отзыва при ничего не снятом — замещён (Р3):
// опечатка в идентификаторе при реакции на утечку выглядела для вызывающего
// как состоявшийся отзыв. Утверждение «исход у трёх случаев один» сохранено.
package user_tokens

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
)

// revokeObservation — всё, что вызывающий и хранилище могут наблюдать об
// исходе отзыва, кроме показаний часов.
type revokeObservation struct {
	// outcome — исход, сведённый в СТРОКУ: сравнение двух исходов есть
	// сравнение одного значения, а не перечисление полей, умалчивающее о поле,
	// которое забыли перечислить.
	outcome string
	// opCreated — операция заведена.
	opCreated bool
	// deleted — строка снята.
	deleted bool
	// audits — событий аудита записано.
	audits int
}

// revokeOutcome исполняет отзыв и сводит исход. Названные вызывающим величины
// — идентификатор удостоверения и идентификатор человека — из отпечатка
// ВЫЧЁРКИВАЮТСЯ: эхо собственного ввода сведениями не является, а без
// вычёркивания два запроса с разными идентификаторами разошлись бы всегда.
// Детали статуса входят в отпечаток: набор деталей — часть наблюдаемого.
func revokeOutcome(t *testing.T, repo *stubUserClientRepo, userID domain.UserID, tokenID domain.UserOAuthClientID) revokeObservation {
	t.Helper()
	ops := &stubOpsRepo{}
	audit := &stubAudit{}
	uc := NewRevokeUserTokenUseCase(repo, &stubTx{}, ops).WithAuditEmitter(audit)

	redact := func(s string) string {
		s = strings.ReplaceAll(s, string(tokenID), "<id>")
		return strings.ReplaceAll(s, string(userID), "<user>")
	}
	obs := func(outcome string) revokeObservation {
		ops.mu.Lock()
		created := ops.created
		ops.mu.Unlock()
		return revokeObservation{outcome: redact(outcome), opCreated: created, deleted: repo.deleted, audits: len(audit.events)}
	}

	if _, err := uc.Execute(context.Background(), RevokeInput{UserID: userID, TokenID: tokenID}); err != nil {
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
	var resp iamv1.RevokeUserTokenResponse
	if err := lastResp.UnmarshalTo(&resp); err != nil {
		return obs(fmt.Sprintf("op-успех, ответ не разбирается: %v", err))
	}
	// Отметка времени в отпечаток не входит — она различает любые два вызова.
	// Входит ФАКТ её наличия.
	return obs(fmt.Sprintf("op-успех tokenId=%q revokedAtSet=%v", resp.GetTokenId(), resp.GetRevokedAt() != nil))
}

// TestRevoke_RepeatAbsentAndForeignShareOneOutcome — CVR-01 … CVR-04. Один
// положительный контроль (CVR-01) и три безрезультатных случая, каждый
// отличается от контроля ОДНИМ фактом и все три равны синхронному `NOT_FOUND`.
// Имя функции — координата приёмки (DoD п.1).
func TestRevoke_RepeatAbsentAndForeignShareOneOutcome(t *testing.T) {
	const (
		caller  = domain.UserID("usr00000000000000001")
		other   = domain.UserID("usr00000000000000002")
		tokenID = domain.UserOAuthClientID("uoc00000000000000009")
		neverID = domain.UserOAuthClientID("uoc00000000000000404")
	)
	const refusal = `sync-отказ code=NotFound msg="UserToken <id> not found" details=0`

	// ── CVR-01, ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Без него утверждения ниже были бы
	// верны и о глаголе, отказывающем всегда.
	own := &stubUserClientRepo{getRow: domain.UserOAuthClient{
		CredentialKind: domain.CredentialKindSecret,
		ID:             tokenID,
		UserID:         caller,
	}}
	ownObs := revokeOutcome(t, own, caller, tokenID)
	if want := `op-успех tokenId="<id>" revokedAtSet=true`; ownObs.outcome != want {
		t.Fatalf("CVR-01: своё живое — исход %s, ожидался %s", ownObs.outcome, want)
	}
	if !ownObs.deleted || ownObs.audits != 1 {
		t.Fatalf("CVR-01: своё живое — снято=%v, событий аудита %d; ожидалось снято и ровно одно событие",
			ownObs.deleted, ownObs.audits)
	}

	// ── CVR-03: ПОВТОРНЫЙ отзыв — строки уже нет.
	repeated := revokeOutcome(t, &stubUserClientRepo{
		getErr: iamerr.Wrapf(iamerr.ErrNotFound, "UserToken %s not found", tokenID),
	}, caller, tokenID)
	// ── CVR-02: идентификатор, которого не было НИКОГДА.
	never := revokeOutcome(t, &stubUserClientRepo{
		getErr: iamerr.Wrapf(iamerr.ErrNotFound, "UserToken %s not found", neverID),
	}, caller, neverID)
	// ── CVR-04: ЧУЖОЕ удостоверение — строка есть, принадлежит другому человеку.
	foreignRepo := &stubUserClientRepo{getRow: domain.UserOAuthClient{
		CredentialKind: domain.CredentialKindSecret,
		ID:             tokenID,
		UserID:         other,
	}}
	foreign := revokeOutcome(t, foreignRepo, caller, tokenID)

	for name, o := range map[string]revokeObservation{
		"CVR-02 никогда-не-было": never,
		"CVR-03 повторный":       repeated,
		"CVR-04 чужое":           foreign,
	} {
		if o.outcome != refusal {
			t.Errorf("%s: исход %s, приёмка (Р1, Р2) требует %s", name, o.outcome, refusal)
		}
		if o.opCreated {
			t.Errorf("%s: заведена операция — отказ обязан быть синхронным, до операции", name)
		}
		if o.deleted {
			t.Errorf("%s: строка снята — снимать было нечего либо строка чужая", name)
		}
		if o.audits != 0 {
			t.Errorf("%s: записано событий аудита %d — события без изменения состояния не бывает", name, o.audits)
		}
	}
	// Неразличимость — отпечатками, а не по одному коду.
	if never.outcome != repeated.outcome || foreign.outcome != repeated.outcome {
		t.Errorf("ОРАКУЛ: исходы различимы — никогда-не-было %s · повторный %s · чужое %s",
			never.outcome, repeated.outcome, foreign.outcome)
	}
}

// TestRevoke_CVR12_UnansweredStoreIsUnavailableNotNotFound — CVR-12: хранилище
// не ответило на синхронной сверке существования — `UNAVAILABLE`, а не
// `NOT_FOUND`: неполученный ответ не есть «нет». Близнец — CVR-02 на том же
// входе, где хранилище ответило «нет».
func TestRevoke_CVR12_UnansweredStoreIsUnavailableNotNotFound(t *testing.T) {
	const (
		caller  = domain.UserID("usr00000000000000001")
		tokenID = domain.UserOAuthClientID("uoc00000000000000404")
	)
	t.Run("близнец CVR-02: хранилище ответило «нет»", func(t *testing.T) {
		o := revokeOutcome(t, &stubUserClientRepo{
			getErr: iamerr.Wrapf(iamerr.ErrNotFound, "UserToken %s not found", tokenID),
		}, caller, tokenID)
		if want := `sync-отказ code=NotFound msg="UserToken <id> not found" details=0`; o.outcome != want {
			t.Fatalf("исход %s, ожидался %s", o.outcome, want)
		}
	})
	t.Run("CVR-12: хранилище не ответило", func(t *testing.T) {
		repo := &stubUserClientRepo{
			readErr: iamerr.Wrapf(iamerr.ErrUnavailable, "pool exhausted: %v", errors.New("dial tcp 10.0.0.9:5432")),
		}
		o := revokeOutcome(t, repo, caller, tokenID)
		if !strings.HasPrefix(o.outcome, "sync-отказ code=Unavailable ") {
			t.Fatalf("исход %s, ожидался синхронный UNAVAILABLE (fail-closed мутации)", o.outcome)
		}
		if strings.Contains(o.outcome, "10.0.0.9") {
			t.Errorf("текст отказа несёт причину чужой стороны: %s", o.outcome)
		}
		if o.opCreated || o.deleted || o.audits != 0 {
			t.Errorf("CVR-12: операция=%v снято=%v аудит=%d — ничего не должно было случиться",
				o.opCreated, o.deleted, o.audits)
		}
	})
}
