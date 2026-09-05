// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_revoke_idempotent_test.go — BAT-1-44 на УРОВНЕ ГЛАГОЛА.
//
// Приёмка базового токена (`sub-phase-BAT-1-basic-access-token-acceptance.md`,
// BAT-1-44) называет исход повторного отзыва ПОИМЁННО: успех, и наблюдаемое
// состояние после него не отличается от состояния после первого отзыва. Там же
// названо, почему исход обязан совпасть с отзывом никогда не существовавшего:
// иначе повторный отзыв стал бы ОРАКУЛОМ СУЩЕСТВОВАНИЯ.
//
// Существующая проба BAT-1-42/44 (`repo/kacho/pg/basic_credential_resolve_
// integration_test.go`) утверждает это на уровне РЕЗОЛВА и снимает строку
// сырым `DELETE`, минуя глагол. Про исход самого глагола она не утверждает
// ничего — этим и занята эта проба.
//
// ТРЕТИЙ исход, которого приёмка прямо не называет, но который решает спор
// «идемпотентность против скрытия существования»: отзыв ЧУЖОГО удостоверения.
// Если «уже отозванное» отвечает успехом, а «чужое» — отказом, то по коду
// ответа узнают, существует ли чужое удостоверение, — то есть скрытие
// существования (security.md §Hardening #6) снимается той самой правкой,
// которой добивались идемпотентности. Поэтому проба требует, чтобы ВСЕ ТРИ
// безрезультатных исхода были неразличимы, и сверяет их ОТПЕЧАТКОМ, а не по
// одному коду.
package user_tokens

import (
	"context"
	"fmt"
	"strings"
	"testing"

	grpcstatus "google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// revokeOutcome — всё, что вызывающий может наблюдать об исходе отзыва, кроме
// показаний часов. Сводится в СТРОКУ, чтобы сравнение двух исходов было
// сравнением одного значения, а не перечислением полей: перечисление умалчивает
// о поле, которое забыли перечислить, и оракул заводится именно там.
//
// Названные вызывающим величины — идентификатор удостоверения и идентификатор
// человека — из отпечатка ВЫЧЁРКИВАЮТСЯ. Эхо собственного ввода сведениями не
// является: без вычёркивания два запроса с разными идентификаторами разошлись
// бы отпечатками всегда, и проба краснела бы на своей фикстуре, а не на дефекте.
// Всё, что остаётся в отпечатке сверх эха, — это то, что ответ СООБЩАЕТ.
func revokeOutcome(t *testing.T, repo *stubUserClientRepo, userID domain.UserID, tokenID domain.UserOAuthClientID) (string, bool) {
	t.Helper()
	ops := &stubOpsRepo{}
	uc := NewRevokeUserTokenUseCase(repo, &stubTx{}, ops)

	redact := func(s string) string {
		s = strings.ReplaceAll(s, string(tokenID), "<id>")
		return strings.ReplaceAll(s, string(userID), "<user>")
	}

	if _, err := uc.Execute(context.Background(), RevokeInput{UserID: userID, TokenID: tokenID}); err != nil {
		st := grpcstatus.Convert(err)
		return redact(fmt.Sprintf("sync-отказ code=%v msg=%q", st.Code(), st.Message())), repo.deleted
	}
	waitForOp(t, ops)

	ops.mu.Lock()
	defer ops.mu.Unlock()
	if ops.lastErr != nil {
		return redact(fmt.Sprintf("op-отказ code=%d msg=%q", ops.lastErr.GetCode(), ops.lastErr.GetMessage())), repo.deleted
	}
	var resp iamv1.RevokeUserTokenResponse
	if ops.lastResp == nil {
		return "op-успех БЕЗ ответа", repo.deleted
	}
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		return fmt.Sprintf("op-успех, ответ не разбирается: %v", err), repo.deleted
	}
	// Отметка времени в отпечаток не входит — она различает любые два вызова.
	// Входит ФАКТ её наличия: пустая отметка на безрезультатном исходе и была
	// бы оракулом («ничего не сняли» читается прямо из тела).
	return redact(fmt.Sprintf("op-успех tokenId=%q revokedAtSet=%v",
		resp.GetTokenId(), resp.GetRevokedAt() != nil)), repo.deleted
}

// TestRevoke_RepeatAbsentAndForeignShareOneOutcome — BAT-1-44 плюс проверка на
// оракул. Четыре случая: один положительный контроль и три безрезультатных,
// которые обязаны быть неразличимы.
func TestRevoke_RepeatAbsentAndForeignShareOneOutcome(t *testing.T) {
	const (
		caller  = domain.UserID("usr00000000000000001")
		other   = domain.UserID("usr00000000000000002")
		tokenID = domain.UserOAuthClientID("uoc00000000000000009")
		neverID = domain.UserOAuthClientID("uoc00000000000000404")
	)

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Без него все утверждения ниже были бы верны и
	// о глаголе, который не делает ничего и всегда отвечает успехом.
	own := &stubUserClientRepo{getRow: domain.UserOAuthClient{
		CredentialKind: domain.CredentialKindSecret,
		ID:             tokenID,
		UserID:         caller,
		OAuthClientID:  "hydra-usr-9",
	}}
	ownOutcome, ownDeleted := revokeOutcome(t, own, caller, tokenID)
	if !ownDeleted {
		t.Fatalf("положительный контроль: своё живое удостоверение НЕ снято — успех ниже был бы вакуумен (исход %s)", ownOutcome)
	}
	if want := `op-успех tokenId="<id>" revokedAtSet=true`; ownOutcome != want {
		t.Fatalf("своё живое: исход %s, ожидался %s", ownOutcome, want)
	}

	// ── (1) ПОВТОРНЫЙ отзыв: строки уже нет.
	repeated := &stubUserClientRepo{
		getErr: iamerr.Wrapf(iamerr.ErrNotFound, "UserToken %s not found", tokenID),
	}
	repeatedOutcome, repeatedDeleted := revokeOutcome(t, repeated, caller, tokenID)

	// ── (2) Идентификатор, которого не было НИКОГДА.
	never := &stubUserClientRepo{
		getErr: iamerr.Wrapf(iamerr.ErrNotFound, "UserToken %s not found", neverID),
	}
	neverOutcome, neverDeleted := revokeOutcome(t, never, caller, neverID)

	// ── (3) ЧУЖОЕ удостоверение: строка есть, принадлежит другому человеку.
	foreign := &stubUserClientRepo{getRow: domain.UserOAuthClient{
		CredentialKind: domain.CredentialKindSecret,
		ID:             tokenID,
		UserID:         other,
		OAuthClientID:  "hydra-usr-2",
	}}
	foreignOutcome, foreignDeleted := revokeOutcome(t, foreign, caller, tokenID)

	// BAT-1-44: исход повторного отзыва — УСПЕХ, названный приёмкой.
	if want := `op-успех tokenId="<id>" revokedAtSet=true`; repeatedOutcome != want {
		t.Errorf("повторный отзыв: исход %s, приёмка BAT-1-44 требует %s", repeatedOutcome, want)
	}
	if repeatedDeleted {
		t.Error("повторный отзыв не имел что снимать, а снятие произошло")
	}

	// Неразличимость — отпечатками, а не по одному коду.
	if neverOutcome != repeatedOutcome {
		t.Errorf("ОРАКУЛ: никогда-не-было %s ≠ повторный %s — по различию узнают, существовало ли удостоверение",
			neverOutcome, repeatedOutcome)
	}
	if foreignOutcome != repeatedOutcome {
		t.Errorf("ОРАКУЛ: чужое %s ≠ повторный %s — по различию узнают, существует ли ЧУЖОЕ удостоверение (security.md §Hardening #6)",
			foreignOutcome, repeatedOutcome)
	}
	if neverDeleted {
		t.Error("отзыв никогда не существовавшего что-то снял")
	}
	// Скрытие существования не ослаблено: успех по чужому — это ОТСУТСТВИЕ
	// строки в пространстве вызывающего, а не право её снять.
	if foreignDeleted {
		t.Error("чужая строка СНЯТА — скрытие существования обернулось чужим удалением")
	}
}
