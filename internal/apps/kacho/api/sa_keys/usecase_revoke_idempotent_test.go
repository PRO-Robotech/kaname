// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_revoke_idempotent_test.go — зеркало user_tokens для полосы машинного
// принципала. Полосы выдачи удостоверений две, и свойство, обязательное для
// одной, обязано быть проверено СРАВНЕНИЕМ полос, а не по каждой отдельно
// (architecture.md §«Параллельные полосы одного механизма»): без зеркала
// расхождение завелось бы как побочный эффект чужой правки и никем не решалось.
//
// Предмет тот же: BAT-1-44 требует УСПЕХА на повторном отзыве, а скрытие
// существования (security.md §Hardening #6) требует, чтобы чужое удостоверение
// было неотличимо от промаха. Совместимы они, только если ВСЕ безрезультатные
// исходы совпадают.
package sa_keys

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

// revokeKeyOutcome — наблюдаемый исход отзыва ключа, сведённый в одну строку.
// Названные вызывающим величины вычёркиваются: эхо собственного ввода не есть
// сведения, а без вычёркивания проба краснела бы на своей фикстуре.
func revokeKeyOutcome(t *testing.T, repo *stubSAClientRepo, hydra *stubHydra, svaID domain.ServiceAccountID, keyID domain.SAOAuthClientID) (string, bool) {
	t.Helper()
	ops := &stubOpsRepo{}
	uc := NewRevokeSAKeyUseCase(repo, &stubTx{}, hydra, ops)

	redact := func(s string) string {
		s = strings.ReplaceAll(s, string(keyID), "<id>")
		return strings.ReplaceAll(s, string(svaID), "<sva>")
	}

	if _, err := uc.Execute(context.Background(), RevokeInput{ServiceAccountID: svaID, KeyID: keyID}); err != nil {
		st := grpcstatus.Convert(err)
		return redact(fmt.Sprintf("sync-отказ code=%v msg=%q", st.Code(), st.Message())), repo.deleted
	}
	waitForOp(t, ops)

	ops.mu.Lock()
	defer ops.mu.Unlock()
	if ops.lastErr != nil {
		return redact(fmt.Sprintf("op-отказ code=%d msg=%q", ops.lastErr.GetCode(), ops.lastErr.GetMessage())), repo.deleted
	}
	if ops.lastResp == nil {
		return "op-успех БЕЗ ответа", repo.deleted
	}
	var resp iamv1.RevokeSAKeyResponse
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		return redact(fmt.Sprintf("op-успех, ответ не разбирается: %v", err)), repo.deleted
	}
	return redact(fmt.Sprintf("op-успех keyId=%q revokedAtSet=%v",
		resp.GetKeyId(), resp.GetRevokedAt() != nil)), repo.deleted
}

// TestRevokeSAKey_RepeatAbsentAndForeignShareOneOutcome — BAT-1-44 на полосе
// машинного принципала плюс проверка на оракул.
func TestRevokeSAKey_RepeatAbsentAndForeignShareOneOutcome(t *testing.T) {
	const (
		caller  = domain.ServiceAccountID("sva00000000000000001")
		other   = domain.ServiceAccountID("sva00000000000000002")
		keyID   = domain.SAOAuthClientID("soc00000000000000009")
		neverID = domain.SAOAuthClientID("soc00000000000000404")
	)

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
	ownHydra := &stubHydra{}
	own := &stubSAClientRepo{getRow: domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindSecret,
		ID:             keyID,
		SvaID:          caller,
		OAuthClientID:  "hydra-sva-9",
	}}
	ownOutcome, ownDeleted := revokeKeyOutcome(t, own, ownHydra, caller, keyID)
	if !ownDeleted {
		t.Fatalf("положительный контроль: своё живое удостоверение НЕ снято — успех ниже был бы вакуумен (исход %s)", ownOutcome)
	}
	if want := `op-успех keyId="<id>" revokedAtSet=true`; ownOutcome != want {
		t.Fatalf("своё живое: исход %s, ожидался %s", ownOutcome, want)
	}

	// ── (1) ПОВТОРНЫЙ отзыв.
	repeatedHydra := &stubHydra{}
	repeated := &stubSAClientRepo{
		getErr: iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient %s not found", keyID),
	}
	repeatedOutcome, repeatedDeleted := revokeKeyOutcome(t, repeated, repeatedHydra, caller, keyID)

	// ── (2) Никогда не существовавший идентификатор.
	neverHydra := &stubHydra{}
	never := &stubSAClientRepo{
		getErr: iamerr.Wrapf(iamerr.ErrNotFound, "SAOAuthClient %s not found", neverID),
	}
	neverOutcome, neverDeleted := revokeKeyOutcome(t, never, neverHydra, caller, neverID)

	// ── (3) ЧУЖОЙ ключ.
	foreignHydra := &stubHydra{}
	foreign := &stubSAClientRepo{getRow: domain.ServiceAccountOAuthClient{
		CredentialKind: domain.CredentialKindSecret,
		ID:             keyID,
		SvaID:          other,
		OAuthClientID:  "hydra-sva-2",
	}}
	foreignOutcome, foreignDeleted := revokeKeyOutcome(t, foreign, foreignHydra, caller, keyID)

	if want := `op-успех keyId="<id>" revokedAtSet=true`; repeatedOutcome != want {
		t.Errorf("повторный отзыв: исход %s, приёмка BAT-1-44 требует %s", repeatedOutcome, want)
	}
	if repeatedDeleted {
		t.Error("повторный отзыв не имел что снимать, а снятие произошло")
	}
	if neverOutcome != repeatedOutcome {
		t.Errorf("ОРАКУЛ: никогда-не-было %s ≠ повторный %s", neverOutcome, repeatedOutcome)
	}
	if foreignOutcome != repeatedOutcome {
		t.Errorf("ОРАКУЛ: чужое %s ≠ повторный %s — по различию узнают, существует ли ЧУЖОЙ ключ (security.md §Hardening #6)",
			foreignOutcome, repeatedOutcome)
	}
	if neverDeleted {
		t.Error("отзыв никогда не существовавшего что-то снял")
	}
	if foreignDeleted {
		t.Error("чужая строка СНЯТА — скрытие существования обернулось чужим удалением")
	}
	// Безрезультатный отзыв НЕ ходит к внешнему поставщику: чужая регистрация
	// не наша, а по несуществующей ходить не за чем. Вызов был бы вторым
	// каналом различения — тем же оракулом, только в чужом журнале.
	for name, h := range map[string]*stubHydra{"повторный": repeatedHydra, "никогда-не-было": neverHydra, "чужое": foreignHydra} {
		if h.deletedClientID != "" {
			t.Errorf("%s: безрезультатный отзыв позвал внешнего поставщика с %q", name, h.deletedClientID)
		}
	}
	if ownHydra.deletedClientID != "hydra-sva-9" {
		t.Errorf("положительный контроль: снятие СВОЕЙ строки не дошло до внешнего поставщика (got %q)", ownHydra.deletedClientID)
	}
}
