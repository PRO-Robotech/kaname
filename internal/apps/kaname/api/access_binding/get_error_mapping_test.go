// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// get_error_mapping_test.go — RED→GREEN regression lock for the audit r5
// finding: Update/Delete collapsed EVERY error from AccessBindings().Get to
// PermissionDenied, though the comment ("Existence-leak parity ... a
// non-existent binding → PermissionDenied") only justifies that mapping for a
// genuinely non-existent binding (iamerr.ErrNotFound). A transient Reader
// failure (statement-timeout, conn reset — surfaced here as ErrUnavailable /
// ErrInternal) was mis-mapped to the terminal, non-retriable PERMISSION_DENIED
// instead of a retriable code, so a well-behaved client would never retry a
// transient outage.
//
// Fix: only errors.Is(err, iamerr.ErrNotFound) maps to PermissionDenied
// (existence-hiding, intentional); every other error goes through
// shared.MapRepoErr like the Reader-acquisition error just above it.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Well-formed AccessBinding ids (prefix "acb" + domain.ShortIDLen==20 total)
// that do not correspond to any seeded binding, used to exercise the
// Get-not-found / Get-transient-error branches without tripping the sync
// malformed-id precheck (shared.ValidateResourceID) before reaching the Get.
const (
	nonexistentABID1 domain.AccessBindingID = "acb0000000000000abc1"
	nonexistentABID2 domain.AccessBindingID = "acb0000000000000abc2"
	nonexistentABID3 domain.AccessBindingID = "acb0000000000000abc3"
	nonexistentABID4 domain.AccessBindingID = "acb0000000000000abc4"
)

// ── Update ──────────────────────────────────────────────────────────────────

// Not-found stays PermissionDenied (existence-hiding is intentional).
func TestAccessBinding_Update_GetNotFound_MapsToPermissionDenied(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_geterr_upd_nf", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kaname.view", nil)
	// No binding seeded ⇒ fakeABRdr.Get returns iamerr.ErrNotFound.
	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID1,
		[]string{"labels"}, false, domain.Labels{"stage": "prod"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"non-existent binding must still 403 (existence-leak protection)")
}

// A transient (non-not-found) Reader failure on the existence-check Get must
// map to a retriable code (via shared.MapRepoErr), NOT the terminal
// PermissionDenied — a client must be able to tell "retry me" from "you are
// forbidden, forever".
func TestAccessBinding_Update_GetTransientError_MapsToRetriable(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_geterr_upd_tr", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kaname.view", nil)
	repo.forceGetErr = iamerr.Wrapf(iamerr.ErrUnavailable, "access_bindings: statement timeout")
	uc := NewUpdateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID2,
		[]string{"labels"}, false, domain.Labels{"stage": "prod"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err),
		"a transient Reader.Get failure must map to a retriable code, not PermissionDenied")
	assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
}

// ── Delete ──────────────────────────────────────────────────────────────────

func TestAccessBinding_Delete_GetNotFound_MapsToPermissionDenied(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_geterr_del_nf", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kaname.view", nil)
	uc := NewDeleteAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID3)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"non-existent binding must still 403 (existence-leak protection)")
}

func TestAccessBinding_Delete_GetTransientError_MapsToRetriable(t *testing.T) {
	const ownerID, accountID, roleID = "usr_acct_owner", "acc_geterr_del_tr", "rol_viewer_test_001"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kaname.view", nil)
	repo.forceGetErr = iamerr.Wrapf(iamerr.ErrInternal, "access_bindings: conn reset")
	uc := NewDeleteAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID4)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err),
		"a transient Reader.Get failure must map to a retriable/internal code, not PermissionDenied")
	assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
}

// ── Get ─────────────────────────────────────────────────────────────────────
//
// Имя файла обещало ЧТЕНИЕ, а покрывало правку и удаление: раунд r5 назвал два
// глагола из трёх, и асимметрию третьего никто не решал (задача
// `PRO-Robotech/kacho#2577`). Пробы ниже приводят имя файла к его содержимому.
//
// # Исходов ТРИ, а не два
//
// Чтение одной привязки обязано разводить три ответа, и ровно так, а не иначе:
//
//	«привязки нет»        → отказ в правах, ПОБАЙТОВО равный настоящему отказу
//	«привязка есть, прав нет» → тот же отказ в правах
//	«сосед не ответил»    → СВОЙ код, отличный от обоих
//
// Первые два обязаны остаться неразличимыми: различимый ответ есть оракул
// существования — по нему отличают «нет доступа» от «не существует», то есть
// ровно то, что скрытие и должно закрыть (`get_hide_existence_test.go`).
// Третий обязан отличаться от обоих: отказ в правах ТЕРМИНАЛЕН — он говорит, что
// повтор бессмыслен, потому что решение зависит от тройки (субъект, отношение,
// объект) и одинаковый повтор не меняет ни одной. Временный отказ чтения
// (таймаут оператора, сброс соединения) о правах не говорит ничего: тот же
// вопрос мгновением позже получает ответ. Схлопнув их, чтение выдаёт
// терминальный вердикт на преходящую беду, и вызывающий, классифицирующий
// ответы соседа по полосе (дренаж, реконсайлер, клиент соседа), пометит
// намерение окончательно провалившимся.

// TestAccessBinding_Get_GetTransientError_MapsToRetriable — временный отказ
// чтения отвечает СВОИМ кодом, а не терминальным отказом в правах.
func TestAccessBinding_Get_GetTransientError_MapsToRetriable(t *testing.T) {
	const ownerID, accountID, roleID = "usr0000000000000ownr", "acc0000000000geterr1", "rol0000000000000view"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kaname.view", nil)
	repo.forceGetErr = iamerr.Wrapf(iamerr.ErrUnavailable, "access_bindings: statement timeout")
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID1)
	require.Error(t, err)
	assert.Equalf(t, codes.Unavailable, status.Code(err),
		"временный отказ чтения ответил %s: повтор осмыслен, а вызывающему сказано, "+
			"что решение окончательно", status.Code(err))
	assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
}

// TestAccessBinding_Get_GetInternalError_MapsToRetriable — вторая форма
// преходящей беды (сброс соединения) разводится так же.
func TestAccessBinding_Get_GetInternalError_MapsToRetriable(t *testing.T) {
	const ownerID, accountID, roleID = "usr0000000000000ownr", "acc0000000000geterr2", "rol0000000000000view"
	repo := newABFakeRepo(ownerID, accountID, "", roleID, "kaname.view", nil)
	repo.forceGetErr = iamerr.Wrapf(iamerr.ErrInternal, "access_bindings: conn reset")
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(newRecordingFGA(), nil)

	_, err := uc.Execute(newOwnerContext(ownerID), nonexistentABID2)
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.NotEqual(t, codes.PermissionDenied, status.Code(err))
}

// TestAccessBinding_Get_ThreeOutcomesAreSplitTwoWays — несущее утверждение:
// промах и настоящий отказ СЛИТЫ (побайтово), временный отказ РАЗВЕДЁН с обоими.
//
// Без второй половины первая истинна на чтении, отвечающем всем одинаково;
// без первой — вторая истинна на чтении, отвечающем всем по-разному и потому
// раздающем оракул. Проверять надо обе, и одной пробой, иначе следующая правка
// закроет одну половину за счёт другой.
func TestAccessBinding_Get_ThreeOutcomesAreSplitTwoWays(t *testing.T) {
	const (
		ownerID   = "usr0000000000000ownr"
		accountID = "acc00000000000ba01ab"
		projectID = "prj0000000000000proj"
		roleID    = "rol0000000000000view"
		subjectID = "usr000000000000grant"
	)

	repo := newABFakeRepo(ownerID, accountID, projectID, roleID, "kaname.view", nil)
	existing := seedClusterBinding(repo, subjectID)
	uc := NewGetAccessBindingUseCase(repo).WithRelationStore(&denyingFGA{}, nil)
	stranger := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000outsidr"})

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ──────────────────────────────────────────────
	subject := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: subjectID})
	if _, err := uc.Execute(subject, existing); err != nil {
		require.NoErrorf(t, err, "субъект привязки обязан её читать: без этого сравнения "+
			"ниже истинны на чтении, отказывающем ВСЕМ")
	}

	// ── ПОЛОСА 1: привязка ЕСТЬ, прав нет ───────────────────────────────────
	_, denyErr := uc.Execute(stranger, existing)
	require.Error(t, denyErr)
	denial := status.Convert(denyErr)

	// ── ПОЛОСА 2: привязки НЕТ ──────────────────────────────────────────────
	_, missErr := uc.Execute(stranger, nonexistentABID3)
	require.Error(t, missErr)
	miss := status.Convert(missErr)

	// ── ПОЛОСА 3: сосед не ответил ──────────────────────────────────────────
	repo.forceGetErr = iamerr.Wrapf(iamerr.ErrUnavailable, "access_bindings: statement timeout")
	_, outageErr := uc.Execute(stranger, existing)
	repo.forceGetErr = nil
	require.Error(t, outageErr)
	outage := status.Convert(outageErr)

	// ── ТОГДА: 1 и 2 слиты, 3 разведён ──────────────────────────────────────
	require.Equalf(t, denial.Code(), miss.Code(),
		"коды промаха и отказа разошлись (%s против %s): по ним отличают "+
			"«не существует» от «нет доступа»", miss.Code(), denial.Code())
	require.Equalf(t, denial.Message(), miss.Message(),
		"ТЕКСТЫ промаха и отказа разошлись при совпавшем коде — различимый текст "+
			"и есть оракул: отказ говорит %q, промах %q", denial.Message(), miss.Message())
	require.NotEqualf(t, denial.Code(), outage.Code(),
		"временный отказ ответил тем же кодом %s, что и отказ в правах: повтор "+
			"осмыслен, а вызывающему сказано, что решение окончательно", outage.Code())
	require.Equalf(t, codes.Unavailable, outage.Code(),
		"временный отказ ответил %s вместо UNAVAILABLE", outage.Code())

	t.Logf("перепись: полос сравнено 3 (промах, отказ, недоступность), положительный "+
		"контроль 1; слиты %s/%s, разведён %s", miss.Code(), denial.Code(), outage.Code())
}
