// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reserved_prefix_test.go — ПРОСТРАНСТВО ИМЁН ЛИЧНЫХ АККАУНТОВ ЗАРЕЗЕРВИРОВАНО
// (приёмка Ф4 редакции 4, sha256
// 7c81fa29d71d70f283cc15dc9cf450f2cb39fe7fa7dec4878e2c6f510e2c6293; Р9 п.3,
// сценарии Ф4-29, Ф4-30; §5.5, §9, §10а п. 1а правка 3, §1б).
//
// # Что доводится
//
// Резерв делает префикс `personal-cloud-` ЗНАКОМ личного аккаунта: `Create` и
// `Update` отвергают имя, начинающееся с него, синхронно, до операции,
// `INVALID_ARGUMENT` / HTTP 400, текстом Р9 п.3. Отвергается ВХОД независимо от
// состояния каталога — рода `ALREADY_EXISTS` здесь нет: ничего не существует
// (api-conventions §Error-format; Р9 п.3).
//
// # Чем краснеет ДО кода (§9)
//
// Резерва в дереве нет: `Create`/`Update` судят имя только ФОРМОЙ
// (`domain/types.go:313-321`, §5.5), поэтому `personal-cloud-abc123` — годная
// форма — принимается и операция возвращается. ЧЕСТНЫЙ КРАСНЫЙ: проба существует,
// исполняется и не сходится, потому что производителя нет (правка 3 §10а п. 1а).
// Близнецы зелёные тем же прогоном: имя без дефиса на границе префикса
// (`personal-cloudabc123`) — не резерв; имя негодной формы с префиксом получает
// прежний отказ ФОРМЫ, до резерва дело не доходит (порядок проверок сохранён).
//
// Модульный держатель — рядом с пробами глаголов аккаунта (§1б). Харнесс создания —
// `createAccountNamed` (name_canon_test.go); харнесс правки — `newLcaRepo`/`newLcaOps`
// (update_labelclear_test.go).
package account

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// reservedPrefixRefusal — текст отказа резерва (Р9 п.3). Часть контракта —
// сверяется побайтово.
const reservedPrefixRefusal = "Illegal argument name: prefix 'personal-cloud-' is reserved for personal accounts"

// createAccountReturning — глагол Create над теми же дублёрами, что
// createAccountNamed, но БЕЗ require.NoError: возвращает синхронный исход Execute
// как есть, чтобы утверждать отказ.
func createAccountReturning(t *testing.T, name string) (*operations.Operation, error) {
	t.Helper()
	uc := NewCreateAccountUseCase(newFakeRepo(), newFakeOpsRepo())
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000abcd"})
	return uc.Execute(ctx, domain.Account{Name: domain.AccountName(name)})
}

// TestCreateAccount_F4_29_ReservedPrefixRejected — Ф4-29: `AccountService.Create`
// с именем из пространства личных аккаунтов отвергается синхронно; близнец без
// дефиса на границе — принимается; негодная форма с префиксом получает отказ формы.
func TestCreateAccount_F4_29_ReservedPrefixRejected(t *testing.T) {
	// ЧЕСТНЫЙ КРАСНЫЙ: резерва нет, имя годной формы принимается.
	t.Run("резерв: personal-cloud- отвергается INVALID_ARGUMENT до операции", func(t *testing.T) {
		op, err := createAccountReturning(t, "personal-cloud-abc123")
		require.Error(t, err, "имя из зарезервированного пространства обязано отвергаться синхронно (Р9 п.3)")
		require.Nil(t, op, "операции нет, аккаунта нет")
		st, ok := status.FromError(err)
		require.True(t, ok, "отказ — gRPC status")
		require.Equal(t, codes.InvalidArgument, st.Code(), "род — INVALID_ARGUMENT, не ALREADY_EXISTS")
		require.Equal(t, reservedPrefixRefusal, st.Message(), "текст резерва — часть контракта (Р9 п.3)")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ (зелёный сегодня, §9): одно различие — нет дефиса на границе
	// префикса, значит это не резерв.
	t.Run("законный близнец: personal-cloudabc123 (без дефиса на границе) — принимается", func(t *testing.T) {
		got := createAccountNamed(t, "personal-cloudabc123")
		require.Equal(t, "personal-cloudabc123", got.Name, "имя вне резерва обязано сохраниться как есть")
	})

	// ПОРЯДОК ПРОВЕРОК (зелёный сегодня): негодная форма с префиксом получает отказ
	// ФОРМЫ, а не резерва — форма судится первой.
	t.Run("порядок проверок: personal-cloud-ABC123 (негодная форма) — отказ ФОРМЫ, не резерва", func(t *testing.T) {
		op, err := createAccountReturning(t, "personal-cloud-ABC123")
		require.Error(t, err, "негодная форма обязана отвергаться")
		require.Nil(t, op)
		st, ok := status.FromError(err)
		require.True(t, ok)
		require.Equal(t, codes.InvalidArgument, st.Code())
		require.Contains(t, st.Message(), "must match", "имя негодной формы получает прежний отказ формы")
		require.NotEqual(t, reservedPrefixRefusal, st.Message(), "до резерва дело не доходит")
	})
}

// TestUpdateAccount_F4_30_ReservedPrefixRejectedOnRename — Ф4-30: переименование
// в пространство личных аккаунтов отвергается синхронно; переименование без
// дефиса на границе проходит; смена меток самого личного аккаунта и повтор его
// текущего имени резервом не отвергаются.
func TestUpdateAccount_F4_30_ReservedPrefixRejectedOnRename(t *testing.T) {
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: lcaOwnerID})
	namePtr := func(s string) *domain.AccountName { n := domain.AccountName(s); return &n }
	seeded := func(name string) *lcaRepo {
		r := newLcaRepo(nil)
		r.acct.Name = domain.AccountName(name)
		return r
	}

	// ЧЕСТНЫЙ КРАСНЫЙ: резерва нет, переименование в годную форму принимается.
	t.Run("резерв: переименование в personal-cloud- отвергается INVALID_ARGUMENT до операции", func(t *testing.T) {
		repo := seeded("acme-team")
		uc := NewUpdateAccountUseCase(repo, newLcaOps())
		op, err := uc.Execute(ctx, UpdateAccountInput{
			ID: lcaAcctID, Name: namePtr("personal-cloud-abc123"), UpdateMask: []string{"name"},
		})
		require.Error(t, err, "переименование в зарезервированное пространство обязано отвергаться синхронно (Р9 п.3)")
		require.Nil(t, op, "операции нет")
		st, ok := status.FromError(err)
		require.True(t, ok, "отказ — gRPC status")
		require.Equal(t, codes.InvalidArgument, st.Code(), "род — INVALID_ARGUMENT")
		require.Equal(t, reservedPrefixRefusal, st.Message(), "то же сообщение, что в Ф4-29")
		require.Equal(t, domain.AccountName("acme-team"), repo.acct.Name, "имя аккаунта осталось acme-team")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ (зелёный сегодня): переименование без дефиса на границе.
	t.Run("законный близнец: переименование в personal-cloudabc123 — операция возвращена", func(t *testing.T) {
		repo := seeded("acme-team")
		uc := NewUpdateAccountUseCase(repo, newLcaOps())
		op, err := uc.Execute(ctx, UpdateAccountInput{
			ID: lcaAcctID, Name: namePtr("personal-cloudabc123"), UpdateMask: []string{"name"},
		})
		require.NoError(t, err, "имя годной формы вне резерва — операция возвращена, имя сменилось")
		require.NotNil(t, op)
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ 2 (зелёный сегодня): смена меток самого личного аккаунта,
	// чьё имя несёт префикс. Без него резерв, встроенный в проверку ВСЕГО
	// аккаунта, отказал бы владельцу в любой правке (Ф4-30).
	t.Run("законный близнец 2: смена меток аккаунта с префиксом — проходит", func(t *testing.T) {
		repo := seeded("personal-cloud-xyz789")
		uc := NewUpdateAccountUseCase(repo, newLcaOps())
		op, err := uc.Execute(ctx, UpdateAccountInput{
			ID: lcaAcctID, Labels: domain.Labels{"tier": "gold"}, UpdateMask: []string{"labels"},
		})
		require.NoError(t, err, "правка прочих полей аккаунта с префиксом резервом не отвергается")
		require.NotNil(t, op)
	})

	// ПОВТОР ТЕКУЩЕГО ИМЕНИ (зелёный сегодня): равное имя не меняется — отказа
	// резерва нет.
	t.Run("повтор текущего имени с префиксом — не правка, резервом не отвергается", func(t *testing.T) {
		repo := seeded("personal-cloud-xyz789")
		uc := NewUpdateAccountUseCase(repo, newLcaOps())
		op, err := uc.Execute(ctx, UpdateAccountInput{
			ID: lcaAcctID, Name: namePtr("personal-cloud-xyz789"), UpdateMask: []string{"name"},
		})
		require.NoError(t, err, "равное имя не меняется — отказа резерва нет")
		require.NotNil(t, op)
	})
}
