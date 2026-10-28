// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// account_id_one_string_one_account_integration_test.go — «строка обозначает не
// больше одного аккаунта» (Р6а) на use-case создания с НАСТОЯЩИМ хранилищем
// (задача kaname#1052, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`, редакция
// 7, sha256 a3dff53e9ae56e3e1fa959d6ee3b43a932aaf09d3918795a62c06377550e3e52).
//
//   - AID-38 — похожие знаки: идентификатор не совпадает с чужой строкой и
//     после свёртки `o`→`0`, `i`/`l`→`1`; пара «имя ↔ имя» — побайтово; реестр —
//     побайтово (названный остаток); гонка двух строк, совпадающих после свёртки;
//   - AID-40 — при двух конфликтах текст идентификатора; идентификатор живого
//     аккаунта держит строку и после правки его имени;
//   - AID-41 — столкновение имени не обрывает транзакцию записи и не оставляет в
//     ключе строки за несостоявшимся аккаунтом.
//
// У каждого мира своя база (`newProbeEnv`): миры друг друга исключают — строка,
// взятая в одном как идентификатор, в другом не могла бы стать именем. Каждое
// заведение — от своего человека фикстуры (`createOutcome`): темп заведения
// считается на личность, а предмет — ключ.
//
// # Чем краснеет до реализации
//
// Создание с `id` заданной формы сегодня отвергается синхронно формой
// генератора (`create.go:249-250`, `invalid account id '<X>'`), и `createOutcome`
// роняет пробу с этим текстом — исход «предмета нет», а не поломка фикстуры:
// фикстура (база, люди, дублёр прав) построена и проверена раньше. Мир (г) AID-38
// краснеет утверждением: имя `acc7m3k9q2x5v8b4n6tl` сегодня принимается. Первая
// половина AID-41 зелёная сегодня — арбитр один, `accounts_name_unique`, — и
// закрепляет её против ключа Р6а.

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// foldLookAlike — свёртка похожих знаков Р6а: `o`→`0`, `i`/`l`→`1`. Проба
// держит её своим написанием ТОЛЬКО для счёта строк мира (сколько живых строк
// сворачиваются в одну); правило судит продукт, а не эта функция.
func foldLookAlike(s string) string {
	out := []byte(s)
	for i, c := range out {
		switch c {
		case 'o':
			out[i] = '0'
		case 'i', 'l':
			out[i] = '1'
		}
	}
	return string(out)
}

// accountsFoldingInto — живые строки `accounts`, чей идентификатор или имя после
// свёртки равны свёртке s.
func accountsFoldingInto(t *testing.T, env *testEnv, s string) int {
	t.Helper()
	rows, err := env.pool.Query(context.Background(), `SELECT id, name FROM kaname.accounts`)
	require.NoError(t, err)
	defer rows.Close()
	want, n := foldLookAlike(s), 0
	for rows.Next() {
		var id, name string
		require.NoError(t, rows.Scan(&id, &name))
		if foldLookAlike(id) == want || foldLookAlike(name) == want {
			n++
		}
	}
	require.NoError(t, rows.Err())
	return n
}

// createdAccount — создание, завершённое `response`; отдаёт аккаунт и проект по
// умолчанию (для снятия порядком AID-18).
func createdAccount(t *testing.T, env *testEnv, who string, a domain.Account) (id, name, defaultProject string) {
	t.Helper()
	uc := createUseCase(env, &relationDouble{admin: true})
	owner, _ := seedUserAccount(t, context.Background(), env.pool, who)
	a.Labels = domain.Labels{}
	op, err := uc.Execute(withPrincipal(owner), a)
	require.NoError(t, err, "%s: создание (id=%q, name=%q) отвергнуто синхронно", who, a.ID, a.Name)
	md := createMetadata(t, op)
	awaitWorkers(t)
	acc := responseAccount(t, finished(t, env, op.ID))
	return acc.GetId(), acc.GetName(), md.GetDefaultProjectId()
}

// ── AID-38 ───────────────────────────────────────────────────────────────────

// TestAccountID38_LookAlikeStringsDoNotDenoteASecondAccount — AID-38.
func TestAccountID38_LookAlikeStringsDoNotDenoteASecondAccount(t *testing.T) {
	// Мир (а): живой `{"id": "dlputi1u"}`; имена и идентификаторы `dlputilu`,
	// `dlput11u` совпадают с ним после свёртки. Текст — присланная строка.
	t.Run("world_a_folded_names_and_ids_are_refused", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		createdAccount(t, env, "aid38a-0", domain.Account{ID: ownerLoginDlputi})

		requireNameTaken(t, createOutcome(t, env, uc, "aid38a-1", domain.Account{Name: "dlputilu"}), "dlputilu")
		requireNameTaken(t, createOutcome(t, env, uc, "aid38a-2", domain.Account{Name: "dlput11u"}), "dlput11u")
		requireAlreadyExists(t, createOutcome(t, env, uc, "aid38a-3", domain.Account{ID: "dlputilu", Name: "aid38-a1"}), "dlputilu")
		requireAlreadyExists(t, createOutcome(t, env, uc, "aid38a-4", domain.Account{ID: "dlput11u", Name: "aid38-a2"}), "dlput11u")
		require.Equal(t, 1, accountsFoldingInto(t, env, ownerLoginDlputi), "после свёртки строку держит не ровно один аккаунт")

		// Близнецы: `k` и `m` ни с одним знаком строки не сворачиваются — проходят.
		require.Equal(t, "dlputiku", responseAccount(t, createOutcome(t, env, uc, "aid38a-5", domain.Account{Name: "dlputiku"})).GetName())
		require.Equal(t, "dlputimu", responseAccount(t, createOutcome(t, env, uc, "aid38a-6",
			domain.Account{ID: "dlputimu", Name: "aid38-a3"})).GetId())
	})

	// Мир (б): живой аккаунт без `id` с именем `godjee`. Идентификатор `g0djee`
	// отвергается (идентификатор ↔ имя другого — после свёртки); имя `g0djee`
	// принимается (имя ↔ имя — побайтово, как до этой работы).
	t.Run("world_b_name_pair_stays_bytewise", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		createdAccount(t, env, "aid38b-0", domain.Account{Name: ownerLoginGodjee})

		requireAlreadyExists(t, createOutcome(t, env, uc, "aid38b-1", domain.Account{ID: "g0djee", Name: "aid38-b"}), "g0djee")
		require.Equal(t, "g0djee", responseAccount(t, createOutcome(t, env, uc, "aid38b-2", domain.Account{Name: "g0djee"})).GetName(),
			"пара «имя ↔ имя другого» сравнилась после свёртки")
	})

	// Мир (в): собственная пара после свёртки не конфликтует.
	t.Run("world_v_own_pair_does_not_conflict", func(t *testing.T) {
		env := newProbeEnv(t)
		id, name, _ := createdAccount(t, env, "aid38v-0", domain.Account{ID: ownerLoginGodjee, Name: "g0djee"})
		require.Equal(t, ownerLoginGodjee, id)
		require.Equal(t, "g0djee", name)
	})

	// Мир (г): живой аккаунт формы генератора; имя `…tl` не формы генератора —
	// правило Р6 его пропускает, — но после свёртки совпадает с чужим id.
	t.Run("world_g_name_folding_into_a_generator_id", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		createdAccount(t, env, "aid38g-0", domain.Account{ID: suppliedLiteral})

		requireNameTaken(t, createOutcome(t, env, uc, "aid38g-1", domain.Account{Name: "acc7m3k9q2x5v8b4n6tl"}), "acc7m3k9q2x5v8b4n6tl")
		// Близнец: `u` не сворачивается — создание проходит.
		require.Equal(t, "acc7m3k9q2x5v8b4n6tu", responseAccount(t, createOutcome(t, env, uc, "aid38g-2",
			domain.Account{Name: "acc7m3k9q2x5v8b4n6tu"})).GetName())
	})

	// Мир (д): реестр сравнивает побайтово — названный остаток Р6а. До удаления
	// `godjee` строка `g0djee` занята ключом; после — выдаётся, а `godjee` держит
	// реестр (Р5).
	t.Run("world_d_registry_is_bytewise", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		_, _, prj := createdAccount(t, env, "aid38d-0", domain.Account{ID: ownerLoginGodjee})

		requireAlreadyExists(t, createOutcome(t, env, uc, "aid38d-1", domain.Account{ID: "g0djee"}), "g0djee")
		removeAccount(t, env, ownerLoginGodjee, prj)
		require.Equal(t, "g0djee", responseAccount(t, createOutcome(t, env, uc, "aid38d-2", domain.Account{ID: "g0djee"})).GetId(),
			"после удаления godjee строка g0djee не выдана: реестр сравнил после свёртки")
		requireAlreadyExists(t, createOutcome(t, env, uc, "aid38d-3", domain.Account{ID: ownerLoginGodjee}), ownerLoginGodjee)
	})

	// Мир (е): одновременно `{"id": "g0djee"}` и имя `godjee` — проходит ровно
	// одно; близнец — строки, которые друг в друга не сворачиваются: обе проходят.
	// Под -race, без time.Sleep: старт горутин — закрытием канала.
	for _, world := range []struct {
		name     string
		id       string
		bothPass bool
	}{
		{"world_e_race_of_two_folding_strings", "g0djee", false},
		{"world_e_twin_race_of_two_distinct_strings", "g9djee", true},
	} {
		t.Run(world.name, func(t *testing.T) {
			env := newProbeEnv(t)
			ctx := context.Background()
			byID, _ := seedUserAccount(t, ctx, env.pool, "aid38e-id")
			byName, _ := seedUserAccount(t, ctx, env.pool, "aid38e-name")
			uc := createUseCase(env, &relationDouble{admin: true})

			var opID, opName *operations.Operation
			var errID, errName error
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				opID, errID = uc.Execute(withPrincipal(byID), domain.Account{ID: domain.AccountID(world.id), Labels: domain.Labels{}})
			}()
			go func() {
				defer wg.Done()
				<-start
				opName, errName = uc.Execute(withPrincipal(byName), domain.Account{Name: ownerLoginGodjee, Labels: domain.Labels{}})
			}()
			close(start)
			wg.Wait()
			awaitWorkers(t)
			require.NoError(t, errName, "создание с именем godjee отвергнуто синхронно")
			require.NoError(t, errID, "создание с идентификатором %q отвергнуто синхронно", world.id)

			gotID, gotName := finished(t, env, opID.ID), finished(t, env, opName.ID)
			if world.bothPass {
				require.Equal(t, world.id, responseAccount(t, gotID).GetId())
				require.Equal(t, ownerLoginGodjee, responseAccount(t, gotName).GetName())
				return
			}
			switch {
			case gotID.Response != nil && gotName.Response == nil:
				requireNameTaken(t, gotName, ownerLoginGodjee)
			case gotName.Response != nil && gotID.Response == nil:
				requireAlreadyExists(t, gotID, world.id)
			default:
				t.Fatalf("из двух созданий строк, совпадающих после свёртки, прошло не ровно одно: по id — %v, по имени — %v",
					gotID.Error, gotName.Error)
			}
			require.Equal(t, 1, accountsFoldingInto(t, env, world.id), "после свёртки g0djee обозначает не ровно один аккаунт")
		})
	}
}

// ── AID-40 ───────────────────────────────────────────────────────────────────

// TestAccountID40_TwoConflictsAnswerTheIDTextAndALiveIDHoldsItsString — AID-40.
func TestAccountID40_TwoConflictsAnswerTheIDTextAndALiveIDHoldsItsString(t *testing.T) {
	// Мир (i): `id` конфликтует с живым B1, имя — с живым B2.
	t.Run("world_i_id_and_name_conflict_with_two_live_accounts", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		createdAccount(t, env, "aid40i-b1", domain.Account{ID: ownerLoginGodjee, Name: "aid40-b1"})
		createdAccount(t, env, "aid40i-b2", domain.Account{Name: ownerLoginDlputi})

		requireAlreadyExists(t, createOutcome(t, env, uc, "aid40i-1", domain.Account{ID: ownerLoginGodjee, Name: ownerLoginDlputi}), ownerLoginGodjee)
		// Близнецы, каждый на одно поле.
		requireAlreadyExists(t, createOutcome(t, env, uc, "aid40i-2", domain.Account{ID: ownerLoginGodjee, Name: "aid40-free"}), ownerLoginGodjee)
		requireNameTaken(t, createOutcome(t, env, uc, "aid40i-3", domain.Account{ID: "aid40-free", Name: ownerLoginDlputi}), ownerLoginDlputi)
	})

	// Мир (ii): строку `godjee` держит реестр (аккаунт удалён), имя `dlputi1u` —
	// живой B2. Текст — идентификатора, какое бы ограничение база ни проверила первым.
	t.Run("world_ii_registry_and_name_key", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		_, _, prj := createdAccount(t, env, "aid40ii-g", domain.Account{ID: ownerLoginGodjee})
		removeAccount(t, env, ownerLoginGodjee, prj)
		createdAccount(t, env, "aid40ii-b2", domain.Account{Name: ownerLoginDlputi})

		requireAlreadyExists(t, createOutcome(t, env, uc, "aid40ii-1", domain.Account{ID: ownerLoginGodjee, Name: ownerLoginDlputi}), ownerLoginGodjee)
		// Близнец: `id`, которого реестр не держит.
		requireNameTaken(t, createOutcome(t, env, uc, "aid40ii-2", domain.Account{ID: "aid40-free2", Name: ownerLoginDlputi}), ownerLoginDlputi)
	})

	// Мир (iii): оба поля конфликтуют с ключом Р6а, каждое — со своим аккаунтом.
	t.Run("world_iii_both_fields_against_the_key", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		createdAccount(t, env, "aid40iii-b3", domain.Account{Name: "aid40-n3"})
		createdAccount(t, env, "aid40iii-b4", domain.Account{ID: "aid40-i4", Name: "aid40-b4"})

		requireAlreadyExists(t, createOutcome(t, env, uc, "aid40iii-1", domain.Account{ID: "aid40-n3", Name: "aid40-i4"}), "aid40-n3")
		// Близнец: идентификатор свободен.
		requireNameTaken(t, createOutcome(t, env, uc, "aid40iii-2", domain.Account{ID: "aid40-free3", Name: "aid40-i4"}), "aid40-i4")
	})

	// Мир (iv): идентификатор живого C держит строку и после правки его имени;
	// правка обратно — собственная пара.
	t.Run("world_iv_live_id_holds_its_string_after_rename", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		createdAccount(t, env, "aid40iv-c", domain.Account{ID: ownerLoginGodjee})
		renameAccount(t, env, ownerLoginGodjee, ownerLoginGodjee+"-x")

		requireNameTaken(t, createOutcome(t, env, uc, "aid40iv-1", domain.Account{Name: ownerLoginGodjee}), ownerLoginGodjee)
		renameAccount(t, env, ownerLoginGodjee, ownerLoginGodjee)
	})

	// Мир (iv-б) — близнец создания мира (iv), своя база: одно различие — после
	// той же правки имени C удалён; строку держит только живой идентификатор.
	t.Run("world_iv_b_twin_deleted_id_does_not_hold_the_name", func(t *testing.T) {
		env := newProbeEnv(t)
		uc := createUseCase(env, &relationDouble{admin: true})
		_, _, prj := createdAccount(t, env, "aid40ivb-c", domain.Account{ID: ownerLoginGodjee})
		renameAccount(t, env, ownerLoginGodjee, ownerLoginGodjee+"-x")
		removeAccount(t, env, ownerLoginGodjee, prj)

		require.Equal(t, ownerLoginGodjee, responseAccount(t, createOutcome(t, env, uc, "aid40ivb-1",
			domain.Account{Name: ownerLoginGodjee})).GetName())
	})
}

// ── AID-41 ───────────────────────────────────────────────────────────────────

// TestAccountID41_NameCollisionKeepsTheWriteTxUsableAndLeavesNoOrphanInTheKey —
// AID-41. Первая половина — транзакция записи хранилища: столкновение имени
// отвечает «занято», строки не вставляет, транзакция годна. Вторая — после
// удаления B строка `aid41-taken` принимается и как идентификатор, и как имя по
// умолчанию: несостоявшаяся вставка C не оставила в ключе строки ни в одной роли.
func TestAccountID41_NameCollisionKeepsTheWriteTxUsableAndLeavesNoOrphanInTheKey(t *testing.T) {
	env := newProbeEnv(t)
	ctx := context.Background()
	const taken, next = "aid41-taken", "aid41-next"
	bID, _, bPrj := createdAccount(t, env, "aid41-b", domain.Account{Name: taken})
	cOwner, _ := seedUserAccount(t, ctx, env.pool, "aid41-c")

	// Близнец: та же транзакция с именем, не занятым никем, — первая вставка проходит.
	twinOwner, _ := seedUserAccount(t, ctx, env.pool, "aid41-twin")
	tw, err := env.repo.Writer(ctx)
	require.NoError(t, err)
	_, err = tw.AccountsW().Insert(ctx, domain.Account{
		ID: domain.AccountID(ids.NewID(domain.PrefixAccount)), Name: "aid41-free", Labels: domain.Labels{}, OwnerUserID: twinOwner,
	})
	require.NoError(t, err, "близнец: вставка со свободным именем отвергнута")
	require.NoError(t, tw.Commit(ctx))

	cID := domain.AccountID(ids.NewID(domain.PrefixAccount))
	w, err := env.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = w.AccountsW().Insert(ctx, domain.Account{ID: cID, Name: taken, Labels: domain.Labels{}, OwnerUserID: cOwner})
	require.Error(t, err, "вставка с занятым именем прошла")
	require.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists), "ожидается ErrAlreadyExists: %v", err)
	_, err = w.AccountsW().Insert(ctx, domain.Account{ID: cID, Name: next, Labels: domain.Labels{}, OwnerUserID: cOwner})
	require.NoError(t, err, "транзакция записи оборвана столкновением имени: вторая вставка не прошла")
	require.NoError(t, w.Commit(ctx), "фиксация после столкновения имени")
	var gotName string
	require.NoError(t, env.pool.QueryRow(ctx, `SELECT name FROM kaname.accounts WHERE id = $1`, string(cID)).Scan(&gotName))
	require.Equal(t, next, gotName)

	removeAccount(t, env, bID, bPrj)
	uc := createUseCase(env, &relationDouble{admin: true})
	got := createOutcome(t, env, uc, "aid41-d", domain.Account{ID: taken})
	require.Nil(t, got.Error, "строка %s осталась в ключе за несостоявшимся аккаунтом: %v", taken, got.Error)
	require.Equal(t, taken, responseAccount(t, got).GetId())
}
