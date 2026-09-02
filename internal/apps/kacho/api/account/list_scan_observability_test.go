// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// list_scan_observability_test.go — величина «сколько строк рассмотрено ради
// одной страницы» снимается В USE-CASE, на выходе из цикла догрузки (#653).
//
// # Что именно здесь утверждается — и почему обе стороны обязательны
//
// Съём, поставленный ВНУТРИ слоя видимости, померил бы последнюю догрузку и
// остался бы постоянным при любом их числе: наблюдаемость выродилась бы в
// константу, неотличимую от исправной. Поэтому проба ставит вопрос с двух
// сторон сразу:
//
//	догрузки  — страница, набранная за три обхода, обязана показать ТРИ
//	            обращения к хранилищу и ВСЕ рассмотренные строки, а не только
//	            отданные;
//	один лист — та же величина на странице без добора обязана показать ОДНО
//	            обращение. Без этой половины «растёт» зеленело бы и на счётчике,
//	            который просто считает вызовы Execute.
//
// Третья сторона — непровязанный съёмщик: наблюдение выключено, а не сломано.
package account

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	repoaccount "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
)

// ───────────── пагинирующий фейк: уважает курсор и размер порции ─────────────
//
// Фейк из list_authz_test.go отдаёт ВСЁ одним ответом и добора не производит
// by construction — на нём «несколько догрузок» не воспроизвести.

type acctPagedRepo struct{ *acctListFakeRepo }

func (f *acctPagedRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &acctPagedReader{&acctListFakeReader{f.acctListFakeRepo}}, nil
}

type acctPagedReader struct{ *acctListFakeReader }

func (r *acctPagedReader) Accounts() repoaccount.ReaderIface {
	return &acctPagedAccounts{&acctListReader{r.p}}
}

type acctPagedAccounts struct{ *acctListReader }

func (a *acctPagedAccounts) List(_ context.Context, f repoaccount.ListFilter) ([]domain.Account, string, error) {
	ids := make([]string, 0, len(a.p.accounts))
	for k := range a.p.accounts {
		ids = append(ids, k)
	}
	sort.Strings(ids)

	out := make([]domain.Account, 0, f.PageSize)
	for _, id := range ids {
		if f.After != nil && id <= f.After.ID {
			continue
		}
		out = append(out, a.p.accounts[id])
		if len(out) == int(f.PageSize) {
			break
		}
	}
	return out, "", nil
}

func seedPagedAcct(r *acctListFakeRepo, id, owner string) {
	// Одна и та же отметка времени у всех: порядок разрешает id, а курсор
	// use-case несёт обе половины — так фейк остаётся честным к keyset-обходу.
	r.accounts[id] = domain.Account{
		ID: domain.AccountID(id), Name: domain.AccountName("n-" + id),
		OwnerUserID: domain.UserID(owner),
		CreatedAt:   time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC),
	}
}

// ───────────── съёмщик-свидетель ─────────────

type acctScanWitness struct {
	resource string
	rows     int
	checks   int
	calls    int
}

func (w *acctScanWitness) ObserveListScan(_ context.Context, resource string, rows, checks int) {
	w.resource, w.rows, w.checks = resource, rows, checks
	w.calls++
}

// ───────────── сторона 1: несколько догрузок ─────────────

func TestListScan_CountsEveryRefill_NotOnlyTheLastOne(t *testing.T) {
	repo := newAcctListFakeRepo()
	for _, id := range []string{"acc-1", "acc-2", "acc-3", "acc-4", "acc-5",
		"acc-6", "acc-7", "acc-8", "acc-9"} {
		seedPagedAcct(repo, id, "usr-other00000000000")
	}

	// Видимы только три последних ⇒ страница набирается на третьем обходе.
	fga := newAcctFGAStub()
	fga.set("user:usr-u1", []string{"acc-7", "acc-8", "acc-9"})

	w := &acctScanWitness{}
	uc := NewListAccountsUseCase(&acctPagedRepo{repo}).
		WithRelationStore(fga).
		WithListScanRecorder(w)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, out, 2, "страница отдаёт запрошенные две строки")

	require.Equal(t, 1, w.calls, "величина снимается ровно один раз за запрос")
	require.Equal(t, "account", w.resource, "вид ресурса размечен")
	require.Equal(t, 3, w.checks,
		"три обращения к хранилищу — по одному на догрузку; съём внутри слоя "+
			"видимости показал бы 1 при любом их числе")
	require.Equal(t, 9, w.rows,
		"рассмотрены ВСЕ девять строк, а не две отданные — стоимость страницы "+
			"и есть предмет замера")
}

// ───────────── сторона 2: одностраничный обход ─────────────

func TestListScan_SinglePage_DoesNotInflate(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedPagedAcct(repo, "acc-1", "usr-u1")
	seedPagedAcct(repo, "acc-2", "usr-u1")

	fga := newAcctFGAStub()
	fga.set("user:usr-u1", []string{"acc-1", "acc-2"})

	w := &acctScanWitness{}
	uc := NewListAccountsUseCase(&acctPagedRepo{repo}).
		WithRelationStore(fga).
		WithListScanRecorder(w)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, out, 2)

	require.Equal(t, 1, w.checks, "добора не было — обращение одно")
	require.Equal(t, 2, w.rows, "рассмотрено ровно то, что отдано")
}

// ───────────── сторона 3: съёмщик не провязан ─────────────

func TestListScan_UnwiredRecorder_IsOffNotBroken(t *testing.T) {
	repo := newAcctListFakeRepo()
	seedPagedAcct(repo, "acc-1", "usr-u1")

	fga := newAcctFGAStub()
	fga.set("user:usr-u1", []string{"acc-1"})

	uc := NewListAccountsUseCase(&acctPagedRepo{repo}).WithRelationStore(fga)

	out, _, err := uc.Execute(ctxUser("usr-u1"), repoaccount.ListFilter{PageSize: 2})
	require.NoError(t, err, "непровязанный съёмщик не роняет запрос")
	require.Len(t, out, 1)
}

// ───────────── пустой съёмщик остаётся годным приёмником ─────────────

func TestListScan_NoopRecorderAccepts(t *testing.T) {
	var s shared.ListScan
	s.AddBatch(4)
	s.AddBatch(3)
	require.Equal(t, 7, s.Rows)
	require.Equal(t, 2, s.Checks)
	s.Report(context.Background(), shared.NoopListScanRecorder{}, "account")
}
