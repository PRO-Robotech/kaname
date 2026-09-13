// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// list_all_operations_store_outage_test.go — ListAllOperations: неполадка
// ЧТЕНИЯ АККАУНТА обязана прийти недоступностью, а не отказом в правах
// (задача #2585).
//
// Полоса своя и соседней не покрывается: `cluster_admin_outage_lane_test.go`
// наводит неполадку на хранилище ПРАВ, то есть на вопрос, заданный после
// успешного чтения аккаунта. Здесь не отвечает само хранилище аккаунтов, и до
// вопроса о правах управление не доходит вовсе.
//
// Довод — тот же, что у соседа, и он про ПОВТОРИМОСТЬ: отказ в правах
// терминален (решение зависит от тройки «субъект · отношение · объект», и
// одинаковый повтор не меняет ни одной), а неполадка чтения о правах не
// говорит ничего — тот же вопрос мгновением позже получает ответ. Цена
// схлопывания здесь своя: это НАДЗОР, и аудитор, получив «не положено» на
// преходящую беду, заключает, что доступа нет.
//
// Рядом — законный близнец: промах обязан остаться ПОБАЙТОВО тем же отказом в
// правах, что и настоящий отказ. Скрытие существования снимать не требовалось,
// и проба это утверждает, а не подразумевает.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
)

// ── дублёр: чтение аккаунта отвечает НАЗНАЧЕННОЙ ошибкой ────────────────────
//
// Одно-фактность: от `acctListFakeRepo` он отличается ровно исходом
// `Accounts().Get` и ничем больше — всё остальное унаследовано вложением.

type acctGetErrRepo struct {
	*acctListFakeRepo
	getErr error
}

func (f *acctGetErrRepo) Reader(ctx context.Context) (kanamerepo.Reader, error) {
	inner, err := f.acctListFakeRepo.Reader(ctx)
	if err != nil {
		return nil, err
	}
	return &acctGetErrReader{Reader: inner, getErr: f.getErr}, nil
}

type acctGetErrReader struct {
	kanamerepo.Reader
	getErr error
}

func (r *acctGetErrReader) Accounts() repoaccount.ReaderIface {
	return &acctGetErrAccounts{ReaderIface: r.Reader.Accounts(), getErr: r.getErr}
}

type acctGetErrAccounts struct {
	repoaccount.ReaderIface
	getErr error
}

func (a *acctGetErrAccounts) Get(ctx context.Context, id domain.AccountID) (domain.Account, error) {
	if a.getErr != nil {
		return domain.Account{}, a.getErr
	}
	return a.ReaderIface.Get(ctx, id)
}

func newAcctGetErrRepo(getErr error) *acctGetErrRepo {
	return &acctGetErrRepo{acctListFakeRepo: newAcctListFakeRepo(), getErr: getErr}
}

// TestListAllOperations_AccountStoreOutage_IsUnavailableNotDenied — предмет
// задачи: преходящая неполадка чтения аккаунта обязана дать UNAVAILABLE.
func TestListAllOperations_AccountStoreOutage_IsUnavailableNotDenied(t *testing.T) {
	repo := newAcctGetErrRepo(iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable"))
	uc := newListAllUC(repo, &acctAdminCheckStub{allow: map[string]bool{}}, &acctAllOpsRepo{})

	got, next, err := uc.Execute(ctxUser("usr-auditor"), "acc0000000000000acct", 50, "")

	if err == nil {
		t.Fatal("неотвеченное чтение аккаунта не прервало выдачу: отказа нет вовсе")
	}
	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("код ответа %s, ожидался Unavailable: «прочитать не удалось» сообщено аудитору "+
			"как «не положено», и повтор выглядит бессмысленным (ошибка: %v)", code, err)
	}
	if got != nil || next != "" {
		t.Fatalf("выдача не прервана: строк=%d, курсор=%q", len(got), next)
	}
}

// TestListAllOperations_AccountMiss_StaysByteIdenticalPermissionDenied —
// законный близнец. Без него проба выше зеленела бы и на правке, снявшей
// скрытие существования: промах отвечал бы NotFound, то есть оракулом.
func TestListAllOperations_AccountMiss_StaysByteIdenticalPermissionDenied(t *testing.T) {
	ops := &acctAllOpsRepo{}

	// (а) промах — аккаунта нет.
	missRepo := newAcctListFakeRepo() // Get промахивается признаком продукта
	_, _, missErr := newListAllUC(missRepo, &acctAdminCheckStub{allow: map[string]bool{}}, ops).
		Execute(ctxUser("usr-stranger"), "acc0000000000000miss", 50, "")

	// (б) настоящий отказ — аккаунт есть, прав нет.
	denyRepo := newAcctListFakeRepo()
	seedAcct(denyRepo, "acc0000000000000acct", "usr-owner")
	_, _, denyErr := newListAllUC(denyRepo, &acctAdminCheckStub{allow: map[string]bool{}}, ops).
		Execute(ctxUser("usr-stranger"), "acc0000000000000acct", 50, "")

	if missErr == nil || denyErr == nil {
		t.Fatalf("оба исхода обязаны быть отказом: промах=%v, отказ=%v", missErr, denyErr)
	}
	missSt, denySt := status.Convert(missErr), status.Convert(denyErr)
	if missSt.Code() != codes.PermissionDenied {
		t.Fatalf("промах ответил %s, ожидался PermissionDenied: скрытие существования снято (ошибка: %v)",
			missSt.Code(), missErr)
	}
	if missSt.Code() != denySt.Code() || missSt.Message() != denySt.Message() {
		t.Fatalf("промах и настоящий отказ различимы — это оракул существования:\n"+
			"  промах: %s %q\n  отказ:  %s %q",
			missSt.Code(), missSt.Message(), denySt.Code(), denySt.Message())
	}
}
