// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reset_second_factor_holder_line_integration_test.go — ЛИНИЯ ДЕРЖАТЕЛЯ сброса
// второго фактора на НАСТОЯЩЕЙ базе (kaname#254, приёмка Ф12-30, Р10).
//
// # Предмет и чем он отличается от unit-пробы рядом
//
// Разбор доступа (кто вправе) решает край отношением `identity_suspender` — он
// закреплён вердиктом по строкам в `internal/service` и здесь НЕ переутверждается.
// Держатель, прошедший край, получает от СЛУЖБЫ линию прямого чтения своей записи:
// несуществующий well-formed `user_id` — `NOT_FOUND`/404 `User <id> not found`
// (раньше состояния строки), кривой по форме id — `INVALID_ARGUMENT`/400
// `invalid user id '<X>'` (раньше чтения). Так это отвечает не держателю ТОЖЕ, но не
// держателю до службы дело не доходит: край отвечает `403` до вызова, оракула
// существования не давая (это и есть «отказ, неотличимый от отсутствия», Ф12-30).
//
// Соседняя `reset_second_factor_test.go` закрепляет эти два исхода на ДУБЛЁРЕ
// репозитория (инъекция `getErr`). Здесь предмет — что РЕАЛЬНЫЙ репозиторий Postgres
// производит промах строкой `ErrNotFound "User <id> not found"` (user_repo.go), а
// `MapRepoErr` переводит его в 404: инъекцию ошибки заменяет отсутствие строки.
//
// Настоящий Postgres. Пропускается под кратким режимом.

package user

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestResetSecondFactorHolderLineOnBadIdsFromRealDB — держатель на кривом и
// несуществующем `user_id` против настоящей базы: форма (400) — раньше чтения,
// промах (404) — контракт-тоном; существующий человек в 404 не попадает.
func TestResetSecondFactorHolderLineOnBadIdsFromRealDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	// ── КРИВОЙ ПО ФОРМЕ id — 400, РАНЬШЕ ЧТЕНИЯ ─────────────────────────────────
	// Форму судит `ValidateResourceID` до `repo.Reader`, поэтому репозиторий здесь
	// не задействован — но проба идёт через тот же вход, что и остальные исходы.
	badForm := "not-a-user-id"
	uc := NewResetSecondFactorUseCase(repo, nil, nil, nil)
	_, err = uc.Execute(ownerCtx(), domain.UserID(badForm))
	require.Error(t, err, "кривой по форме id обязан быть отвергнут")
	require.Equalf(t, codes.InvalidArgument, status.Code(err),
		"кривой id — `INVALID_ARGUMENT`/400, раньше права и раньше чтения (получено %s)", status.Code(err))
	require.Equalf(t, "invalid user id '"+badForm+"'", status.Convert(err).Message(),
		"служба на кривой id отвечает своим текстом формы (край отвечает `invalid resource id` — это линия сквозной через край)")

	// ── НЕСУЩЕСТВУЮЩИЙ WELL-FORMED id — 404 `User <id> not found` ───────────────
	// Форма верна, строки НЕТ: реальный `userReader.Get` промахивается строкой
	// `ErrNotFound`, `MapRepoErr` переводит её в `NOT_FOUND`. Инъекции ошибки нет —
	// её роль играет отсутствие строки.
	absent := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = uc.Execute(ownerCtx(), absent)
	require.Error(t, err, "сброс на несуществующем человеке обязан промахнуться")
	require.Equalf(t, codes.NotFound, status.Code(err),
		"промах — `NOT_FOUND`/404 (получено %s)", status.Code(err))
	require.Equalf(t, "User "+string(absent)+" not found", status.Convert(err).Message(),
		"промах — контракт-тоном, байт-идентичным сокрытию существования держателю")

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: существующий человек в 404 НЕ ПОПАДАЕТ ──────────
	// Без него отрицание выше зеленело бы и на дереве, где реальный репозиторий
	// промахивается ВСЕГДА. Существующая строка найдена — служба идёт дальше, к
	// состоянию фактора, и отвечает «фактора нет» (строки способа не сеяны), то есть
	// `FAILED_PRECONDITION`, а НЕ `NOT_FOUND`.
	present, _ := seedUserWithAccount(t, ctx, repo, "hold2")
	ucFound := NewResetSecondFactorUseCase(repo, nil, &rsfMethods{}, nil)
	_, err = ucFound.Execute(ownerCtx(), present)
	require.Error(t, err, "у существующего человека второго фактора нет — сброс отвечает отказом состояния")
	require.NotEqualf(t, codes.NotFound, status.Code(err),
		"существующий человек ошибочно получил 404: реальный репозиторий его не нашёл — тогда промах выше вакуумен (получено %s)", status.Code(err))
	require.Equalf(t, codes.FailedPrecondition, status.Code(err),
		"существующий человек без фактора — `FAILED_PRECONDITION` (строка найдена, судится состояние), получено %s", status.Code(err))

	t.Logf("перепись линии держателя: кривой id → %s · несуществующий well-formed → %s · существующий без фактора → %s",
		codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition)
}
