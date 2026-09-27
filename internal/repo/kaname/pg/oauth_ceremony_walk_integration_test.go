// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_walk_integration_test.go — ХОД ДВИЖКА над хранилищами
// церемонии (`oauth_ceremony_vaults.go`) для проб слоя доступа (задача
// PRO-Robotech/kaname#434).
//
// # Зачем он есть
//
// Обмен кода и оборот токена обновления в прод-сборке (`cmd/kaname/ceremony.go`)
// исполняет движок фундамента (`corelib/oauthceremony`) над CeremonyVaults.
// Пробы гонки, изоляции, порядка замков, отсечки и снятия сессии судят базу под
// этими вызовами и обязаны судить её на ТЕХ ЖЕ вызовах: своих композиций обмена
// и оборота у слоя доступа больше нет, и зелёное на них о прод-пути ничего не
// говорило.
//
// # Что здесь настоящее, а что подставлено
//
// Настоящее: хранилища (CeremonyVaults), их единица запроса и единица работы,
// адаптер порта отзыва (`ceremonyport.Grants`) и писатель отзыва семейства
// (`OAuthCeremonyRepo.RevokeFamily`) — над настоящей базой.
//
// Подставлен ДВИЖОК: порядок его вызовов и одно его решение.
//
//   - порядок — тот, что назван шапкой хранилищ: обмен — единица запроса,
//     выборка кода, погашение, единица работы, первое поколение токена
//     обновления, закрепление, урегулирование; оборот — выборка токена, единица
//     работы, замок оборота, преемник, закрепление;
//   - решение — СИГНАЛ ПОВТОРА отзывает семейство портом отзыва словом повтора.
//     Сигнал — запись вместе с ErrAuthorizationCodeConsumed либо
//     ErrRefreshTokenRotated на выборке, ноль строк погашения либо замка
//     оборота после живой выборки. Так решает мост фундамента
//     (`oauthceremony/bridge.go`: replayedCode, consumeCode,
//     GetRefreshTokenSession, RotateRefreshToken).
//
// Что движок зовёт отзыв на этом исходе и этим словом, держат пробы с настоящим
// движком: `internal/ceremonyport`
// (`TestK1_RevokedFamilyIsRefusedWhereTheAccessTokenIsPresented`) и сквозные
// пробы прод-сборки `cmd/kaname` (LINE-A-1-13, 17, 21, 28).
//
// Записи выпуска токена доступа ход не кладёт: её кладёт порт выпуска
// (`ceremonyport.AccessTokens`), и пробы, которым она нужна, сеют её сами.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// walkOutcome — исход хода так, как его различает движок.
type walkOutcome int

const (
	// walkRefused — ни выдачи, ни повтора: хранилище отказало (причина — в
	// ошибке хода).
	walkRefused walkOutcome = iota
	// walkIssued — выдача закреплена.
	walkIssued
	// walkReplay — сигнал повтора: семейство отозвано портом отзыва.
	walkReplay
)

func (o walkOutcome) String() string {
	switch o {
	case walkRefused:
		return "отказ"
	case walkIssued:
		return "выдача"
	case walkReplay:
		return "повтор"
	}
	return fmt.Sprintf("исход %d вне словаря хода", int(o))
}

// ceremonyWalk — ход движка над хранилищами пула и настоящий порт отзыва.
type ceremonyWalk struct {
	v      *kanamepg.CeremonyVaults
	grants *ceremonyport.Grants
}

func newCeremonyWalk(t *testing.T, pool *pgxpool.Pool) ceremonyWalk {
	t.Helper()
	grants, err := ceremonyport.NewGrants(kanamepg.NewOAuthCeremonyRepo(pool))
	require.NoError(t, err, "адаптер порта отзыва не собран")
	return ceremonyWalk{v: ceremonyVaults(t, pool), grants: grants}
}

// walkRefreshTTL — срок токена обновления, который ход называет хранилищу:
// поле гранта, без которого хранилище токен не заводит.
const walkRefreshTTL = time.Hour

// withRefreshExpiry — грант записи со сроком токена обновления, как его
// подаёт движок хранилищу токена обновления.
func withRefreshExpiry(g oauthceremony.GrantRecord) oauthceremony.GrantRecord {
	g.Session.ExpiresAt = map[oauthceremony.TokenKind]time.Time{
		oauthceremony.TokenKindRefresh: time.Now().Add(walkRefreshTTL),
	}
	return g
}

// exchange — обмен кода code на первое поколение токена обновления rt в своей
// единице запроса. Урегулирование — ровно один раз, после операции.
func (w ceremonyWalk) exchange(ctx context.Context, code, rt string) (walkOutcome, error) {
	reqCtx, settle := w.v.OpenRequest(ctx)
	out, err := w.exchangeInRequest(reqCtx, code, rt)
	if serr := settle(ctx); serr != nil {
		return out, errors.Join(err, fmt.Errorf("урегулирование запроса: %w", serr))
	}
	return out, err
}

// exchangeInRequest — обмен в открытой единице запроса.
func (w ceremonyWalk) exchangeInRequest(ctx context.Context, code, rt string) (walkOutcome, error) {
	rec, err := w.v.FetchAuthorizationCode(ctx, code)
	switch {
	case errors.Is(err, oauthceremony.ErrAuthorizationCodeConsumed):
		return w.replayed(ctx, rec.Grant.GrantID, oauthceremony.RevocationCodeReplay)
	case err != nil:
		return walkRefused, fmt.Errorf("выборка кода: %w", err)
	}
	consumed, err := w.v.ConsumeAuthorizationCode(ctx, code)
	if err != nil {
		return walkRefused, fmt.Errorf("погашение кода: %w", err)
	}
	if consumed.Rows() == 0 {
		return w.replayed(ctx, rec.Grant.GrantID, oauthceremony.RevocationCodeReplay)
	}
	unit, err := w.v.Begin(ctx)
	if err != nil {
		return walkRefused, fmt.Errorf("единица работы обмена: %w", err)
	}
	if _, err := w.v.StoreRefreshToken(unit, rt, "", withRefreshExpiry(rec.Grant)); err != nil {
		return walkRefused, errors.Join(fmt.Errorf("первое поколение токена обновления: %w", err), w.v.Rollback(unit))
	}
	if err := w.v.Commit(unit); err != nil {
		return walkRefused, fmt.Errorf("закрепление обмена: %w", err)
	}
	return walkIssued, nil
}

// rotate — оборот предъявленного токена обновления в преемника successor.
func (w ceremonyWalk) rotate(ctx context.Context, presented, successor string) (walkOutcome, error) {
	grant, err := w.v.FetchRefreshToken(ctx, presented)
	switch {
	case errors.Is(err, oauthceremony.ErrRefreshTokenRotated):
		return w.replayed(ctx, grant.GrantID, oauthceremony.RevocationRefreshReplay)
	case err != nil:
		return walkRefused, fmt.Errorf("выборка токена обновления: %w", err)
	}
	unit, err := w.v.Begin(ctx)
	if err != nil {
		return walkRefused, fmt.Errorf("единица работы оборота: %w", err)
	}
	locked, err := w.v.RotateRefreshToken(unit, grant.GrantID, presented)
	if err != nil {
		return walkRefused, errors.Join(fmt.Errorf("замок оборота: %w", err), w.v.Rollback(unit))
	}
	if locked.Rows() == 0 {
		if err := w.v.Rollback(unit); err != nil {
			return walkRefused, fmt.Errorf("откат оборота, опереженного другим: %w", err)
		}
		return w.replayed(ctx, grant.GrantID, oauthceremony.RevocationRefreshReplay)
	}
	if _, err := w.v.StoreRefreshToken(unit, successor, "", withRefreshExpiry(grant)); err != nil {
		return walkRefused, errors.Join(fmt.Errorf("преемник оборота: %w", err), w.v.Rollback(unit))
	}
	if err := w.v.Commit(unit); err != nil {
		return walkRefused, fmt.Errorf("закрепление оборота: %w", err)
	}
	return walkIssued, nil
}

// replayed — решение движка на сигнал повтора: отзыв семейства портом отзыва.
func (w ceremonyWalk) replayed(ctx context.Context, grantID string, reason oauthceremony.RevocationReason) (walkOutcome, error) {
	if _, err := w.grants.RevokeGrantRefreshTokens(ctx, grantID, reason); err != nil {
		return walkReplay, fmt.Errorf("отзыв семейства повтора: %w", err)
	}
	return walkReplay, nil
}

// requireWalkIssued — посев через ход: выдача обязана состояться.
func requireWalkIssued(t *testing.T, out walkOutcome, err error, what string) {
	t.Helper()
	require.NoError(t, err, what)
	require.Equal(t, walkIssued, out, "%s: исход хода %s, ожидалась выдача", what, out)
}
