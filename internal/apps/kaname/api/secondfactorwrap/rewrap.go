// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secondfactorwrap — переобёртка секретов второго фактора под ПЕРВЫЙ
// ключ перечня `authn.second-factor-encryption-key-hex` (kaname#259 п.3).
//
// # Зачем
//
// Перечень ключей обёртки даёт ЗАМЕЩЕНИЕ ключа — новый ставится первым, все
// открывают, — но не ВЫВОД: прежний ключ открывает каждый секрет, записанный
// им, и снять его из перечня значит отдать недоступность (503) каждому, чей
// секрет им обёрнут. Проход переносит каждый такой секрет под первый ключ;
// после него прежний ключ не читает ни одной строки и снимается.
//
// # Как проход держит свои свойства
//
//   - БЕЗ ПОТЕРИ: секрет не меняется, меняется только обёртка — приложение
//     человека даёт те же коды, принятый шаг строки остаётся в силе;
//   - КАЖДАЯ ЗАМЕНА — CAS ПО ПРОЧИТАННОМУ: материал строки сменяется, только
//     пока он побайтово тот, что проход прочитал (ban #10). Служба, заведшая
//     фактор заново или снявшая его, пока проход держал прежнее значение,
//     выигрывает: переобёрнутый ПРЕЖНИЙ секрет поверх нового не ложится, снятая
//     строка не воскресает. Промах замены — перечитывание строки;
//   - СРЫВ НА СЕРЕДИНЕ БЕЗОПАСЕН: у каждой строки своя замена, зафиксированная
//     отдельно, поэтому в любой момент каждая строка — либо под первым ключом,
//     либо под прежним, который ещё назван в перечне. Повтор довершает;
//   - ПОВТОР ИДЕМПОТЕНТЕН: строка, уже обёрнутая первым ключом, не пишется.
//
// # Исходы — по типу, а не по значению
//
// `Run` возвращает счёт (`Report`) и отказ. Отказ — «не смог спросить»:
// хранилище не ответило, сделанное до него названо счётом и зафиксировано.
// Счёт без отказа различает «каждый секрет под первым ключом» (`Settled`) и
// «проход прошёл, но не всё переехало»: секрет, которого не открывает ни один
// ключ перечня, и строка, не устоявшаяся за бюджет замен, — остаток, и
// прежние ключи при нём не снимаются.
package secondfactorwrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// Store — хранилище строк второго фактора, над которым идёт проход. Исполняет
// его адаптер способа входа (`internal/repo/kaname/pg`), единственный файл,
// которому дано назвать таблицу секрета.
type Store interface {
	// TOTPSecretsAfter — строки вида `totp` ОБОИХ состояний (подтверждённые и
	// заведения — секрет под ключом обёртки есть у тех и у других) с
	// человеком строго после after, по возрастанию человека, не больше limit.
	TOTPSecretsAfter(ctx context.Context, after domain.UserID, limit int) ([]domain.LoginMethod, error)
	// SwapTOTPSecret — замена материала строки `totp` человека на next ТОЛЬКО
	// если он побайтово равен prev; меняется один материал. false — материал
	// уже другой либо строки нет.
	SwapTOTPSecret(ctx context.Context, user domain.UserID, prev, next domain.LoginVerifier) (bool, error)
	// Get — строка человека данного вида; NOT_FOUND — строки нет.
	Get(ctx context.Context, user domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error)
}

// Rewrapper — переобёртка хранимого секрета под первый ключ перечня (порт по
// существующему типу `totpverify.Verifier`): (stored, true) — уже под ним;
// (новое, false) — переобёрнут; `totpverify.ErrSecretUnreadable` — не
// открывается перечнем.
type Rewrapper interface {
	Rewrap(stored domain.LoginVerifier) (domain.LoginVerifier, bool, error)
}

// SwapAttempts — бюджет замен одной строки.
//
// Выведен из аргумента о прогрессе, а не выбран: промах замены доказывает, что
// конкурент ЗАФИКСИРОВАЛ новое значение строки (замена ждёт его замка и судит
// условие по зафиксированному). Значение, положенное службой с тем же первым
// ключом, при перечитывании уже под ним — строка устаивается второй попыткой.
// Третья покрывает реплику, у которой первым ещё стоял прежний ключ: её
// значение переобёртывается ещё раз. Строка, которую меняют перед КАЖДОЙ
// заменой, дольше не держит проход: она — остаток «не устоялось», и повтор
// команды пройдёт её снова.
const SwapAttempts = 3

// Report — счёт прохода. Каждая строка, увиденная проходом, попадает ровно в
// одну клетку: Rows = Rewrapped + Current + Unreadable + Vanished + Unsettled.
type Report struct {
	// Rows — строк `totp`, увиденных проходом.
	Rows int
	// Rewrapped — переобёрнуто этим проходом.
	Rewrapped int
	// Current — уже были под первым ключом: писать было нечего.
	Current int
	// Unreadable — не открываются ни одним ключом перечня: не тронуты.
	Unreadable int
	// Vanished — строку сняли, пока проход держал её значение.
	Vanished int
	// Unsettled — строку меняли перед каждой заменой дольше бюджета.
	Unsettled int
}

// Settled — каждая увиденная строка, которая существует, под первым ключом.
// Только при этом исходе прежние ключи можно снимать из перечня.
func (r Report) Settled() bool { return r.Unreadable == 0 && r.Unsettled == 0 }

// UseCase — проход переобёртки.
type UseCase struct {
	store       Store
	rewrapper   Rewrapper
	page        int
	callTimeout time.Duration
}

// New собирает проход. page — строк за одно чтение; callTimeout — предел
// КАЖДОГО обращения к хранилищу: вызывающий (команда оператора) срока на весь
// проход не ставит — работа пропорциональна числу людей, — поэтому зависшая
// связь ограничивается здесь, на каждом вызове.
func New(store Store, rewrapper Rewrapper, page int, callTimeout time.Duration) (*UseCase, error) {
	switch {
	case store == nil:
		return nil, errors.New("second factor rewrap: store required")
	case rewrapper == nil:
		return nil, errors.New("second factor rewrap: rewrapper required — without it no stored secret can be opened")
	case page <= 0:
		return nil, fmt.Errorf("second factor rewrap: page size must be positive (got %d)", page)
	case callTimeout <= 0:
		return nil, fmt.Errorf("second factor rewrap: store call timeout must be positive (got %s)", callTimeout)
	}
	return &UseCase{store: store, rewrapper: rewrapper, page: page, callTimeout: callTimeout}, nil
}

// settled — клетка счёта, в которую легла строка.
type settled int

const (
	settledRewrapped settled = iota
	settledCurrent
	settledUnreadable
	settledVanished
	settledUnsettled
)

// Run проходит все строки `totp` страницами по возрастанию человека.
//
// Отказ хранилища останавливает проход и возвращается вместе со счётом
// сделанного: каждая замена до него зафиксирована, и повтор продолжит. Строки,
// заведённые после того, как курсор их миновал, пишет служба своим первым
// ключом; проход их не видит, и это не остаток — отсюда совет повторного
// прогона у команды.
func (u *UseCase) Run(ctx context.Context) (Report, error) {
	var (
		rep    Report
		cursor domain.UserID
	)
	for {
		page, err := u.readPage(ctx, cursor)
		if err != nil {
			return rep, fmt.Errorf("second factor rewrap: reading rows after %q: %w", cursor, err)
		}
		for _, row := range page {
			outcome, err := u.settle(ctx, row)
			if err != nil {
				return rep, fmt.Errorf("second factor rewrap: user %s: %w", row.UserID, err)
			}
			rep.Rows++
			switch outcome {
			case settledRewrapped:
				rep.Rewrapped++
			case settledCurrent:
				rep.Current++
			case settledUnreadable:
				rep.Unreadable++
			case settledVanished:
				rep.Vanished++
			case settledUnsettled:
				rep.Unsettled++
			}
		}
		if len(page) < u.page {
			return rep, nil
		}
		cursor = page[len(page)-1].UserID
	}
}

// settle доводит одну строку до клетки: переобёртка → CAS по прочитанному →
// при промахе перечитывание, не больше SwapAttempts замен.
func (u *UseCase) settle(ctx context.Context, row domain.LoginMethod) (settled, error) {
	for swaps := 0; ; swaps++ {
		next, alreadyFirst, err := u.rewrapper.Rewrap(row.Verifier)
		switch {
		case errors.Is(err, totpverify.ErrSecretUnreadable):
			return settledUnreadable, nil
		case err != nil:
			return 0, err
		case alreadyFirst:
			return settledCurrent, nil
		case swaps == SwapAttempts:
			return settledUnsettled, nil
		}
		swapped, err := u.swap(ctx, row, next)
		if err != nil {
			return 0, err
		}
		if swapped {
			return settledRewrapped, nil
		}
		// Материал уже другой: его зафиксировал конкурент. Судится ЕГО значение,
		// а не то, что проход держал.
		fresh, err := u.reread(ctx, row.UserID)
		if errors.Is(err, iamerr.ErrNotFound) {
			return settledVanished, nil
		}
		if err != nil {
			return 0, err
		}
		row = fresh
	}
}

func (u *UseCase) readPage(ctx context.Context, after domain.UserID) ([]domain.LoginMethod, error) {
	callCtx, cancel := context.WithTimeout(ctx, u.callTimeout)
	defer cancel()
	return u.store.TOTPSecretsAfter(callCtx, after, u.page)
}

func (u *UseCase) swap(ctx context.Context, row domain.LoginMethod, next domain.LoginVerifier) (bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, u.callTimeout)
	defer cancel()
	return u.store.SwapTOTPSecret(callCtx, row.UserID, row.Verifier, next)
}

func (u *UseCase) reread(ctx context.Context, user domain.UserID) (domain.LoginMethod, error) {
	callCtx, cancel := context.WithTimeout(ctx, u.callTimeout)
	defer cancel()
	return u.store.Get(callCtx, user, domain.LoginMethodTOTP)
}
