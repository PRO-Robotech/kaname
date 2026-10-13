// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// email_change_level.go — уровень сессии у глаголов смены адреса (приёмка
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`,
// редакция 4, Р2; задача PRO-Robotech/kaname#770).
//
// # Свойство
//
// Правка канала восстановления не ниже того, что личность сама завела: у
// человека с заведённым способом, дающим «2» (код по времени, ключ доступа),
// и запрос смены, и предъявление кода требуют сессии не ниже «2». Отношение то
// же, что у заведения второго фактора (`sf_enroll_level.go`, kaname#747 Р1).
//
// # Формула
//
// Глагол проходит, если уровень сессии не ниже уровня, который заведённое у
// личности гарантирует по правилу уровня (`assurance.GuaranteedLevels`, худший
// исход флагов ключа), — и заведённое ПРОЧИТАНО. Нечитаемое заведённое — отказ
// хранилища, а не «ничего не заведено»: такой исход открыл бы ровно то, что
// условие запрещает. Порог не выписан литералом: его отвечает правило, а
// сравнение ступеней — единая функция ранжирования платформы (`acrlevel.Rank`).
//
// Сессия, чей уровень уже не ниже того, что может потребовать ЛЮБОЕ
// заведённое, заведённого не читает: исход от прочитанного не зависит.
//
// # Порядок
//
// Сессия → положение подтверждения → уровень → свежесть (только запрос) → поля
// тела. Уровень раньше свежести: несвежая «1» человека с кодом получает
// указание повысить уровень, а повышение кодом снимает оба недостатка одним
// предъявлением. Отказ по уровню ничего не пишет: транзакция не открыта, темп,
// окно адресата и попытки кода не расходуются.

import (
	"context"

	"github.com/PRO-Robotech/corelib/acrlevel"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// EnrolledMethodsReader — чтение заведённого у личности вне транзакции записи:
// строки способов входа и наличие ключа доступа. Удовлетворяет
// `loginmethod.Store`.
type EnrolledMethodsReader interface {
	// Get — строка способа данного вида; NOT_FOUND — способа нет.
	Get(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error)
	// AccessKeyEnrolled — есть ли у личности хоть одна строка ключа доступа.
	AccessKeyEnrolled(ctx context.Context, userID domain.UserID) (bool, error)
}

// requireEmailChangeLevel — условие уровня Р2 у обоих глаголов смены.
func requireEmailChangeLevel(ctx context.Context, d EmailChangeDeps, resolved Resolved) error {
	ceiling := guaranteedRank(assurance.Methods())
	if ceiling == 0 {
		// Правило не назвало уровня ни одному способу — сравнение было бы
		// проходом без условия: глагол не выполняется (fail-closed).
		d.Observer.EmailChangeObserved(EmailChangeStoreFailed)
		d.Logger.ErrorContext(ctx, "email change: the rule names no level for any login method — the verb is not performed",
			"user_id", string(resolved.User.ID))
		return ErrStoreUnavailable
	}
	presented := acrlevel.Rank(resolved.Session.AssuranceLevel)
	if presented >= ceiling {
		return nil
	}
	enrolled, err := enrolledForCompletion(ctx, d.Methods.Get, d.Methods.AccessKeyEnrolled, resolved.User.ID)
	if err != nil {
		// Причина — в журнал, наружу — отказ хранилища фиксированным текстом.
		d.Observer.EmailChangeObserved(EmailChangeStoreFailed)
		d.Logger.ErrorContext(ctx, "email change: enrolled login methods unreadable — the verb is not performed",
			"user_id", string(resolved.User.ID), "err", err.Error())
		return ErrStoreUnavailable
	}
	required := guaranteedRank(enrolled)
	if presented >= required {
		return nil
	}
	d.Observer.EmailChangeObserved(EmailChangeStepUpRequired)
	return &StepUpRequiredError{Required: required, Presented: presented}
}

// guaranteedRank — наивысшая ступень, которую множество способов гарантирует
// по правилу уровня; 0 — правило не назвало ни одной.
func guaranteedRank(methods []assurance.Method) int {
	rank := 0
	for _, l := range assurance.GuaranteedLevels(methods) {
		if r := acrlevel.Rank(l.String()); r > rank {
			rank = r
		}
	}
	return rank
}
