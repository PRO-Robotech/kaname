// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// sf_enroll_level.go — уровень сессии у заведения второго фактора (kaname#747,
// приёмка `level-two-is-enrolled-at-level-two.md`, Р1, Р4).
//
// # Свойство
//
// Способ, чьё предъявление даёт «2», не появляется у личности по решению
// сессии ниже «2». Код по времени даёт «2» лишь вместе с паролем, и у личности
// без ключа доступа его заводит свежая «1» (Ф12 Р8): два предъявления разных
// видов в одной сессии. У личности с ключом сессия «1» означает, что ключ в ней
// не предъявлен, — и код, заведённый ею, дал бы «2» тому, кто его не имел.
// Поэтому у такой личности `enroll` и `confirm` требуют сессии «2».
//
// # Формула
//
// Глагол проходит, если сессия «2» ЛИБО перечень ключей личности ПРОЧИТАН и
// пуст. Нечитаемый перечень — отказ хранилища, а не «ключа нет»: исход «ключа
// нет» при неизвестном перечне открыл бы ровно то, что условие запрещает.
// Чтение с семантикой «продолжить при сбое» (`enrollmentBeforeWrite`) здесь
// поэтому не годится — оно решено для сброса счёта, не для доступа.
//
// # Порядок
//
// Сессия → уровень → свежесть → состояние заведения: как у глаголов ключа, чей
// пол судят край и второй замок до службы. Отказ по уровню ничего не пишет —
// ожидающее заведение не трогается.

import (
	"context"
	"strconv"

	"github.com/PRO-Robotech/corelib/acrlevel"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// StepUpRequiredError — указание повысить уровень на полосе формы (Ф11 Р11):
// тот же текст и тот же вызов, что у публичного слушателя. Ступени — числа
// лестницы (`acrlevel.Rank`): в вызов не попадает ничего, кроме цифр.
type StepUpRequiredError struct {
	// Required — ступень, которой глагол требует.
	Required int
	// Presented — ступень сессии, с которой пришёл запрос.
	Presented int
}

// Error — текст указания, дословно один на все поверхности.
func (e *StepUpRequiredError) Error() string { return iamerr.TextStepUpRequired }

// Challenge — значение `WWW-Authenticate` указания (RFC 9470 §3).
func (e *StepUpRequiredError) Challenge() string {
	return iamerr.StepUpChallenge(strconv.Itoa(e.Required), strconv.Itoa(e.Presented))
}

// requireEnrollmentLevel — условие Р4: сессия не ниже уровня, который даёт
// ключ доступа, либо прочитанный пустой перечень ключей личности.
//
// Порог не выписан литералом: это ступень, которую ключ даёт одним
// предъявлением при ЛЮБОМ исходе флагов, — её отвечает правило
// (`assurance.GuaranteedLevels`), а сравнение ступеней — единая функция
// ранжирования платформы (`acrlevel.Rank`). Поднимет правило уровень ключа —
// поднимется и порог заведения кода у личности с ключом.
func requireEnrollmentLevel(ctx context.Context, d SecondFactorDeps, resolved Resolved) error {
	required := keyLevelRank()
	if required == 0 {
		// Правило не назвало уровня ключа — порога нет, и проход был бы
		// открытием без условия: глагол не выполняется (fail-closed).
		d.Logger.ErrorContext(ctx, "second factor enrollment: the rule names no level for an access key — the verb is not performed",
			"user_id", string(resolved.User.ID))
		return ErrStoreUnavailable
	}
	presented := acrlevel.Rank(resolved.Session.AssuranceLevel)
	if presented >= required {
		return nil
	}
	hasKey, err := d.Methods.AccessKeyEnrolled(ctx, resolved.User.ID)
	if err != nil {
		// Причина — в журнал, наружу — отказ хранилища фиксированным текстом.
		d.Logger.ErrorContext(ctx, "second factor enrollment: access key list unreadable — the verb is not performed",
			"user_id", string(resolved.User.ID), "err", err.Error())
		return ErrStoreUnavailable
	}
	if !hasKey {
		return nil
	}
	d.Observer.SecondFactorRefusalObserved(RefusalStepUpRequired)
	return &StepUpRequiredError{Required: required, Presented: presented}
}

// keyLevelRank — наивысшая ступень, которую ключ доступа гарантирует одним
// предъявлением (худший исход флагов); 0 — правило уровня не назвало.
func keyLevelRank() int {
	rank := 0
	for _, l := range assurance.GuaranteedLevels([]assurance.Method{assurance.MethodWebAuthn}) {
		if r := acrlevel.Rank(l.String()); r > rank {
			rank = r
		}
	}
	return rank
}
