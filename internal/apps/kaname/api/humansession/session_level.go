// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// session_level.go — уровень уверенности записи сессии ПОСЛЕ её выдачи
// (задачи PRO-Robotech/kaname#343, #208; приёмка Ф11
// `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`,
// Р1, Р2, Р5).
//
// # Писатель уровня внутри сессии — один
//
// Выданной сессии уровень меняет только предъявление внутри неё (Ф11 Р5), и
// у этой записи ОДИН вызывающий — presentInSession ниже; четыре глагола
// (повышение, подтверждение второго фактора, его снятие, новый набор запасных
// кодов) зовут его, а не оператор хранилища. Держит это гейт пакета
// `session_level_writer_test.go`: вызов `PresentInSession` в не-тестовом коде
// пакета — ровно один, и он здесь.
//
// # Кандидат — правилом, запись — оператором с условием на прежнее
//
// Правило выводит КАНДИДАТА из имён предъявленного в сессии. Имена не несут
// флагов утверждения ключа (запись хранит множество словами словаря — Ф3 Р1),
// поэтому у сессии, выданной ключом, кандидат беднее записанного: «3» ключа с
// проверкой пользователя правило по слову `webauthn` не восстановит. Отсюда два
// следствия, и оба держатся построением, а не проверкой у вызывающего:
//
//   - слово `webauthn` в предъявления правила НЕ переводится вовсе. Перевод
//     подставлял бы флаги, которых ключ не сообщал, — уровень, выведенный из
//     подстановки, ложен в обе стороны;
//   - запись уровня решает ОПЕРАТОР с условием на прежнее значение: кандидат
//     ниже записанного запись не понижает (понижение в пределах сессии
//     невыразимо — Ф11 Р2), выше — поднимает. Множество, не дающее уровня само
//     по себе (код второго фактора в сессии ключа), приносит кандидатом
//     записанный уровень.
//
// Копии уровня — ответ церемонии, событие повышения, ответ смены пароля —
// читают то, что ЛЕГЛО (`PresentedRecord`), а не кандидата.

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// presentInSession — предъявление способа m внутри сессии s одной записью:
// множество, уровень, новый носитель и момент. Ответ — то, что легло.
func presentInSession(ctx context.Context, w Writer, s domain.HumanSession, m assurance.Method,
	digest domain.BearerDigest, at time.Time,
) (PresentedRecord, error) {
	methods := withMethod(s.PresentedMethods, m)
	return w.PresentInSession(ctx, s.ID, methods, candidateLevel(s.AssuranceLevel, methods), digest, at)
}

// candidateLevel — кандидат правила от имён предъявленного; множество без
// уровня (код второго фактора в сессии ключа) — записанный уровень.
func candidateLevel(recorded string, methods []string) string {
	if l, ok := assurance.LevelOf(presentationsOf(methods)); ok {
		return l.String()
	}
	return recorded
}

// presentationsOf — слова записи → предъявления правила уровня. Слово
// `webauthn` не переводится (шапка): флагов утверждения у слова нет, и любой
// перевод был бы подстановкой. Слова вне словаря записи не бывает (CHECK
// строки).
func presentationsOf(methods []string) []assurance.Presentation {
	out := make([]assurance.Presentation, 0, len(methods))
	for _, m := range methods {
		switch m {
		case assurance.MethodPassword.String():
			out = append(out, assurance.PasswordPresented())
		case assurance.MethodTOTP.String():
			out = append(out, assurance.TOTPPresented())
		case assurance.MethodLookupSecret.String():
			out = append(out, assurance.LookupSecretPresented())
		case assurance.MethodRecoveryCode.String():
			out = append(out, assurance.RecoveryCodePresented())
		}
	}
	return out
}

// recordedLevel — уровень записи как значение оси: опознаётся среди уровней,
// которые правило вообще производит, а не преобразованием строки (второй
// производитель уровня — находка гейта `assurance_level_sole_writer`). Записи
// вне оси не бывает (CHECK строки); не опознан — ok=false.
func recordedLevel(recorded string) (assurance.Level, bool) {
	for _, l := range assurance.PresentableLevels(assurance.Methods()) {
		if l.String() == recorded {
			return l, true
		}
	}
	return "", false
}
