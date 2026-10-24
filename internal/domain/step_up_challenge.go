// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// step_up_challenge.go — ИСПЫТАНИЕ ПОВЫШЕНИЯ ключом доступа внутри живой
// сессии (задача PRO-Robotech/kaname#827; приёмка
// `docs/engineering/acceptance/step-up-with-any-enrolled-method.md`, Р2, Р3;
// замысел §2.1).
//
// # Почему это своя строка
//
// Ключ привязки у трёх видов испытаний разный: у церемоний Ф7 — человек, у
// входа ключом (Ф13) — контекст формы, у повышения — ЗАПИСЬ СЕССИИ. Три ключа —
// три таблицы, и испытание одного вида в чужой церемонии не находится по
// построению, а не совпадением значения фильтра у каждого читателя.
//
// # Привязка — запись сессии, не носитель
//
// Носитель перевыпускается каждым успешным предъявлением (Ф11 Р5): испытание,
// привязанное к дайджесту носителя, стало бы непредъявимым после соседней
// ветви. Человек выводится через сессию — второго источника принадлежности
// строка не несёт.
//
// # Моменты — часы службы, моментом-параметром
//
// Как у испытаний Ф7: срок — величина контракта Ф7 (`ChallengeTTL`), а ось
// времени приёмка строит управляемыми часами. Проверки «предъявлено не раньше
// выдачи» у схемы НЕТ намеренно: оба момента ставят часы службы, и реплика с
// отстающими часами получила бы отказ схемы на верном предъявлении.

import (
	"fmt"
	"time"
)

// StepUpChallenge — выдаваемое испытание повышения: значение, запись сессии,
// которой оно выдано, и его срок.
type StepUpChallenge struct {
	// Challenge — случайные байты; ключ строки. Длина — та же, что у прочих
	// испытаний ключа (`AccessKeyChallengeBytes`).
	Challenge []byte
	// SessionID — запись сессии, которой испытание выдано. Одно ЖИВОЕ
	// испытание на запись держит частичная уникальность схемы (ban #10).
	SessionID HumanSessionID
	// IssuedAt и ExpiresAt — момент выдачи и предел, часы службы.
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Validate — самопроверка выдаваемого испытания.
func (c StepUpChallenge) Validate() error {
	switch {
	case len(c.Challenge) != AccessKeyChallengeBytes:
		return fmt.Errorf("Illegal argument challenge: must be %d bytes", AccessKeyChallengeBytes)
	case c.SessionID == "":
		return fmt.Errorf("Illegal argument session_id: required")
	case c.IssuedAt.IsZero():
		return fmt.Errorf("Illegal argument issued_at: required")
	case !c.ExpiresAt.After(c.IssuedAt):
		return fmt.Errorf("Illegal argument expires_at: must be after issued_at")
	}
	return nil
}

// StepUpChallengeState — почему испытание повышения не сгорело: три причины
// наружу различимы (приёмка SUA Р3), и каждая — свой отказ состояния.
type StepUpChallengeState int

const (
	// StepUpChallengeNotIssued — строки этой пары (сессия, испытание) нет: не
	// выдавалось, выдано другой сессии либо сменено новой выдачей.
	StepUpChallengeNotIssued StepUpChallengeState = iota + 1
	// StepUpChallengePresented — строка есть и уже предъявлена.
	StepUpChallengePresented
	// StepUpChallengeExpired — строка есть, не предъявлена, предел вышел.
	StepUpChallengeExpired
)
