// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registration — регистрация человека нашей полосой и её три следствия
// одним исходом (фаза Ф4, задача PRO-Robotech/kacho#1270; приёмка
// `docs/engineering/acceptance/registration-and-its-three-consequences.md`).
//
// # Раскладка
//
// `lanes.go` — ЕДИНСТВЕННОЕ объявление полос регистрации (Р4); `iface.go` —
// порты; `register.go` — глагол регистрации: одна транзакция трёх следствий
// (Р1); `refusals.go` — отказы. Транспорт живёт в `internal/handler/loginlanehttp`
// — сюда он не течёт.
package registration

// Consequence — одно из следствий регистрации (Ф1-20). Словарь закрыт: полоса
// объявляет следствия из него, и глагол исполняет ровно объявленные.
type Consequence string

const (
	// ConsequenceMirror — зеркало пользователя заведено: строка человека, личный
	// аккаунт, проект по умолчанию, две самопривязки, намерения материализации.
	ConsequenceMirror Consequence = "mirror"
	// ConsequenceAddress — адрес числится неподтверждённым и подтверждение
	// затребовано: строка способа входа привязана к адресу, отметка подтверждения
	// пуста (Ф2 П1).
	ConsequenceAddress Consequence = "address"
	// ConsequenceSession — сессия выдана (Ф3 Р1, `humansession.IssueSession`).
	ConsequenceSession Consequence = "session"
)

// Consequences — закрытый перечень следствий в порядке исполнения: зеркало
// первым (адрес и сессия привязываются к его строке), сессия последней (Ф4-04:
// сшивка приложением зеленеет именно на ней).
func Consequences() []Consequence {
	return []Consequence{ConsequenceMirror, ConsequenceAddress, ConsequenceSession}
}

// Lane — полоса регистрации: чем человек представился впервые и какие
// следствия полоса производит.
//
// Полоса — сущность НАШЕГО кода, а не ключ отступа в чужом файле (Р4). Гейт
// дерева `internal/check` `TestRegistration_EveryLaneIssuesASession` читает ЭТО
// объявление и требует от каждой полосы выдачи сессии (Ф1-24); глагол
// регистрации исполняет ровно то, что полоса объявила, — поэтому гейт судит то
// же, что исполняется.
type Lane struct {
	// Name — имя полосы; значение метки счётчиков и имя в красном гейта.
	Name string
	// Consequences — следствия, которые полоса производит одним исходом.
	Consequences []Consequence
}

// Имена полос. Пароль — единственная полоса Ф4; вход ключом доступа — Ф13.
const (
	LanePassword = "password"
)

// Lanes — ЕДИНСТВЕННОЕ объявление полос регистрации.
//
// Второго места, перечисляющего полосы, в дереве нет и не заводится: гейт
// единственности (`ScanRegistrationLaneLiterals`) находит составной литерал
// полосы вне этого файла. Число полос ни одним сценарием не утверждается
// (приёмка §12 п. 3): требуется равенство «полос N · выдают сессию N».
var Lanes = []Lane{
	{Name: LanePassword, Consequences: []Consequence{ConsequenceMirror, ConsequenceAddress, ConsequenceSession}},
}

// LaneByName — полоса из объявления по имени; ok=false — такой полосы нет.
// Возвращается копия: объявление не правится через возвращённое значение.
func LaneByName(name string) (Lane, bool) {
	for _, l := range Lanes {
		if l.Name == name {
			out := l
			out.Consequences = append([]Consequence(nil), l.Consequences...)
			return out, true
		}
	}
	var none Lane
	return none, false
}

// Produces — объявляет ли полоса следствие c.
func (l Lane) Produces(c Consequence) bool {
	for _, x := range l.Consequences {
		if x == c {
			return true
		}
	}
	return false
}
