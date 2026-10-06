// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package feedgen — шаблоны писем kaname и функции постановки, порождённые
// генератором извещений corelib (`notifygen`) над каталогом `notifications/`
// этого пакета (приёмка NTF-2, Р3; замысел issue-2917, З1, З19).
//
// Каталог несёт 24 шаблона таблицы Р3, все класса security, и перечень
// обязательного класса `notifications/required-security.yaml`. Файлы
// `notifications_<шаблон>.gen.go` и `notifications/<шаблон>/revision.yaml`
// порождает генератор версии пина corelib из go.mod; руками они не правятся —
// `go run github.com/PRO-Robotech/corelib/cmd/notifygen` из корня дерева.
//
// Пакет — владелец каталога шаблонов в дереве kaname ровно один: генератор
// пишет вывод рядом с каталогом `notifications/`, и функции постановки живут
// здесь.
package feedgen
