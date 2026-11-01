// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadfixture

// permanent_project.go — фикстура D-K приёмки
// `object-keeps-its-project-after-unregistration.md` (kaname#983) и её варианты.
//
// D-K — новая редакция манифеста registry (фикстура П6) с записью `writes: owner`
// (kaname#982: без неё кортеж `owner` регистрации — отказ политики записи) и
// ключом `permanentProject: true` на ресурсах `registries` и `repositories`.
// Документ ВЫЧИСЛЯЕТСЯ правкой фикстуры П6, а не лежит второй копией: две копии
// одного манифеста разошлись бы молча. Каждая правка сверяет свою разность с
// исходником (`requireDelta`).

import (
	"bytes"
	"fmt"
)

// PermanentProjectKey — ключ манифеста, объявляющий неизменность проекта типа.
const PermanentProjectKey = "permanentProject"

// permanentLine — строка ключа в единственной законной форме (ключ либо
// отсутствует, либо равен true).
const permanentLine = "    permanentProject: true"

// Строки начала записей ресурсов: ключ встаёт сразу за ними, чтобы не разрывать
// пару «тип объекта · writes», которую правят фикстуры `writes`.
const (
	registriesHead   = "  - name: registries\n"
	repositoriesHead = "  - name: repositories\n"
)

// PermanentProjectDocument — документ D-K: новая редакция registry, `writes:
// owner` и `permanentProject: true` на обоих ресурсах.
func PermanentProjectDocument() ([]byte, error) {
	edition, err := Read(NewEditionFile)
	if err != nil {
		return nil, err
	}
	withWrites, err := WithWrites(edition)
	if err != nil {
		return nil, err
	}
	return WithPermanentProject(withWrites)
}

// WithPermanentProject — `permanentProject: true` на `registries` и
// `repositories`. Разность — две добавленные строки.
func WithPermanentProject(doc []byte) ([]byte, error) {
	out, err := replaceOnce(doc, registriesHead, registriesHead+permanentLine+"\n", "ключ на registries")
	if err != nil {
		return nil, err
	}
	if out, err = replaceOnce(out, repositoriesHead, repositoriesHead+permanentLine+"\n", "ключ на repositories"); err != nil {
		return nil, err
	}
	return out, requireDelta(doc, out, nil, []string{permanentLine, permanentLine})
}

// WithoutPermanentProject — D-K без ключа на обоих ресурсах (снятие объявления,
// PB-23). Разность — две удалённые строки.
func WithoutPermanentProject(dk []byte) ([]byte, error) {
	out, err := replaceOnce(dk, registriesHead+permanentLine+"\n", registriesHead, "снять ключ с registries")
	if err != nil {
		return nil, err
	}
	if out, err = replaceOnce(out, repositoriesHead+permanentLine+"\n", repositoriesHead, "снять ключ с repositories"); err != nil {
		return nil, err
	}
	return out, requireDelta(dk, out, []string{permanentLine, permanentLine}, nil)
}

// WithRegistriesPermanentProject — D-K, у которого строка ключа `registries`
// (ресурс 0) заменена строкой line; пустая line — ключ снят только у
// `registries`. Разность — одна строка.
func WithRegistriesPermanentProject(dk []byte, line string) ([]byte, error) {
	repl := registriesHead
	var added []string
	if line != "" {
		repl += line + "\n"
		added = []string{line}
	}
	out, err := replaceOnce(dk, registriesHead+permanentLine+"\n", repl, "сменить ключ у registries")
	if err != nil {
		return nil, err
	}
	return out, requireDelta(dk, out, []string{permanentLine}, added)
}

// WithRegistriesParents — документ, у которого указатели `registries` (ресурс 0)
// заменены строкой line (`    parents: [account]`). Разность — одна строка.
func WithRegistriesParents(doc []byte, line string) ([]byte, error) {
	const old = "    parents: [project]\n"
	start := bytes.Index(doc, []byte(registriesHead))
	end := bytes.Index(doc, []byte(repositoriesHead))
	if start < 0 || end < start {
		return nil, fmt.Errorf("publicreadfixture: ресурсы registries и repositories не найдены в порядке документа")
	}
	rel := bytes.Index(doc[start:end], []byte(old))
	if rel < 0 {
		return nil, fmt.Errorf("publicreadfixture: у registries нет строки %q", old)
	}
	at := start + rel
	out := append(append(append([]byte(nil), doc[:at]...), []byte(line+"\n")...), doc[at+len(old):]...)
	return out, requireDelta(doc, out, []string{"    parents: [project]"}, []string{line})
}
