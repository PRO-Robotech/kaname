// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadfixture

// writes.go — фикстуры ключа `writes` манифеста registry (kaname#982, приёмка
// `kaname-derives-the-parent-of-a-registered-object.md`, документы P0 и W мира ДР).
//
// W — документ registry (прежней либо новой редакции) плюс одна запись `writes`
// на ресурсах `registries` и `repositories`: модуль сверх указателя пишет
// создателя (`owner`) человеком либо учёткой. Каждая правка — ТЕКСТОМ документа,
// и её разность с исходником сверяется здесь же (`requireDelta`): близнец обязан
// отличаться ровно объявленным фактом.

import (
	"bytes"
	"fmt"
	"strings"
)

// WritesKey — ключ манифеста, объявляющий отношения сверх указателя.
const WritesKey = "writes"

// Строки записи `writes` документа W — одинаковые у обоих ресурсов.
const (
	writesHead    = "    writes:"
	writesOwner   = "      - relation: owner"
	writesSubject = "        subjects: [user, service_account]"
)

// Якоря ресурсов: запись `writes` встаёт сразу за строкой типа объекта.
const (
	registriesAnchor   = "    objectType: registry_registry\n"
	repositoriesAnchor = "    objectType: registry_repository\n"
)

// ownerWrites — блок записи `writes` документа W.
func ownerWrites() string {
	return writesHead + "\n" + writesOwner + "\n" + writesSubject + "\n"
}

// WithWrites — документ W: на `registries` и `repositories` объявлено
// `writes: [{relation: owner, subjects: [user, service_account]}]`. Разность с
// исходником — шесть добавленных строк, по три на ресурс.
func WithWrites(doc []byte) ([]byte, error) {
	block := ownerWrites()
	out, err := replaceOnce(doc, registriesAnchor, registriesAnchor+block, "writes на registries")
	if err != nil {
		return nil, err
	}
	if out, err = replaceOnce(out, repositoriesAnchor, repositoriesAnchor+block, "writes на repositories"); err != nil {
		return nil, err
	}
	added := []string{writesHead, writesOwner, writesSubject, writesHead, writesOwner, writesSubject}
	return out, requireDelta(doc, out, nil, added)
}

// WithRegistriesWrites — близнец W с ДРУГОЙ записью `writes` у `registries`
// (ресурс 0): блок W заменён текстом block (строки с отступом ключа ресурса,
// каждая с переводом строки). Блок `repositories` не трогается. Разность — ровно
// замена блока; одна правка ключа W, как требует DP-20.
func WithRegistriesWrites(w []byte, block string) ([]byte, error) {
	if !strings.HasSuffix(block, "\n") {
		return nil, fmt.Errorf("publicreadfixture: блок writes обязан кончаться переводом строки")
	}
	old := registriesAnchor + ownerWrites()
	twin, err := replaceOnce(w, old, registriesAnchor+block, "заменить writes у registries")
	if err != nil {
		return nil, err
	}
	removed, added := Delta(w, twin)
	for _, l := range removed {
		if l != writesHead && l != writesOwner && l != writesSubject {
			return nil, fmt.Errorf("publicreadfixture: замена writes удалила чужую строку %q", l)
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return nil, fmt.Errorf("publicreadfixture: замена writes не изменила документ")
	}
	return twin, nil
}

// WithRegistriesRelation — документ с ещё одним авторским отношением у
// `registries` (ресурс 0): строка line встаёт первой в его раздел `relations`.
// Разность — одна добавленная строка.
func WithRegistriesRelation(doc []byte, line string) ([]byte, error) {
	start := bytes.Index(doc, []byte(registriesAnchor))
	end := bytes.Index(doc, []byte(repositoriesAnchor))
	if start < 0 || end < 0 || end < start {
		return nil, fmt.Errorf("publicreadfixture: ресурсы registries и repositories не найдены в порядке документа")
	}
	const head = "    relations:\n"
	rel := bytes.Index(doc[start:end], []byte(head))
	if rel < 0 {
		return nil, fmt.Errorf("publicreadfixture: у registries нет раздела relations")
	}
	at := start + rel + len(head)
	out := append(append(append([]byte(nil), doc[:at]...), []byte(line+"\n")...), doc[at:]...)
	return out, requireDelta(doc, out, nil, []string{line})
}
