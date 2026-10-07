// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// event_audience.go — вопрос об аудитории версии события ресурса (приёмка
// NTF-3, kacho#2918, Р30 «Вопрос с оградой»; Р7 `ListEventAudience`,
// `Resolve{event}`): объект, поколение `g_E`, токен версии прав `R_E` и факты
// объекта на момент события.

import (
	"strconv"
	"strings"
)

// EventFacts — факты объекта на момент события (Р3), переданные вызывающим.
// У `UPDATED` Previous* несут факты поколения `g_E − 1`; аудитория — объединение.
type EventFacts struct {
	ProjectID           string
	AccountID           string
	Labels              map[string]string
	ParentChain         []string
	PreviousLabels      map[string]string
	PreviousParentChain []string
}

// Scope — области версии события, кроме самого объекта: проект, аккаунт и
// цепи предков обоих поколений, в форме `<тип модели>:<id>`, без повторов.
func (f EventFacts) Scope() []string {
	seen := map[string]bool{}
	var out []string
	add := func(ref string) {
		if ref == "" || seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, ref)
	}
	if f.ProjectID != "" {
		add("project:" + f.ProjectID)
	}
	if f.AccountID != "" {
		add("account:" + f.AccountID)
	}
	for _, c := range f.ParentChain {
		add(c)
	}
	for _, c := range f.PreviousParentChain {
		add(c)
	}
	return out
}

// MalformedChainEntry — первый элемент цепей предков не в форме `<тип>:<id>`
// (оба непусты); "" — все в форме.
func (f EventFacts) MalformedChainEntry() (field, entry string, malformed bool) {
	for _, set := range []struct {
		field string
		chain []string
	}{{"parent_chain", f.ParentChain}, {"previous_parent_chain", f.PreviousParentChain}} {
		for _, c := range set.chain {
			typ, id, ok := strings.Cut(c, ":")
			if !ok || typ == "" || id == "" {
				return set.field, c, true
			}
		}
	}
	return "", "", false
}

// EventAudienceQuestion — вопрос об аудитории версии события.
type EventAudienceQuestion struct {
	// ObjectType, ObjectID — объект в словаре МОДЕЛИ.
	ObjectType string
	ObjectID   string
	// Generation — поколение `g_E`.
	Generation int64
	// AuthzRev — токен версии прав `R_E` (текстовая форма снимка).
	AuthzRev string
	Facts    EventFacts
	// ViaSubscription — права уровня кластера учитываются (подписчик цели, Р11).
	ViaSubscription bool
	// Subject — непусто: вопрос о членстве одного субъекта `user:<id>`.
	Subject string
	// AfterSubject — страница начинается строго после этого `user:<id>`.
	AfterSubject string
	// Limit — наибольшее число субъектов страницы.
	Limit int
}

// EventAudienceVerdict — исход чтения, который не является страницей.
type EventAudienceVerdict int

const (
	// EventAudienceAnswered — аудитория прочитана.
	EventAudienceAnswered EventAudienceVerdict = iota
	// EventAudienceGenerationNotApplied — последнее применённое службой доступа
	// поколение объекта меньше `g_E` (головы нет либо она старше): ждём, а не
	// угадываем (Р30 «Барьер поколения»).
	EventAudienceGenerationNotApplied
	// EventAudienceTokenAhead — снимок `R_E` новее снимка вопроса: токен не
	// выдан этой службой (снимок вопроса обязан быть не старше `R_E`).
	EventAudienceTokenAhead
)

// EventAudiencePage — ответ чтения аудитории.
type EventAudiencePage struct {
	Verdict EventAudienceVerdict
	// Subjects — `user:<id>` по возрастанию; только при EventAudienceAnswered.
	Subjects []string
}

// ValidAuthzRevisionForm — s в канонической текстовой форме снимка транзакций
// (`pg_snapshot`): `xmin:xmax:xip,…`, где xmin ≤ xmax, а каждый xip — в
// [xmin, xmax) по возрастанию без повторов. Иная строка токеном версии прав,
// выданным `CurrentAuthzRevision`, быть не может.
func ValidAuthzRevisionForm(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return false
	}
	xmin, ok := parseXID(parts[0])
	if !ok {
		return false
	}
	xmax, ok := parseXID(parts[1])
	if !ok || xmin > xmax {
		return false
	}
	if parts[2] == "" {
		return true
	}
	prev := uint64(0)
	for i, x := range strings.Split(parts[2], ",") {
		xip, ok := parseXID(x)
		if !ok || xip < xmin || xip >= xmax || (i > 0 && xip <= prev) {
			return false
		}
		prev = xip
	}
	return true
}

// parseXID — десятичное беззнаковое без знака и ведущих нулей (кроме «0»).
func parseXID(s string) (uint64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}
