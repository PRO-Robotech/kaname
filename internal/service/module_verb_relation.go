// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// catalogFacts — снимок каталога модулей; nil, когда каталог не провязан.
func (s *AuthorizeService) catalogFacts() *catalog.Facts {
	if s.catalog == nil {
		return nil
	}
	return s.catalog.Facts()
}

// moduleVerbRelation — отношение действия `<модуль>.<ресурс>.<глагол>` по
// каталогу модуля: глагольное отношение `v_<глагол>` типа объекта. Им разрешается
// ВСЯКИЙ вопрос `Check` без явного отношения (kaname#994, kaname#995).
//
// # Почему каталог, а не ярус
//
// Ярус (`resolveActionToRelation`: `get` → `viewer`) и глагол — РАЗНЫЕ отношения,
// и ярус отвечал не о том, о чём спросили, в обе стороны:
//   - уже выданного: ярус системного класса у типов модулей не выводится вовсе,
//     и анонимная самопроверка отвечала «нет» при живом праве (kaname#994);
//   - шире выданного: ярус `viewer` объединяет `get` и `list`, и вошедший, которому
//     выдан только `get`, получал «да» на вопрос о `list` (kaname#995).
//
// Тот же глагол, взятый у типа, — ровно то отношение, которое край и прокси
// передают явно.
//
// # Когда ответа нет — пустая строка, и это отказ
//
// Пусто в четырёх случаях, и в каждом подстановки умолчанием нет:
//   - каталог не провязан;
//   - действие не названо тремя частями;
//   - ресурс действия в каталоге не соответствует типу объекта: глагол берётся
//     у ТИПА ОБЪЕКТА, и действие о другом ресурсе спросило бы не то, что назвало;
//   - тип объекта такого глагола в каталоге не объявляет (у `cluster` глаголов
//     нет вовсе).
//
// Каталог — живые строки (`catalog.Facts`), а не таблица, порождённая сборкой:
// тип, заведённый доставкой манифеста в работающем процессе, таблица сборки не
// знает (kacho#1816).
func moduleVerbRelation(facts *catalog.Facts, action, objectType string) string {
	if facts == nil {
		return ""
	}
	cut := strings.LastIndexByte(action, '.')
	if cut <= 0 || cut == len(action)-1 {
		return ""
	}
	dotted, verb := action[:cut], domain.NormalizeVerb(action[cut+1:])
	if !strings.Contains(dotted, ".") {
		return ""
	}
	if fgaType, ok := facts.FGAObjectType(dotted); !ok || fgaType != objectType {
		return ""
	}
	for _, declared := range facts.VerbsOfType(objectType) {
		if declared == verb {
			return authzmap.VerbRelationPrefix + verb
		}
	}
	return ""
}
