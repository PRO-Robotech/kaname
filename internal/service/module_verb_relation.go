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
// Пусто в пяти случаях, и в каждом подстановки умолчанием нет:
//   - каталог не провязан;
//   - действие не названо тремя частями;
//   - ресурс действия — ключ каталога, и этот ключ называет ДРУГОЙ тип, чем тип
//     объекта: глагол берётся у ТИПА ОБЪЕКТА, и действие о другом ресурсе
//     спросило бы не то, что назвало;
//   - ресурс действия — не ключ каталога, а модуль действия тип объекта не
//     объявляет;
//   - тип объекта такого глагола в каталоге не объявляет (у `cluster` глаголов
//     нет вовсе).
//
// # Два словаря имени ресурса: ключ каталога и токен права
//
// Действие приходит в словаре ТОКЕНА ПРАВА (`vpc.networks.get` — множественное
// число, путь коллекции), а каталог ключуется словарём ТИПА (`vpc.network`).
// У registry, storage и loadbalancer написания совпадают, у vpc, compute и iam
// нет, и сводить их правилом склонения нельзя: токены несут и змеиный регистр, и
// составные формы (`network_interfaces`, `used_addresses`), а расхождение
// намеренное (`authzmap/fga_types.go`). Поэтому ключ каталога судится строго —
// он обязан называть тип объекта, — а токен права, которого среди ключей нет,
// судится МОДУЛЕМ: тип объекта обязан принадлежать модулю действия. Действие
// чужого модуля ответа не получает; ресурс внутри своего модуля задаёт тип
// объекта, а не сегмент действия.
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
	dot := strings.IndexByte(dotted, '.')
	if dot <= 0 {
		return ""
	}
	if fgaType, isKey := facts.FGAObjectType(dotted); isKey {
		if fgaType != objectType {
			return ""
		}
	} else if !moduleDeclaresType(facts, dotted[:dot], objectType) {
		return ""
	}
	for _, declared := range facts.VerbsOfType(objectType) {
		if declared == verb {
			return authzmap.VerbRelationPrefix + verb
		}
	}
	return ""
}

// moduleDeclaresType — тип объекта объявлен ЖИВЫМ ресурсом модуля.
func moduleDeclaresType(facts *catalog.Facts, module, objectType string) bool {
	for _, r := range facts.Resources() {
		if r.Module == module && r.ObjectType == objectType {
			return true
		}
	}
	return false
}
