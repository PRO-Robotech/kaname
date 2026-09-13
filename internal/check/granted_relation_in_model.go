// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// granted_relation_in_model.go — разбор: отношение, которое ВЫДАЁТ миграция,
// обязано СУЩЕСТВОВАТЬ в модели, которую применяет решение о доступе.
//
// # Предмет
//
// Выдача права живёт в двух артефактах, и они доезжают до решения РАЗНЫМИ
// путями: отношение объявляет модель прав, а саму выдачу пишет миграция —
// строкой в очередь. Если миграция называет отношение, которого в применяемой
// модели нет, запись отвергается со значением «такого отношения нет», дренаж
// верно считает такой отказ ПОСТОЯННЫМ, и строка травится: счётчик попыток
// выставляется в потолок, и больше её не возьмут никогда.
//
// # Что это стоит
//
// У этой очереди НЕТ переезда отравленных строк обратно в работу: разбор
// партиций идёт по идентификатору ресурса, которого у неё нет by construction
// (она партиционирована по ключу кортежа). Следствие названо честно: отравленная
// строка не «подождёт», а ЛЕЖИТ ДО ВМЕШАТЕЛЬСТВА ОПЕРАТОРА. Право, которое она
// несла, не выдаётся.
//
// # Почему разбор дерева, а не внимание
//
// Расхождение не видно НИ ОДНОЙ из двух сторон. Миграция — обычный SQL: она
// применяется без ошибки, потому что про модель ничего не знает. Модель —
// обычный DSL: он проходит проверку, потому что про миграции ничего не знает.
// Сборка цела, пробы обеих сторон зелёные, а право не выдано. Единственное
// место, где два факта встречаются, — дерево.
//
// # Чего этот разбор НЕ ловит (названо, чтобы на него не сослались шире предмета)
//
// Он про СОСТАВ, а не про ПОРЯДОК. Если отношение в модели есть, но новая её
// редакция ещё не применена, а дренаж уже взял строку, — пара сойдётся, разбор
// промолчит, а строка отравится ровно так же. Порядок двух путей доставки
// деревом не проверяется.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с `PRO-Robotech/kacho:internal/repohygiene/grantedrelationinmodel_test.go`
// (снято вынесением службы — `kacho#2598`; предмет жив здесь, задача #17).
// Изменилось: координаты обоих операндов (приставки `services/iam/` в
// самостоятельном клоне нет), разбор вынесен из пробы в пакет `check`.
// Осталось дословно: имя гейта, ОБЕ формы записи кортежа и то, что применяемая
// модель читается ВСТРОЕННАЯ, а не каноническая.
//
// Близнеца в платформе нет: семейство снято там вместе со службой (ban #20).
package check

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	// MigrationsDirRel — дом миграций службы.
	MigrationsDirRel = "internal/migrations"
	// AppliedModelRelPath — модель, которую ПРИМЕНЯЕТ решение о доступе.
	//
	// Каноническая копия (`proto/kaname/cloud/iam/v1/fga_model.fga`) сюда
	// намеренно НЕ подставляется: две копии держит байт-идентичными своя цель, а
	// разбор обязан читать ту, которая ИСПОЛНЯЕТСЯ.
	AppliedModelRelPath = "internal/authzmodel/fga_model.fga"
	// outboxTableMark — имя очереди, по которому миграция признаётся пишущей
	// выдачу. Смена имени обязана быть видна предпосылкой «выдач ноль», а не
	// молчанием.
	outboxTableMark = "fga_outbox"
)

// RelationGrant — одна выдача: какое отношение на каком типе объекта пишет
// миграция.
type RelationGrant struct {
	ObjectType string
	Relation   string
	Where      string // путь относительно корня — координата находки
}

var (
	// Блок кортежа, ФОРМА ПЕРВАЯ — конструктор. Блок ограничивается СЛЕДУЮЩИМ
	// таким же вызовом, поэтому пары не перетекают между соседними кортежами
	// одной вставки.
	tupleBlockRe = regexp.MustCompile(`jsonb_build_object`)
	grantRelRe   = regexp.MustCompile(`'relation'\s*,\s*'([a-z_]+)'`)
	grantObjRe   = regexp.MustCompile(`'object'\s*,\s*'([a-z_]+):`)

	// Блок кортежа, ФОРМА ВТОРАЯ — готовый объект JSON.
	//
	// Её производит сведённая первичная миграция: снимок печатает ЗНАЧЕНИЕ
	// столбца, а не выражение, которым его когда-то собрали. Конструктора в
	// таком файле может не быть ни одного, поэтому распознаватель, знающий
	// только первую форму, не находит НИЧЕГО — и это молчание, а не находка.
	// Ловит это предпосылка «выдач ноль».
	tupleJSONRe    = regexp.MustCompile(`\{[^{}]*"relation"[^{}]*\}`)
	grantRelJSONRe = regexp.MustCompile(`"relation"\s*:\s*"([a-z_]+)"`)
	grantObjJSONRe = regexp.MustCompile(`"object"\s*:\s*"([a-z_]+):`)
)

// GrantsFromMigrations — пары «тип объекта + отношение» из миграций, пишущих в
// очередь. Возвращает ещё и объём осмотренного: без него «ноль находок»
// неотличимо от «ноль прочитанного».
func GrantsFromMigrations(root string) (grants []RelationGrant, migrationsRead, blocksSeen int, err error) {
	dir := filepath.Join(root, filepath.FromSlash(MigrationsDirRel))
	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		return nil, 0, 0, fmt.Errorf("обход миграций: %w", rerr)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		raw, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			return nil, 0, 0, fmt.Errorf("чтение %s: %w", name, rerr)
		}
		body := string(raw)
		if !strings.Contains(body, outboxTableMark) {
			continue
		}
		migrationsRead++
		rel := MigrationsDirRel + "/" + name

		idx := tupleBlockRe.FindAllStringIndex(body, -1)
		for i, loc := range idx {
			end := len(body)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			chunk := body[loc[0]:end]
			rm := grantRelRe.FindStringSubmatch(chunk)
			if rm == nil {
				continue
			}
			blocksSeen++
			om := grantObjRe.FindStringSubmatch(chunk)
			if om == nil {
				// Тип объекта собран выражением, а не литералом — деревом он не
				// разрешается. Такой блок пропускается ОСОЗНАННО и виден в
				// переписи как разница между блоками и парами.
				continue
			}
			grants = append(grants, RelationGrant{ObjectType: om[1], Relation: rm[1], Where: rel})
		}

		// Вторая форма обходится ОТДЕЛЬНО, а не общим образцом: у форм разные
		// разделители блока, и один образец на обе дал бы блок, перетекающий за
		// границу кортежа.
		for _, chunk := range tupleJSONRe.FindAllString(body, -1) {
			rm := grantRelJSONRe.FindStringSubmatch(chunk)
			if rm == nil {
				continue
			}
			blocksSeen++
			om := grantObjJSONRe.FindStringSubmatch(chunk)
			if om == nil {
				continue
			}
			grants = append(grants, RelationGrant{ObjectType: om[1], Relation: rm[1], Where: rel})
		}
	}
	return grants, migrationsRead, blocksSeen, nil
}

var (
	modelTypeRe   = regexp.MustCompile(`^\s*type\s+([a-z_]+)\s*$`)
	modelDefineRe = regexp.MustCompile(`^\s*define\s+([a-z_]+)\s*:`)
)

// RelationsByType — разбор DSL модели: тип → множество объявленных отношений.
//
// Предикаты построчные и СТРОГИЕ: объявление типа занимает строку целиком, а
// объявление отношения начинается с ключевого слова. Готовая форма модели в
// JSON под эти строки не подпадает ни одной строкой.
func RelationsByType(text string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	cur := ""
	for _, line := range strings.Split(text, "\n") {
		if m := modelTypeRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
			if _, ok := out[cur]; !ok {
				out[cur] = map[string]bool{}
			}
			continue
		}
		if m := modelDefineRe.FindStringSubmatch(line); m != nil && cur != "" {
			out[cur][m[1]] = true
		}
	}
	return out
}

// MissingGrantedRelations — выдачи, у которых в модели нет типа либо отношения.
func MissingGrantedRelations(grants []RelationGrant, model map[string]map[string]bool) []string {
	var missing []string
	for _, g := range grants {
		rels, typeKnown := model[g.ObjectType]
		switch {
		case !typeKnown:
			missing = append(missing, fmt.Sprintf(
				"%s: выдаёт %s#%s — в применяемой модели НЕТ ТИПА %q",
				g.Where, g.ObjectType, g.Relation, g.ObjectType))
		case !rels[g.Relation]:
			missing = append(missing, fmt.Sprintf(
				"%s: выдаёт %s#%s — тип есть, ОТНОШЕНИЯ %q у него нет (объявлены: %s)",
				g.Where, g.ObjectType, g.Relation, g.Relation, JoinRelationSet(rels)))
		}
	}
	sort.Strings(missing)
	return missing
}

// CountRelations — сколько отношений объявлено всего.
func CountRelations(m map[string]map[string]bool) int {
	n := 0
	for _, rels := range m {
		n += len(rels)
	}
	return n
}

// JoinRelationSet — отношения одного типа, по порядку.
func JoinRelationSet(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// JoinGrants — различные пары «тип#отношение», по порядку.
func JoinGrants(g []RelationGrant) string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range g {
		k := x.ObjectType + "#" + x.Relation
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
