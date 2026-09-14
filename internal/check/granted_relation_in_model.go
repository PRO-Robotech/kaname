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

	"github.com/PRO-Robotech/kaname/internal/migrations"
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
		raw, rerr := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- имя из перечня собственного каталога
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
//
// revoked — отношения, чью выдачу снимает позднейшая миграция
// (`RevokedRelationsFromMigrations`). Передаётся ПАРАМЕТРОМ, а не берётся
// внутри: инъекция подаёт сюда синтетику, и судья, ходящий за ведомостью сам,
// на ней бы не работал.
func MissingGrantedRelations(grants []RelationGrant, model map[string]map[string]bool,
	revoked map[string]string) []string {
	var missing []string
	for _, g := range grants {
		if _, gone := revoked[g.Relation]; gone {
			continue
		}
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

// ── ОТЗЫВ ВЫДАЧИ ─────────────────────────────────────────────────────────────
//
// # Зачем ось вообще
//
// Разбор выше читает ТЕКСТ всех миграций и позднейший отзыв не вычитает.
// Применённую миграцию не правят (запрет #5), поэтому выдача, записанная в
// сведённом посеве, держала бы своё отношение в модели НАВСЕГДА: снять его
// стало бы невозможно by construction, а не трудно. Так и вышло с правом
// читать пределы (`kaname#59`): глаголы сняты, выдача отозвана, а объявление
// модели держала строка посева, которую править нельзя.
//
// # Почему это НЕ послабление
//
// Послабление прощает существующее нарушение. Здесь предмета нарушения нет:
// после отзыва в очереди не остаётся НИ ОДНОЙ строки, называющей отношение, —
// травиться нечему. Но это утверждение о РАНТАЙМЕ, и текстом оно не
// проверяется: здесь разбирается НАМЕРЕНИЕ миграции, а исход её наката держит
// интеграционная проба отзыва (`internal/migrations`,
// `TestLimitReaderGrant_IsRevokedAndLeavesATrace`, утверждение «очередь не
// несёт ни одной строки про это отношение»). Обе половины названы с обеих
// сторон, чтобы снятие одной не осталось незамеченным.
//
// # Граница разбора названа честно
//
// Отношение берётся ТОЛЬКО там, где его можно разрешить по тексту: литерал,
// список литералов и локальная константа, объявленная в той же накатной
// половине. Выражение, которое деревом не разрешается (значение из таблицы,
// аргумент функции), отзывом НЕ считается — и это верная сторона ошибки:
// нераспознанный отзыв оставляет находку, а не гасит её.

// reGrantsDeleted — удаление выдач, по которому миграция признаётся отзывающей.
// Написание терпимое: SQL нечувствителен к регистру и допускает произвольные
// пробелы, а предикат, узнающий одну запись из многих законных, МОЛЧИТ на
// остальных — и молчание читается как факт о дереве.
var reGrantsDeleted = regexp.MustCompile(`(?i)delete\s+from\s+kaname\s*\.\s*access_bindings\b`)

var (
	// Форма 1 — литерал прямо в сравнении.
	reRelLiteral = regexp.MustCompile(`(?i)granted_relation\s*=\s*'([a-z_]+)'`)
	// Форма 2 — список литералов (`IN (…)` и `= ANY (…)`).
	reRelList = regexp.MustCompile(`(?i)granted_relation\s*(?:=\s*any\s*)?(?:in\s*)?\(([^)]*)\)`)
	// Форма 3 — локальная переменная; её значение разрешается объявлением ниже.
	reRelIdent = regexp.MustCompile(`(?i)granted_relation\s*=\s*([a-z_][a-z0-9_]*)\b`)
	// Литерал внутри списка.
	reBareLiteral = regexp.MustCompile(`'([a-z_]+)'`)
)

// declaredConstant — значение локальной константы, объявленной литералом.
//
// Образец собирается ПО ИМЕНИ, а не общим: общий нашёл бы объявление соседней
// переменной и приписал отзыву чужое отношение.
func declaredConstant(up, ident string) (string, bool) {
	re, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(ident) +
		`\s+(?:constant\s+)?[a-z]+\s*:=\s*'([a-z_]+)'`)
	if err != nil {
		return "", false
	}
	if m := re.FindStringSubmatch(up); m != nil {
		return m[1], true
	}
	return "", false
}

// RevokedRelationsFromMigrations — отношения, чью ВЫДАЧУ снимает накатная
// половина какой-либо миграции корпуса: имя отношения → координата миграции.
//
// Второе возвращаемое — сколько файлов прочитано. Без него «отзывов ноль»
// неотличимо от «каталог не прочитан», и ось молча перестала бы работать.
func RevokedRelationsFromMigrations(root string) (map[string]string, int, error) {
	dir := filepath.Join(root, filepath.FromSlash(MigrationsDirRel))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("обход миграций: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	revoked := map[string]string{}
	read := 0
	for _, name := range names {
		raw, rerr := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- имя из перечня своего каталога
		if rerr != nil {
			return nil, 0, fmt.Errorf("чтение %s: %w", name, rerr)
		}
		read++
		// Комментарии забеливаются: разбор, судящий текст, не отличает оператор
		// от прозы, которая этот же оператор объясняет, — и гейт краснел бы на
		// собственной шапке.
		up := migrations.SQLBlankComments(migrations.MigrationUpSection(string(raw)))
		if !reGrantsDeleted.MatchString(up) {
			continue
		}
		rel := MigrationsDirRel + "/" + name

		for _, m := range reRelLiteral.FindAllStringSubmatch(up, -1) {
			revoked[m[1]] = rel
		}
		for _, m := range reRelList.FindAllStringSubmatch(up, -1) {
			for _, lit := range reBareLiteral.FindAllStringSubmatch(m[1], -1) {
				revoked[lit[1]] = rel
			}
		}
		for _, m := range reRelIdent.FindAllStringSubmatch(up, -1) {
			if v, ok := declaredConstant(up, m[1]); ok {
				revoked[v] = rel
			}
		}
	}
	return revoked, read, nil
}

// JoinRevoked — отозванные отношения, по порядку. Для переписи: «отзывов N»
// без перечня не отличает точный отзыв от бланкетного.
func JoinRevoked(m map[string]string) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
