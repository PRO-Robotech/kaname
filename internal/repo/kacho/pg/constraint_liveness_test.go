// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// constraint_liveness_test.go — гейт класса: ОТОБРАЖЕНИЕ ОТКАЗА НЕ ПЕРЕЖИВАЕТ
// СВОЙ ПРЕДМЕТ.
//
// ПРЕДМЕТ. `pgmaperr.go` переводит имя нарушенного ограничения в текст, который
// читает арендатор. Имя ограничения — факт СХЕМЫ, а не кода: его заводит
// миграция и снимает миграция. Когда ограничение снято, ветвь отображения
// остаётся — и остаётся молча: она не краснеет, потому что вход, на котором она
// срабатывает, перестал быть представимым (`testing.md` §«Гейт на класс», п.9 —
// негативное утверждение замолкает).
//
// Цена измерена, а не предположена. Ветвь `access_binding_conditions_condition_fk`
// пережила снятие своего предмета: миграция `0075_retire_tenant_condition_surface`
// сносит обе таблицы (`access_binding_conditions`, `conditions`) вместе с внешним
// ключом, заведённым `0048`, а отображение продолжало обещать арендатору два
// текста про ресурс `Condition` — компонент, снятый с продукта ЦЕЛИКОМ. Клиент
// шёл искать настройку того, чего в продукте нет.
//
// ЧТО ГЕЙТ СУДИТ И ЧЕГО НЕ СУДИТ (граница названа, чтобы «ноль находок» не
// читалось шире сделанного):
//
//   - судит: имена в ветвях `switch pgErr.ConstraintName` файла `pgmaperr.go`,
//     прочитанные РАЗБОРОМ (не подстрокой: те же имена стоят в объяснениях
//     рядом, и проверка по тексту краснела бы на собственном комментарии);
//   - судит: заведено ли имя хоть одной миграцией и не снято ли оно позже — по
//     имени, вместе со своей таблицей, или вместе со своим триггером;
//   - НЕ судит: верен ли текст по существу и полон ли перечень отображённых
//     ограничений. Ограничений в схеме десятки, отображена их часть — это
//     осознанно (неразобранное получает общий текст), и предметом гейта не
//     является.
//
// Способность падать и молчать доказана инъекцией — `TestConstraintLivenessGateInjection`.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const migrationsRelDir = "../../../migrations"

// schemaFacts — состояние схемы, выведенное последовательным применением
// Up-половин миграций. Down-половина НЕ читается намеренно: она описывает
// откат, и снос в ней означает обратное сносу в Up.
type schemaFacts struct {
	// constraintOwner — имя ограничения → таблица, на которой оно заведено
	// (пусто, если владельца установить нечем: триггер, RAISE ... CONSTRAINT).
	constraintOwner map[string]string
	// aliveConstraint — имя ограничения живо на конец применения.
	aliveConstraint map[string]bool
	// aliveTable — таблица жива на конец применения.
	aliveTable map[string]bool
}

var (
	reCreateTable   = regexp.MustCompile(`(?i)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z0-9_.]+)`)
	reDropTable     = regexp.MustCompile(`(?i)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([a-z0-9_.]+)`)
	reAlterTable    = regexp.MustCompile(`(?i)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?([a-z0-9_.]+)`)
	reAddConstraint = regexp.MustCompile(`(?i)\bADD\s+CONSTRAINT\s+([a-z0-9_]+)`)
	reDropConstrain = regexp.MustCompile(`(?i)\bDROP\s+CONSTRAINT\s+(?:IF\s+EXISTS\s+)?([a-z0-9_]+)`)
	reInlineConstr  = regexp.MustCompile(`(?i)^\s*CONSTRAINT\s+([a-z0-9_]+)\b`)
	reCreateTrigger = regexp.MustCompile(`(?i)\bCREATE\s+(?:CONSTRAINT\s+)?TRIGGER\s+([a-z0-9_]+)`)
	reDropTrigger   = regexp.MustCompile(`(?i)\bDROP\s+TRIGGER\s+(?:IF\s+EXISTS\s+)?([a-z0-9_]+)\s+ON\s+([a-z0-9_.]+)`)
	reRaiseConstr   = regexp.MustCompile(`(?i)\bCONSTRAINT\s*=\s*'([a-z0-9_]+)'`)
	reMigVersion    = regexp.MustCompile(`^([0-9]+)_`)
	// Уникальный индекс — тоже имя, которым сервер называет нарушенное
	// ограничение (`pgErr.ConstraintName` на 23505 несёт имя ИНДЕКСА). Без этой
	// полосы гейт объявлял бы находкой девять живых имён — то есть мерил бы
	// собственную слепоту, а не дерево.
	reCreateIndex = regexp.MustCompile(`(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([a-z0-9_]+)`)
	reIndexOn     = regexp.MustCompile(`(?i)\bON\s+([a-z0-9_.]+)`)
	reDropIndex   = regexp.MustCompile(`(?i)\bDROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?([a-z0-9_.]+)`)
	reRenameIndex = regexp.MustCompile(`(?i)\bALTER\s+INDEX\s+(?:IF\s+EXISTS\s+)?([a-z0-9_.]+)\s+RENAME\s+TO\s+([a-z0-9_]+)`)
)

// bareTable снимает имя схемы: миграции пишут и `kacho_iam.t`, и `t`.
func bareTable(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// upHalf возвращает Up-половину миграции без SQL-комментариев. Комментарии
// снимаются потому, что имена ограничений обильно стоят в объяснениях (в том
// числе имена СНЯТЫХ), и без этого гейт считал бы прозу фактом схемы.
func upHalf(src string) string {
	if i := strings.Index(src, "-- +goose Down"); i >= 0 {
		src = src[:i]
	}
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// readSchemaFacts применяет Up-половины всех миграций в порядке версии.
func readSchemaFacts(t *testing.T) (schemaFacts, int) {
	t.Helper()
	entries, err := os.ReadDir(migrationsRelDir)
	if err != nil {
		t.Fatalf("каталог миграций не прочитан: %v", err)
	}
	type mig struct {
		version int64
		path    string
	}
	var migs []mig
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := reMigVersion.FindStringSubmatch(e.Name())
		if m == nil {
			t.Fatalf("имя миграции %q не несёт версии — порядок применения не выводится", e.Name())
		}
		v, cerr := strconv.ParseInt(m[1], 10, 64)
		if cerr != nil {
			t.Fatalf("версия миграции %q не разобрана: %v", e.Name(), cerr)
		}
		migs = append(migs, mig{version: v, path: filepath.Join(migrationsRelDir, e.Name())})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].version < migs[j].version })

	f := schemaFacts{
		constraintOwner: map[string]string{},
		aliveConstraint: map[string]bool{},
		aliveTable:      map[string]bool{},
	}
	for _, m := range migs {
		raw, rerr := os.ReadFile(m.path)
		if rerr != nil {
			t.Fatalf("миграция %s не прочитана: %v", m.path, rerr)
		}
		applyUp(&f, upHalf(string(raw)))
	}
	return f, len(migs)
}

func applyUp(f *schemaFacts, up string) {
	// Текущая таблица оператора: CREATE TABLE / ALTER TABLE задают её, и
	// встреченное следом имя ограничения принадлежит ей.
	current := ""
	pendingIndex := "" // имя индекса, чья таблица придёт следующей строкой `ON …`
	for _, line := range strings.Split(up, "\n") {
		if m := reRenameIndex.FindStringSubmatch(line); m != nil {
			old, neu := bareTable(m[1]), strings.ToLower(m[2])
			f.aliveConstraint[neu] = true
			if owner, ok := f.constraintOwner[old]; ok {
				f.constraintOwner[neu] = owner
			}
			f.aliveConstraint[old] = false
			delete(f.constraintOwner, old)
			continue
		}
		if m := reDropIndex.FindStringSubmatch(line); m != nil {
			f.aliveConstraint[bareTable(m[1])] = false
		}
		if m := reCreateIndex.FindStringSubmatch(line); m != nil {
			name := strings.ToLower(m[1])
			f.aliveConstraint[name] = true
			pendingIndex = name
			if on := reIndexOn.FindStringSubmatch(line); on != nil {
				f.constraintOwner[name] = bareTable(on[1])
				pendingIndex = ""
			}
			continue
		}
		if pendingIndex != "" {
			if on := reIndexOn.FindStringSubmatch(line); on != nil {
				f.constraintOwner[pendingIndex] = bareTable(on[1])
				pendingIndex = ""
			}
		}
		if m := reCreateTable.FindStringSubmatch(line); m != nil {
			current = bareTable(m[1])
			f.aliveTable[current] = true
		}
		if m := reAlterTable.FindStringSubmatch(line); m != nil {
			current = bareTable(m[1])
		}
		if m := reDropTable.FindStringSubmatch(line); m != nil {
			dropped := bareTable(m[1])
			f.aliveTable[dropped] = false
			// Снос таблицы уносит её ограничения — это и есть тот способ, каким
			// отображение теряет предмет, не будучи упомянутым ни одной строкой.
			for name, owner := range f.constraintOwner {
				if owner == dropped {
					f.aliveConstraint[name] = false
				}
			}
			current = ""
		}
		if m := reAddConstraint.FindStringSubmatch(line); m != nil {
			f.aliveConstraint[strings.ToLower(m[1])] = true
			if current != "" {
				f.constraintOwner[strings.ToLower(m[1])] = current
			}
		}
		if m := reInlineConstr.FindStringSubmatch(line); m != nil {
			f.aliveConstraint[strings.ToLower(m[1])] = true
			if current != "" {
				f.constraintOwner[strings.ToLower(m[1])] = current
			}
		}
		if m := reDropConstrain.FindStringSubmatch(line); m != nil {
			f.aliveConstraint[strings.ToLower(m[1])] = false
		}
		if m := reCreateTrigger.FindStringSubmatch(line); m != nil {
			f.aliveConstraint[strings.ToLower(m[1])] = true
			if current != "" {
				f.constraintOwner[strings.ToLower(m[1])] = current
			}
		}
		if m := reRaiseConstr.FindStringSubmatch(line); m != nil {
			f.aliveConstraint[strings.ToLower(m[1])] = true
		}
		if m := reDropTrigger.FindStringSubmatch(line); m != nil {
			// Триггер сносится, но имя может быть тут же пересоздано ниже —
			// порядок строк и решает, поэтому просто снимаем.
			f.aliveConstraint[strings.ToLower(m[1])] = false
		}
	}
}

// mappedConstraintNames — имена, по которым `pgmaperr.go` выбирает текст
// отказа. Читаются РАЗБОРОМ: берутся строковые литералы ветвей `case` тех
// `switch`, чьё подлежащее — `pgErr.ConstraintName`.
func mappedConstraintNames(t *testing.T, file string) map[string]token.Position {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("%s не разобран: %v", file, err)
	}
	out := map[string]token.Position{}
	ast.Inspect(f, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok || sw.Tag == nil {
			return true
		}
		sel, ok := sw.Tag.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "ConstraintName" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, e := range cc.List {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, uerr := strconv.Unquote(lit.Value)
				if uerr != nil || v == "" {
					continue
				}
				out[strings.ToLower(v)] = fset.Position(lit.Pos())
			}
		}
		return true
	})
	return out
}

func TestRefusalTextNeverNamesARetiredConstraint(t *testing.T) {
	facts, migCount := readSchemaFacts(t)
	mapped := mappedConstraintNames(t, "pgmaperr.go")

	// Предпосылка гейта: обход обязан быть непустым в обе стороны, иначе «ноль
	// находок» неотличимо от «ноль прочитанного».
	if migCount == 0 {
		t.Fatal("миграций прочитано 0 — вердикт беспредметен")
	}
	if len(mapped) == 0 {
		t.Fatal("ветвей отображения ограничений прочитано 0 — разбор разошёлся с файлом")
	}
	live := 0
	for _, ok := range facts.aliveConstraint {
		if ok {
			live++
		}
	}
	if live == 0 {
		t.Fatal("живых ограничений в схеме 0 — разбор миграций разошёлся с корпусом")
	}

	dead := deadMappedConstraints(facts, mapped)

	t.Logf("перепись: миграций %d · живых ограничений %d · отображено ветвями %d · потеряли предмет %d",
		migCount, live, len(mapped), len(dead))

	if len(dead) > 0 {
		t.Fatalf("отображение отказа пережило свой предмет — %d ветвей называют ограничение, которого в схеме нет:\n  %s\n"+
			"Исходов два: снять ветвь вместе с предметом либо вернуть предмет в схему. Оставить как есть — нельзя: "+
			"ветвь не покраснеет никогда, а текст, который она обещает, называет арендатору снятый компонент.",
			len(dead), strings.Join(dead, "\n  "))
	}
}

// deadMappedConstraints — ЧИСТЫЙ предикат гейта: какие из отображённых имён
// потеряли предмет. Выделен затем, чтобы способность гейта падать и молчать
// доказывалась синтетическим входом, а не наличием дефекта в дереве: проба,
// опирающаяся на живую находку, исчезает вместе с нею — ровно тогда, когда
// находка правильно закрыта.
func deadMappedConstraints(facts schemaFacts, mapped map[string]token.Position) []string {
	var dead []string
	for name, pos := range mapped {
		known, seen := facts.aliveConstraint[name]
		switch {
		case !seen:
			dead = append(dead, name+" — ни одна миграция его не заводит ("+pos.String()+")")
		case !known:
			dead = append(dead, name+" — снято миграцией ("+pos.String()+")")
		}
	}
	sort.Strings(dead)
	return dead
}
