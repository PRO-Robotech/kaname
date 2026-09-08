// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_liveness_levels_integration_test.go — ГЕЙТ: у каждого уровня каталога
// выбор ОБЪЯВЛЕН, а не совпал.
//
// Задача продукта #1878; заказан приёмкой
// `services/iam/docs/engineering/acceptance/module-withdrawal-is-described.md`
// §9.2, решение — `docs/engineering/architecture/catalog-liveness-key-per-level.md`.
//
// # Предмет
//
// Каталог трёхуровневый, и «мой родитель жив» на каждом переходе держится
// по-своему. До #1878 два перехода из трёх держали живость КЛЮЧОМ, а третий —
// КОММЕНТАРИЕМ, и различие никем не решалось: оно СОВПАЛО. Следующий, кто
// заведёт четвёртый уровень, не нашёл бы места, где сказано, какой выбор для
// него верен, — и совпадение повторилось бы.
//
// Гейт требует по каждому уровню ОДНОГО из двух: либо ключ на живую строку
// родителя есть, либо выбор в пользу первичного ключа ОБЪЯВЛЕН решением с
// координатой. Третьего — «так вышло» — не существует.
//
// # Почему гейт судит РАЗОБРАННУЮ схему, а не текст миграции
//
// Лёгкая форма («в тексте миграции есть объяснение») запрещена прямо: предикат,
// считающий собственное объяснение проверяемого, за эту линию давал ложное
// число. Здесь схему разбирает сам Postgres: уровни, имена ключей и их колонки
// читаются из `pg_constraint`, а не из `.sql`. Комментарий, объясняющий ключ,
// в `pg_constraint` не попадает by construction.
//
// # Перечень уровней ВЫВОДИТСЯ, а не выписан
//
// Выписанный перечень не заметил бы четвёртого уровня — то есть промолчал бы
// ровно там, ради чего заведён. Уровень — это пара «таблица каталога ссылается
// на таблицу каталога»; обе стороны берутся из схемы.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// livenessColumn — имя колонки живости в каталоге. Одно на все уровни: `live`
// есть производная `retired_at IS NULL`, и согласие двух держит проверка
// колонки, а не читатель.
const livenessColumn = "live"

// catalogFK — внешний ключ между двумя таблицами каталога, каким его видит
// Postgres: имя и КОЛОНКИ РОДИТЕЛЯ, на которые он ссылается.
type catalogFK struct {
	Name    string
	RefCols []string
}

// refersToLiveness — ссылается ли ключ на колонку живости родителя.
func (f catalogFK) refersToLiveness() bool {
	for _, c := range f.RefCols {
		if c == livenessColumn {
			return true
		}
	}
	return false
}

// catalogLevel — переход «дочерняя таблица каталога → родительская».
type catalogLevel struct {
	Child         string
	Parent        string
	ParentHasLive bool
	Keys          []catalogFK
}

func (l catalogLevel) name() string { return l.Child + " → " + l.Parent }

// declaredChoice — ОБЪЯВЛЕННЫЙ выбор в пользу первичного ключа.
//
// Запись живёт, пока у неё есть предмет: уровень существует И живость на нём
// действительно не держится ключом. Запись, которой нечего обосновывать, —
// находка, а не безобидный остаток: её унаследует следующая слепая зона.
type declaredChoice struct {
	Reason   string // почему на этом уровне ключ живости не нужен
	Decision string // координата решения: документ, где выбор записан
}

// declaredLivenessChoices — ведомость объявленных выборов.
//
// СЕГОДНЯ ОНА ПУСТА, и это НЕ поломка: пустая ведомость есть ровно та цель, ради
// которой ведомость заведена — живость каждого уровня держится ключом. Гейт на
// пустой ведомости ПРОХОДИТ и печатает перепись; падать на достижении
// собственной цели он не вправе, иначе подталкивал бы держать запись ради
// зелёного.
var declaredLivenessChoices = map[string]declaredChoice{}

// auditCatalogLevels — ЯДРО гейта, отделённое от базы НАМЕРЕННО.
//
// Инъекция обязана подать ему уровни, которых в дереве нет (в том числе пустой
// обход), и получить исход — а не читать схему живой базы, где такого входа не
// бывает by construction.
func auditCatalogLevels(levels []catalogLevel, declared map[string]declaredChoice) (census string, findings []string) {
	var keyed, byChoice, noLiveness int
	seenDeclared := map[string]bool{}

	sorted := append([]catalogLevel(nil), levels...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name() < sorted[j].name() })

	for _, l := range sorted {
		if !l.ParentHasLive {
			// У родителя нет живости — держать на этом уровне нечего, и
			// требовать ключа было бы находкой без предмета.
			noLiveness++
			continue
		}
		held := false
		for _, k := range l.Keys {
			if k.refersToLiveness() {
				held = true
			}
		}
		choice, declaredHere := declared[l.name()]
		switch {
		case held && declaredHere:
			seenDeclared[l.name()] = true
			findings = append(findings, "уровень "+l.name()+
				": живость держит КЛЮЧ, а в ведомости стоит объявленный выбор в пользу "+
				"первичного — записи больше нечего обосновывать, снимите её")
		case held:
			keyed++
		case declaredHere:
			seenDeclared[l.name()] = true
			byChoice++
			if strings.TrimSpace(choice.Reason) == "" || strings.TrimSpace(choice.Decision) == "" {
				findings = append(findings, "уровень "+l.name()+
					": выбор объявлен без причины либо без координаты решения — "+
					"объявление без предмета не отличается от совпадения")
			}
		default:
			names := make([]string, 0, len(l.Keys))
			for _, k := range l.Keys {
				names = append(names, k.Name+"("+strings.Join(k.RefCols, ", ")+")")
			}
			if len(names) == 0 {
				names = append(names, "ключей нет вовсе")
			}
			findings = append(findings, "уровень "+l.name()+
				": живость родителя не держит НИ ОДИН ключ, и выбор в пользу первичного "+
				"не объявлен — различие уровней СОВПАЛО, а не было решено. Ключи уровня: "+
				strings.Join(names, "; "))
		}
	}

	for name := range declared {
		if !seenDeclared[name] {
			findings = append(findings, "ведомость объявляет выбор для уровня "+name+
				", которого в схеме нет — записи нечего обосновывать")
		}
	}

	census = fmt.Sprintf("уровней каталога прочитано %d: держат живость ключом %d, "+
		"выбор объявлен %d, у родителя живости нет %d; записей ведомости %d",
		len(sorted), keyed, byChoice, noLiveness, len(declared))

	if len(sorted) == 0 {
		findings = append(findings, "обход пуст: уровней каталога не прочитано ни одного — "+
			"«ноль находок» здесь неотличимо от «ноль прочитанного»")
	}
	sort.Strings(findings)
	return census, findings
}

// readCatalogLevels — уровни каталога, КАК ИХ ВИДИТ POSTGRES.
//
// Читается `pg_constraint`, а не текст миграции: схему уже разобрал сервер, и
// комментарий, объясняющий ключ, в неё не попадает.
func readCatalogLevels(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []catalogLevel {
	t.Helper()

	rows, err := pool.Query(ctx, `
		SELECT child.relname,
		       parent.relname,
		       c.conname,
		       (SELECT array_agg(att.attname ORDER BY u.ord)
		          FROM unnest(c.confkey) WITH ORDINALITY AS u(attnum, ord)
		          JOIN pg_attribute att
		            ON att.attrelid = c.confrelid AND att.attnum = u.attnum),
		       EXISTS (SELECT 1 FROM pg_attribute pa
		                WHERE pa.attrelid = c.confrelid
		                  AND pa.attname = $1 AND pa.attnum > 0 AND NOT pa.attisdropped)
		  FROM pg_constraint c
		  JOIN pg_class child      ON child.oid  = c.conrelid
		  JOIN pg_class parent     ON parent.oid = c.confrelid
		  JOIN pg_namespace cns    ON cns.oid    = child.relnamespace
		  JOIN pg_namespace pns    ON pns.oid    = parent.relnamespace
		 WHERE c.contype = 'f'
		   AND cns.nspname = 'kaname' AND pns.nspname = 'kaname'
		   AND child.relname  LIKE 'catalog\_%'
		   AND parent.relname LIKE 'catalog\_%'`, livenessColumn)
	require.NoError(t, err)
	defer rows.Close()

	byLevel := map[string]*catalogLevel{}
	for rows.Next() {
		var child, parent, conname string
		var refCols []string
		var parentHasLive bool
		require.NoError(t, rows.Scan(&child, &parent, &conname, &refCols, &parentHasLive))
		key := child + " → " + parent
		if byLevel[key] == nil {
			byLevel[key] = &catalogLevel{Child: child, Parent: parent, ParentHasLive: parentHasLive}
		}
		byLevel[key].Keys = append(byLevel[key].Keys, catalogFK{Name: conname, RefCols: refCols})
	}
	require.NoError(t, rows.Err())

	out := make([]catalogLevel, 0, len(byLevel))
	for _, l := range byLevel {
		out = append(out, *l)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// САМ ГЕЙТ.

func TestEveryCatalogLevelDeclaresHowParentLivenessIsHeld(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	levels := readCatalogLevels(t, ctx, pool)
	census, findings := auditCatalogLevels(levels, declaredLivenessChoices)
	t.Log(census)
	for _, l := range levels {
		names := make([]string, 0, len(l.Keys))
		for _, k := range l.Keys {
			names = append(names, k.Name+"("+strings.Join(k.RefCols, ", ")+")")
		}
		sort.Strings(names)
		t.Logf("  уровень %s: %s", l.name(), strings.Join(names, "; "))
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ ЖИВОЙ СХЕМОЙ: снятый ключ уровня даёт находку С ИМЕНЕМ УРОВНЯ.
//
// Это доказательство способности гейта упасть на ТОМ ЖЕ входе, который он судит
// в дереве, — а не на синтетике. База у пробы своя, поэтому снятие ключа не
// достаётся никому другому.

func TestCatalogLevelGateFiresWhenALivenessKeyIsDropped(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	// Контроль: до снятия гейт молчит.
	_, findings := auditCatalogLevels(readCatalogLevels(t, ctx, pool), declaredLivenessChoices)
	require.Emptyf(t, findings, "на целой схеме гейт обязан молчать, иначе инъекция ничего не доказывает: %v", findings)

	for _, dropped := range []struct{ table, constraint, level string }{
		{"catalog_resource", "catalog_resource_module_live_fk", "catalog_resource → catalog_module"},
		{"catalog_verb", "catalog_verb_resource_live_fk", "catalog_verb → catalog_resource"},
	} {
		t.Run(dropped.constraint, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			_, err := pool.Exec(ctx,
				`ALTER TABLE kaname.`+dropped.table+` DROP CONSTRAINT `+dropped.constraint)
			require.NoError(t, err)

			census, findings := auditCatalogLevels(readCatalogLevels(t, ctx, pool), declaredLivenessChoices)
			t.Log(census)
			require.Lenf(t, findings, 1, "ожидалась ровно одна находка, получено: %v", findings)
			require.Contains(t, findings[0], dropped.level,
				"находка обязана называть УРОВЕНЬ: без имени её не отнести ни к одной паре таблиц")
			t.Logf("находка: %s", findings[0])
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ СИНТЕТИКОЙ: входы, которых в дереве нет by construction.
//
// Живая схема не может подать ни пустой обход, ни объявленный выбор, ни запись
// без предмета, — а именно на них гейт обязан вести себя названным образом.
// Проба идёт БЕЗ Postgres: ядро от базы отделено ради этого.

func TestCatalogLevelGateJudgesEachInputByItself(t *testing.T) {
	keyed := catalogLevel{Child: "catalog_verb", Parent: "catalog_resource", ParentHasLive: true,
		Keys: []catalogFK{
			{Name: "catalog_verb_resource_fk", RefCols: []string{"module", "resource"}},
			{Name: "catalog_verb_resource_live_fk", RefCols: []string{"module", "resource", "live"}},
		}}
	bare := catalogLevel{Child: "catalog_verb", Parent: "catalog_resource", ParentHasLive: true,
		Keys: []catalogFK{{Name: "catalog_verb_resource_fk", RefCols: []string{"module", "resource"}}}}
	noLive := catalogLevel{Child: "catalog_tier", Parent: "catalog_kind", ParentHasLive: false,
		Keys: []catalogFK{{Name: "catalog_tier_kind_fk", RefCols: []string{"kind"}}}}

	choice := declaredChoice{Reason: "родитель не снимается", Decision: "docs/…/decision.md"}

	for _, c := range []struct {
		name     string
		levels   []catalogLevel
		declared map[string]declaredChoice
		want     string // подстрока ожидаемой находки; пусто — гейт обязан молчать
	}{
		{name: "ключ живости есть — молчание", levels: []catalogLevel{keyed},
			declared: map[string]declaredChoice{}},
		{name: "ключа нет и выбор не объявлен — находка с именем уровня",
			levels: []catalogLevel{bare}, declared: map[string]declaredChoice{},
			want: "catalog_verb → catalog_resource: живость родителя не держит НИ ОДИН ключ"},
		{name: "ключа нет, выбор объявлен — молчание", levels: []catalogLevel{bare},
			declared: map[string]declaredChoice{"catalog_verb → catalog_resource": choice}},
		{name: "объявление без причины — находка", levels: []catalogLevel{bare},
			declared: map[string]declaredChoice{
				"catalog_verb → catalog_resource": {Decision: "docs/…/decision.md"}},
			want: "без причины либо без координаты решения"},
		{name: "объявление пережило свой предмет — находка", levels: []catalogLevel{keyed},
			declared: map[string]declaredChoice{"catalog_verb → catalog_resource": choice},
			want:     "больше нечего обосновывать"},
		{name: "объявление уровня, которого нет — находка", levels: []catalogLevel{keyed},
			declared: map[string]declaredChoice{"catalog_ghost → catalog_module": choice},
			want:     "которого в схеме нет"},
		{name: "у родителя нет живости — держать нечего, молчание",
			levels: []catalogLevel{noLive}, declared: map[string]declaredChoice{}},
		{name: "пустой обход — находка", levels: nil, declared: map[string]declaredChoice{},
			want: "обход пуст"},
	} {
		t.Run(c.name, func(t *testing.T) {
			census, findings := auditCatalogLevels(c.levels, c.declared)
			t.Log(census)
			if c.want == "" {
				require.Emptyf(t, findings, "гейт обязан молчать, получено: %v", findings)
				return
			}
			require.Lenf(t, findings, 1, "ожидалась ровно одна находка, получено: %v", findings)
			require.Contains(t, findings[0], c.want)
		})
	}
}
