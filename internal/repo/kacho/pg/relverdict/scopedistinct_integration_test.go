// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// scopedistinct_integration_test.go — #811: ПРЕДОК, ДОСТИГНУТЫЙ ДВУМЯ ПУТЯМИ,
// ЧИТАЕТСЯ ОДИН РАЗ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Обход цепи областей несёт в кортеже ГЛУБИНУ, поэтому `UNION` рекурсивной
// ветви не схлопывает одного и того же предка, достигнутого разными путями:
// кортежи `(account, 1)` и `(account, 2)` различны, и оба остаются.
//
// Дубль возникает на цепи, которую пишет ПРОИЗВОДИТЕЛЬ (`ownerregister.ParentChain`)
// для compute и nlb — двумя звеньями сразу:
//
//	объект → проект   (звено 1)      объект → аккаунт (звено 2)
//
// Обход присваивает глубину по ШАГУ, а не по звену: аккаунт достигается прямым
// звеном на глубине 1 и через проект — на глубине 2. Кластер, стоящий над
// аккаунтом, наследует обе — 2 и 3.
//
// Каждая строка обхода умножает ОБА арма запроса: ветвь выдач соединяется с ней
// `CROSS JOIN`, ветвь фактов — по паре колонок. `DISTINCT` прячет дублирование
// в ОТВЕТЕ, но не в стоимости, и на ОТКАЗНОМ вопросе (где короткого замыкания
// `LIMIT 1` не происходит) цена платится целиком.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО МЕРИТСЯ И ПОЧЕМУ ИМЕННО ЭТО
//
// Несущая величина — СТРОКИ набора областей, а не миллисекунды: строка не
// зависит от машины, соседней нагрузки и кэша, а на хеш-соединении экономия
// вообще не видна в чтениях (она остаётся в пробах хеша) — то есть замер
// временем сказал бы «ничего не изменилось» на верной правке.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБА НЕ НЕСЁТ СВОЕЙ КОПИИ ОБХОДА
//
// Своя копия мерила бы САМУ СЕБЯ: она осталась бы красной после починки
// прод-кода — либо, будучи поправленной вместе с ним, перестала бы касаться
// предмета. Ровно это и случилось с плечом Г15 соседней пробы: `observedScope`
// несёт СВОЙ обход по `resource_parent_edge`, поэтому починка запроса вердикта
// не сдвигает его числа НИ НА ЕДИНИЦУ, и утверждать о запросе оно не может.
//
// Поэтому список CTE берётся из ТЕКСТА, который исполняет продукт: он режется по
// якорю финального `SELECT`, а имя набора, который читают армы, ВЫВОДИТСЯ из
// того же текста. Съедет якорь или разойдутся армы — проба скажет об этом
// отказом, а не молчанием.

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/pkg/ownerregister"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// scopeFinalSelectAnchor — начало финального `SELECT` запроса вердикта.
//
// По нему отрезается список CTE. Якорь назван ДОСЛОВНО и проверяется на
// единственность: два вхождения или ноль означают, что текст запроса
// перестроен, и резать его прежним способом больше нельзя.
const scopeFinalSelectAnchor = "\nSELECT src.cond_name"

// scopeArmJoin — как армы читают набор областей.
//
// Оба арма обязаны читать ОДИН И ТОТ ЖЕ набор: разойдясь, они дали бы разные
// множества областей на один вопрос, и «одна семантика области» перестала бы
// быть верной внутри одного запроса.
var scopeArmJoin = regexp.MustCompile(`(?:CROSS )?JOIN ([a-z_]+) sc\b`)

// TestScopeChain_AncestorReachedTwiceIsReadOnce — набор областей, который читают
// армы, не повторяет предка.
func TestScopeChain_AncestorReachedTwiceIsReadOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()

	// ВЫРОЖДЕННЫЙ КОНТРОЛЬ ИДЁТ ПЕРВЫМ И НАЗЫВАЕТСЯ ВСЛУХ: на объекте без
	// предков обе величины равны единице ДО и ПОСЛЕ правки, то есть на такой
	// фикстуре утверждение не значит ничего. Показать это обязательно — иначе
	// зелёное на ней читалось бы как доказательство.
	shallow := measureScopeShape(t, ctx, chainShape{
		name:  "вырожденная цепь (объект без предков)",
		chain: nil,
	})
	t.Logf("КОНТРОЛЬ %s: строк набора %d, различных областей %d — величины СОВПАДАЮТ "+
		"и на прежней форме обхода, поэтому такая фикстура класс найти не может",
		shallow.shape.name, shallow.rows, shallow.distinct)
	if shallow.rows != shallow.distinct {
		t.Fatalf("вырожденная цепь дала %d строк при %d различных: контроль не воспроизвёл "+
			"вырожденный случай, и вывод «нужна цепь с дублем» повисает", shallow.rows, shallow.distinct)
	}

	// ПРЕДМЕТ: цепь той формы, какую шлёт производитель для compute и nlb.
	two := measureScopeShape(t, ctx, chainShape{
		name:  "два звена — форма compute/nlb",
		chain: ownerregister.ParentChain(nil, "prj-1", "acc-1"),
	})
	t.Logf("ПРЕДМЕТ %s: строк набора %d, различных областей %d",
		two.shape.name, two.rows, two.distinct)

	// Предпосылка самой пробы: дубль обязан БЫТЬ ВОЗМОЖЕН на этой фикстуре.
	// Иначе равенство ниже выполнится тождественно, как на вырожденной цепи.
	if two.distinct <= shallow.distinct {
		t.Fatalf("на цепи из двух звеньев различных областей %d — не больше, чем у объекта "+
			"без предков (%d): фикстура не построила цепи вовсе, и равенство ниже проверяло бы "+
			"пустое место", two.distinct, shallow.distinct)
	}

	if two.rows != two.distinct {
		t.Fatalf(
			"набор областей, который читают армы (%s), отдаёт %d строк при %d различных областях.\n"+
				"Каждая лишняя строка умножает ОБА арма: ветвь выдач соединена с набором `CROSS JOIN`, "+
				"ветвь фактов — по паре колонок. На отказном вопросе короткого замыкания нет, и цена "+
				"платится целиком.\nПричина: кортеж обхода несёт ГЛУБИНУ, поэтому `UNION` не схлопывает "+
				"предка, достигнутого двумя путями (аккаунт на 1 и 2, кластер на 2 и 3).\n"+
				"Закрывается отбором различных поверх обхода — сам обход сохраняется.",
			two.relation, two.rows, two.distinct)
	}
}

// chainShape — форма цепи, которую сеет точка замера.
type chainShape struct {
	name  string
	chain []string
}

// scopeShape — что набор областей отдал армам.
type scopeShape struct {
	shape    chainShape
	relation string
	rows     int
	distinct int
}

// measureScopeShape — строки и различные области набора, который читают армы
// ЗАПРОСА ВЕРДИКТА, на цепи заданной формы.
func measureScopeShape(t *testing.T, ctx context.Context, shape chainShape) scopeShape {
	t.Helper()

	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("разбор строки подключения: %v", err)
	}
	capture := &verdictCapture{}
	cfg.ConnConfig.Tracer = capture
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	seedTenant(t, ctx, tx)
	base := time.Now().UTC().Truncate(time.Microsecond)
	registerThroughProducer(t, ctx, tx, catalogFormOf(t, "vpc_network"), "net-1",
		shape.chain, projectOf(shape.chain), accountOf(shape.chain), base)

	// ВОПРОС ЗАДАЁТСЯ ОТКАЗНЫЙ, И ЭТО НЕ СЛУЧАЙНОСТЬ: на разрешающем ветвь выдач
	// останавливается на первой же строке (`LIMIT 1`), и цена дублей не платится
	// вовсе — то есть проба мерила бы случай, в котором предмета нет.
	got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject:    "user:usr-1",
		ObjectType: "vpc_network",
		ObjectID:   "net-1",
		Relation:   "v_get",
	})
	if err != nil {
		t.Fatalf("вопрос вердикта на цепи «%s»: %v", shape.name, err)
	}
	if got != relverdict.Deny {
		t.Fatalf("на цепи «%s» вердикт %s, ожидался отказ: выдач не сеялось, и разрешение "+
			"означает, что фикстура посеяла не то — либо что арм замкнулся и цена дублей не "+
			"платится", shape.name, got)
	}

	axis, err := relverdict.LabelAxisForTest("vpc.network", "vpc_network")
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	prod := relverdict.VerdictQuerySQLForTest(axis)
	stmts := capture.matching(prod)
	if len(stmts) != 1 {
		t.Fatalf("захвачено %d операторов, тождественных запросу вердикта, ожидался ровно один: "+
			"ноль означает, что продукт исполняет ДРУГОЙ текст, чем собирает verdictQuerySQL, и "+
			"проба мерила бы не тот запрос", len(stmts))
	}

	rel := armScopeRelation(t, prod)
	probeSQL := scopeCensusSQL(t, prod, rel)

	var rows, distinct int
	if err := tx.QueryRow(ctx, probeSQL, stmts[0].args...).Scan(&rows, &distinct); err != nil {
		t.Fatalf("перепись набора областей на цепи «%s»: %v\nЗапрос:\n%s", shape.name, err, probeSQL)
	}
	return scopeShape{shape: shape, relation: rel, rows: rows, distinct: distinct}
}

// armScopeRelation — имя набора областей, ВЫВЕДЕННОЕ из текста продукта.
//
// Выписанное имя пережило бы переименование набора и продолжало бы мерить то,
// чего армы не читают.
func armScopeRelation(t *testing.T, prod string) string {
	t.Helper()
	found := scopeArmJoin.FindAllStringSubmatch(prod, -1)
	if len(found) == 0 {
		t.Fatalf("в тексте вердикта не нашлось ни одного соединения с набором областей под "+
			"псевдонимом `sc`: предпосылка пробы не выполнена, и «ноль находок» означало бы "+
			"«ноль прочитанного».\nПредикат: %s", scopeArmJoin.String())
	}
	name := found[0][1]
	for _, m := range found[1:] {
		if m[1] != name {
			t.Fatalf("армы читают РАЗНЫЕ наборы областей: %q и %q. Одна семантика области "+
				"перестала быть верной внутри одного запроса", name, m[1])
		}
	}
	t.Logf("объём осмотренного: соединений с набором областей %d, все читают %q",
		len(found), name)
	return name
}

// scopeCensusSQL — перепись набора областей, собранная НА СПИСКЕ CTE ПРОДУКТА.
//
// Продуктовым остаётся всё, что производит набор; пробе принадлежит только
// финальная проекция. Параметры $6, $8 и $9 списком CTE не читаются — они живут
// в армах, — поэтому связываются заведомо истинным предикатом: без этого число
// параметров оператора разошлось бы с числом захваченных значений.
func scopeCensusSQL(t *testing.T, prod, rel string) string {
	t.Helper()
	if n := strings.Count(prod, scopeFinalSelectAnchor); n != 1 {
		t.Fatalf("якорь финального SELECT (%q) встречается %d раз, ожидался ровно один: "+
			"текст запроса перестроен, и резать его прежним способом нельзя",
			strings.TrimSpace(scopeFinalSelectAnchor), n)
	}
	cteList := prod[:strings.Index(prod, scopeFinalSelectAnchor)]
	return cteList + fmt.Sprintf(`
SELECT count(*)::int, count(DISTINCT (sc.s_type, sc.s_id))::int
  FROM %s sc
 WHERE $6::text[] IS NOT NULL AND $8::int IS NOT NULL AND $9::text IS NOT NULL`, rel)
}

// projectOf / accountOf — зеркальные колонки регистрации, выведенные из цепи.
//
// Производитель заполняет их той же парой, из которой строит цепь; расписывать
// их отдельно значило бы завести второе место об одном предмете.
func projectOf(chain []string) string { return afterPrefix(chain, "project:") }
func accountOf(chain []string) string { return afterPrefix(chain, "account:") }

func afterPrefix(chain []string, prefix string) string {
	for _, link := range chain {
		if strings.HasPrefix(link, prefix) {
			return strings.TrimPrefix(link, prefix)
		}
	}
	return ""
}
