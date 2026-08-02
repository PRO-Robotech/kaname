// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// listgrantimpliesread_test.go — роль, дающая СПИСОК, обязана давать и ЧТЕНИЕ.
//
// # Почему это стало инвариантом
//
// Членство в странице публичного List равно праву прочитать эту строку по id: List
// возвращает то же сообщение ресурса, что и Get, поэтому «видно в перечне, но без
// содержимого» на такой выдаче нереализуемо. Предикат страницы поэтому сведён к
// отношению чтения (`v_get`) во всех сервисах с пообъектным сужением списка.
//
// У этого есть цена, и её нельзя платить молча: правило роли, которое авторит глагол
// `list` и НЕ авторит `get`, материализует `v_list` и ярусный кортеж, но не `v_get` —
// то есть после сужения перестаёт показывать объект вообще. Такое правило надо
// РЕШАТЬ (дописать `get` либо снять), а не обнаруживать по жалобе на пропавший список.
//
// # Что здесь проверяется, и на чём проверка держится
//
// Правила системных ролей читаются из применённых миграций и резолвятся ЗАКРЫТОЙ
// таблицей типов того же пакета (ObjectType) — тем самым резолвом, которым реконсайлер
// выбирает тип объекта для кортежа. Пара, которой таблица не несёт, кортежа не получит:
// резолв возвращает ok=false, а запасной подстановки по построению нет.
//
// Две оговорки, без которых числа ниже читались бы шире, чем заслуживают.
//
// ПЕРВАЯ: осматривается ВЕСЬ ряд миграций, а не итоговое состояние ролей. Более поздняя
// миграция переписывает правила более ранней, поэтому найденное правило может описывать
// уже смещённую строку. Для ЗАПРЕТА это безопасно в нужную сторону: осмотренное — НАДМНОЖЕСТВО
// живого, поэтому «ноль находок» покрывает живое состояние и подавно. Для чисел — нет, и
// поэтому перепись говорит «правил осмотрено», а не «ролей таких-то».
//
// ВТОРАЯ: «пара не в таблице» здесь означает ровно то, что сказано, — тип объекта для
// кортежа по ней не выводится. Совпадёт ли такое правило с чем-нибудь ВЫШЕ по потоку,
// решает другой словарь (типы зеркала, domain.AllMaterializableTypes), и это отдельный
// вопрос. Такие пары считаются и называются, но в запрет не идут: у них другой предмет.
//
// Отрицание идёт В ПАРЕ с положительным: «ноль правил list-без-get» зеленеет сильнее
// всего тогда, когда не резолвится вообще ничего, поэтому число резолвящихся правил и
// число правил, дающих list ВМЕСТЕ с get, утверждаются отдельно.
package authzmap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// migrationsDir — где живут применённые миграции iam, относительно этого пакета.
const migrationsDir = "../migrations"

// ruleObjectRe вытаскивает объекты правил из тела миграции. Форма ключа модуля за
// историю менялась (`modules` списком → `module` скаляром, миграция 0033), поэтому
// принимаются обе: гейт обязан читать ВСЁ дерево миграций, а не его свежий хвост.
var ruleObjectRe = regexp.MustCompile(`\{"modules?":(?:\[[^]]*\]|"[^"]*"),"resources":\[[^]]*\],"verbs":\[[^]]*\]\}`)

// seededRule — одно правило системной роли, как оно записано в миграции.
type seededRule struct {
	Module    string   `json:"module"`
	Modules   []string `json:"modules"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`

	file string
}

func (r seededRule) modules() []string {
	if r.Module != "" {
		return []string{r.Module}
	}
	return r.Modules
}

// hasVerb — есть ли глагол, с нормализацией того же вида, что применяет домен.
func (r seededRule) hasVerb(want string) bool {
	for _, v := range r.Verbs {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}

// isWildcard — правило-суперпользователь `*.*`: его глаголы разворачиваются в полный
// набор типа, поэтому `get` в нём присутствует по построению.
func (r seededRule) isWildcard() bool {
	for _, m := range r.modules() {
		if m == "*" {
			return true
		}
	}
	for _, res := range r.Resources {
		if res == "*" {
			return true
		}
	}
	for _, v := range r.Verbs {
		if v == "*" {
			return true
		}
	}
	return false
}

func loadSeededRules(t *testing.T) []seededRule {
	t.Helper()
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("прочитать %s: %v", migrationsDir, err)
	}
	var out []seededRule
	files := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		files++
		b, rerr := os.ReadFile(filepath.Join(migrationsDir, e.Name()))
		if rerr != nil {
			t.Fatalf("прочитать %s: %v", e.Name(), rerr)
		}
		for _, raw := range ruleObjectRe.FindAllString(string(b), -1) {
			var r seededRule
			if uerr := json.Unmarshal([]byte(raw), &r); uerr != nil {
				t.Fatalf("%s: правило %s не разобрано: %v", e.Name(), raw, uerr)
			}
			r.file = e.Name()
			out = append(out, r)
		}
	}
	if files == 0 {
		t.Fatalf("в %s нет ни одного .sql — гейт осматривает пустоту", migrationsDir)
	}
	t.Logf("перепись: миграций прочитано = %d; объектов правил найдено = %d", files, len(out))
	return out
}

// TestSeededRole_ListGrantImpliesRead — сам запрет.
func TestSeededRole_ListGrantImpliesRead(t *testing.T) {
	rules := loadSeededRules(t)

	var (
		resolvable   int      // (модуль, ресурс) резолвится закрытой таблицей типов
		listAndGet   int      // положительный контроль: даёт список И чтение
		unresolvable []string // грант, которому не на что материализоваться
		findings     []string
	)

	for _, r := range rules {
		if r.isWildcard() {
			continue // глаголы развернутся в полный набор типа, `get` там есть
		}
		for _, mod := range r.modules() {
			for _, res := range r.Resources {
				dotted := mod + "." + res
				if _, ok := ObjectType(mod, res); !ok {
					if r.hasVerb("list") && !r.hasVerb("get") {
						// Только та часть, которая относится к предмету ЭТОГО файла:
						// правило даёт список без чтения И тип для кортежа по нему не
						// выводится. Такое правило не показало бы объект ни до сужения
						// предиката, ни после, и его надо решать отдельно.
						unresolvable = append(unresolvable,
							fmt.Sprintf("%s (%s, глаголы %v)", dotted, r.file, r.Verbs))
					}
					continue
				}
				resolvable++
				switch {
				case r.hasVerb("list") && !r.hasVerb("get"):
					findings = append(findings, fmt.Sprintf(
						"%s (%s): правило авторит %v — `list` без `get`.\n"+
							"  Следствие: реконсайлер напишет `v_list` и ярусный кортеж, но НЕ `v_get`, "+
							"а членство в странице публичного List равно праву прочитать строку по id — "+
							"объект не покажется вовсе.\n"+
							"  ЧТО ДЕЛАТЬ: дописать `get` (это не расширение — список и так отдаёт то же "+
							"сообщение, что Get) либо снять правило, если показывать нечего.",
						dotted, r.file, r.Verbs))
				case r.hasVerb("list") && r.hasVerb("get"):
					listAndGet++
				}
			}
		}
	}

	sort.Strings(unresolvable)
	sort.Strings(findings)

	// Положительный контроль: без него «ноль находок» неотличимо от «ничего не
	// резолвится и запрет ни к чему не приложился».
	if resolvable == 0 {
		t.Fatalf("ни одно правило не резолвится закрытой таблицей типов — запрет не приложился ни к чему. "+
			"Либо имена ресурсов в миграциях разошлись с таблицей, либо разбор правил сломан "+
			"(объектов найдено: %d)", len(rules))
	}
	if listAndGet == 0 {
		t.Fatalf("ни одно резолвящееся правило не даёт `list` вместе с `get` — предикат запрета "+
			"не различает искомое состояние от любого другого (резолвится правил: %d)", resolvable)
	}
	t.Logf("перепись: пар (модуль, ресурс) резолвится закрытой таблицей типов = %d; из них дают `list` "+
		"вместе с `get` = %d; правил «список без чтения» на НЕрезолвящейся паре = %d",
		resolvable, listAndGet, len(unresolvable))

	// Открытый предмет, НЕ этого запрета: правило даёт список без чтения, и пары нет в
	// закрытой таблице типов — тип объекта для кортежа по нему не выводится. Называется
	// поимённо, чтобы не быть невидимым; решать — продуктовое действие (дописать `get` и
	// привести имя ресурса к словарю, либо снять правило).
	for _, u := range unresolvable {
		t.Logf("ОТКРЫТО (другой предмет): %s — список без чтения И пары нет в закрытой таблице типов", u)
	}

	if len(findings) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "роль даёт список, но не даёт чтения (%d):\n", len(findings))
		for _, f := range findings {
			fmt.Fprintf(&b, "\n%s\n", f)
		}
		t.Error(b.String())
	}
}

// TestSeededRole_ListGrantImpliesRead_GateDiscriminates — инъекция в обе стороны.
//
// Проверка обязана краснеть на настоящем правиле «list без get» и молчать на законном
// близнеце той же формы. Оба входа строятся из ЖИВОЙ пары (модуль, ресурс), взятой из
// закрытой таблицы, — синтетический тип прошёл бы мимо резолва и ничего не доказал.
func TestSeededRole_ListGrantImpliesRead_GateDiscriminates(t *testing.T) {
	var mod, res string
	for _, e := range Catalog() {
		if _, ok := ObjectType(e.Module, e.Resource); ok {
			mod, res = e.Module, e.Resource
			break
		}
	}
	if mod == "" {
		t.Fatalf("в закрытой таблице типов нет ни одной пары — инъекции не на чем стоять")
	}

	classify := func(verbs []string) bool { // true ⇒ находка
		r := seededRule{Module: mod, Resources: []string{res}, Verbs: verbs}
		if r.isWildcard() {
			return false
		}
		if _, ok := ObjectType(mod, res); !ok {
			return false
		}
		return r.hasVerb("list") && !r.hasVerb("get")
	}

	if !classify([]string{"list"}) {
		t.Errorf("правило %s.%s с глаголом только `list` обязано быть находкой", mod, res)
	}
	if classify([]string{"get", "list"}) {
		t.Errorf("законный близнец (`get` вместе с `list`) обязан молчать — иначе запрет ловит форму, а не существо")
	}
	if classify([]string{"get"}) {
		t.Errorf("правило без `list` вообще предметом запрета не является")
	}
	if classify([]string{"*"}) {
		t.Errorf("правило-суперпользователь разворачивается в полный набор глаголов типа — `get` там есть")
	}
}
