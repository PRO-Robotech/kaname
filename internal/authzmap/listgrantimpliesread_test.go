// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// ruleObjectRe — КАНДИДАТ в правило: объект JSON без вложенных объектов.
//
// Здесь стоял образец, требовавший ключей в ОДНОМ порядке и без пробелов
// (`{"module":…,"resources":…,"verbs":…}`). Он описывал не правило, а то, как
// его записал автор рукописной миграции.
//
// Сведение цепочки в одну первичную (2026-09-04) завело вторую законную форму:
// `pg_dump` печатает ЗНАЧЕНИЕ столбца, а `jsonb` хранит ключи по длине —
// `verbs`(5) · `module`(6) · `resources`(9), — да ещё с пробелом после
// двоеточия. Прежний образец не совпал НИ РАЗУ, и гейт объявил, что правил
// ноль: не находка, а молчание. Поймала его собственная предпосылка
// («объектов найдено 0»), и это единственное, чем такое молчание отличимо от
// исправной работы.
//
// Порядок ключей теперь не судится вовсе — его судит разбор JSON, которому
// порядок безразличен by construction. Образец отбирает кандидатов, а
// принадлежность к правилам решают ОБА обязательных ключа ниже.
var ruleObjectRe = regexp.MustCompile(`\{[^{}]*\}`)

// ruleObjectKeys — ключи, без которых объект правилом не является. Проверяются
// оба: по одному «resources» под образец подпадает всякий перечень ресурсов,
// какой встретится в строке данных.
var ruleObjectKeys = []string{`"resources"`, `"verbs"`}

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
			isRule := true
			for _, k := range ruleObjectKeys {
				if !strings.Contains(raw, k) {
					isRule = false
					break
				}
			}
			if !isRule {
				continue
			}
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
		exemptNoVGet []string // тип, чьё чтение не гейтится `v_get` ни одной записью каталога
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

				// ИСКЛЮЧЕНИЕ, ВЫВЕДЕННОЕ ИЗ КАТАЛОГА, А НЕ ВЫПИСАННОЕ.
				//
				// Запрет держится на следствии: «реконсайлер напишет v_list, но не
				// v_get, а членство в странице публичного List равно праву
				// прочитать строку по id». Следствие наступает только там, где
				// чтение ГЕЙТИТСЯ отношением `v_get`. Есть типы, где оно не
				// гейтится им НИКОГДА: их чтение сужается на данных
				// (`scope_filtered`), а `required_relation` у Get и List пуст.
				// Для такого типа «list без get» ничего не ломает, и требовать
				// `get` значило бы требовать отношение, которого не спрашивает
				// ни одна запись каталога.
				//
				// Исключение ВЫВОДИТСЯ из каталога разрешений и потому истекает
				// само: появится запись, требующая `v_get` на этом типе, — пара
				// вернётся под запрет без правки этого файла.
				//
				// Замер на дереве: записей каталога 350, из них с
				// `required_relation = "v_get"` — 27 на 24 типах; `iam_role`
				// среди них нет, а записей с этим типом — три (Update, Delete,
				// ListOperations). Это и есть решение kacho#1916, принятое
				// ИНАЧЕ и с замером, а не пропущенное: у ресурса `role` модуля
				// `iam` нет ни одного действия, чей гейт спрашивал бы `v_get`.
				if typ, ok := ObjectType(mod, res); ok && !typesGatedByVGet(t)[typ] {
					exemptNoVGet = append(exemptNoVGet, dotted)
					continue
				}

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
	sort.Strings(exemptNoVGet)
	t.Logf("перепись: пар (модуль, ресурс) резолвится закрытой таблицей типов = %d; из них дают `list` "+
		"вместе с `get` = %d; правил «список без чтения» на НЕрезолвящейся паре = %d; "+
		"пар, освобождённых каталогом (чтение не гейтится `v_get` ни одной записью) = %d %v",
		resolvable, listAndGet, len(unresolvable), len(exemptNoVGet), uniqStrings(exemptNoVGet))

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

// typesGatedByVGet — типы объектов, чьё чтение гейтится отношением `v_get` хотя
// бы одной записью каталога разрешений.
//
// Читается ВСТРОЕННАЯ копия каталога того же сервиса — та, которую iam сеет; её
// байт-в-байт согласие с копией края держит отдельный гейт, и второй разбор
// здесь не заводится.
//
// Пустой результат — ОТКАЗ, а не «освободить всех»: разбор, переставший видеть
// каталог, освободил бы от запрета каждую пару и остался бы зелёным.
func typesGatedByVGet(t *testing.T) map[string]bool {
	t.Helper()
	const rel = "../apps/kacho/seed/embedded/permission_catalog.json"
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("каталог разрешений не прочитан (%s): %v — без него исключение ниже "+
			"освободило бы от запрета КАЖДУЮ пару", rel, err)
	}
	var entries []struct {
		RequiredRelation string `json:"required_relation"`
		ScopeExtractor   struct {
			ObjectType string `json:"object_type"`
		} `json:"scope_extractor"`
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatalf("каталог разрешений не разобран: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("каталог разрешений пуст — освобождение стало бы всеобщим")
	}
	out := map[string]bool{}
	for _, e := range entries {
		if e.RequiredRelation == "v_get" && e.ScopeExtractor.ObjectType != "" {
			out[e.ScopeExtractor.ObjectType] = true
		}
	}
	if len(out) == 0 {
		t.Fatalf("в каталоге (%d записей) НИ ОДНА не требует `v_get` — предикат "+
			"освобождения выродился и снял бы запрет со всех пар", len(entries))
	}
	return out
}

// uniqStrings — перечень без повторов: одна пара встречается в правилах многих
// ролей, и перепись печатала бы её столько же раз.
func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
