// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// manifest_test.go — форму манифеста домена судит ОДИН исполнитель (задача #1088,
// приёмка services/iam/docs/engineering/acceptance/module-manifest-seed-contract.md).
//
// Сценарии здесь — MOD-MF-01 · 02 · 03 · 04 · 05 · 06 · 07 · 12: то, что видно
// вызывающему загрузчика целиком. Ключ-нестрока разбирается отдельным файлом
// (keys_internal_test.go): три из четырёх его сценариев утверждают МОЛЧАНИЕ
// ступени разбора на входе, который до типизированной цели не доходит.
//
// # Каждое отрицание стоит в паре с положительным
//
// Проба «такое отвергается» без пробы «законное проходит» зеленеет на загрузчике,
// отвергающем ВСЁ. Поэтому у каждого отказа ниже — свой парный положительный на
// том же документе, испорченном ровно в одном месте.
package manifest_test

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// compactManifest — законный документ, испорченный по одному месту в каждой
// отрицательной пробе. Раздел `seed` здесь сокращён до одного элемента каждого
// подраздела: предмет проб этого файла — ФОРМА, а не объём. Полный раздел из
// черновика читает MOD-MF-01 из testdata.
const compactManifest = `apiVersion: iam/v1
module: vpc
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: system
      description: Личность модуля на пути запроса к соседям.
  groups:
    - name: vpc-internal-consumers
      account: system
      description: Смежные модули, ходящие в vpc на пути запроса.
  accessBindings:
    - subjects:
        - {type: group, name: vpc-internal-consumers}
      roleId: vpc.internal_consumer
      scopeType: iam.cluster
      scopeId: cluster_kacho_root
      target: allInScope
  joins:
    - serviceAccount: {account: system, name: kacho-vpc}
      group: {account: system, name: module-quota-readers}
      why: читает пределы квот на пути мутации, перед списанием
`

// lineOf — номер строки, на которой в документе впервые встречается needle.
// Ожидание номера ВЫВОДИТСЯ из документа, а не выписывается константой:
// выписанное разошлось бы с фикстурой молча при первой же её правке.
func lineOf(t *testing.T, doc, needle string) int {
	t.Helper()
	for i, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("в документе нет строки с %q — фикстура и проба разошлись", needle)
	return 0
}

// reportedLines — номера строк, названные отказом.
//
// Разбором, а не подстрокой: `strings.Contains(msg, "line 1")` истинно и на
// «line 15», поэтому проба, написанная через подстроку, объявляла бы отказ на
// глубине 15 указывающим на корень. Поймано собственным утверждением этой же
// пробы — и починена проба, а не код.
var lineMention = regexp.MustCompile(`line (\d+)`)

func reportedLines(err error) []int {
	var out []int
	for _, m := range lineMention.FindAllStringSubmatch(err.Error(), -1) {
		n, convErr := strconv.Atoi(m[1])
		if convErr == nil {
			out = append(out, n)
		}
	}
	return out
}

// namesFieldAndLine — отказ обязан называть ПРЕДМЕТ: имя поля и номер строки.
// «invalid manifest» без координаты посылает читателя искать вручную.
func namesFieldAndLine(t *testing.T, err error, field string, line int) {
	t.Helper()
	if err == nil {
		t.Fatalf("ожидался отказ, называющий поле %q и строку %d; получен nil", field, line)
	}
	msg := err.Error()
	if !strings.Contains(msg, field) {
		t.Errorf("отказ не называет поле %q: %s", field, msg)
	}
	if !slices.Contains(reportedLines(err), line) {
		t.Errorf("отказ не называет строку %d (названы %v): %s", line, reportedLines(err), msg)
	}
}

// ── MOD-MF-01 ───────────────────────────────────────────────────────────────

// TestMODMF01RealManifestPassesTheLoader — положительный контроль ВСЕЙ полосы.
// Без него любое отрицание ниже зеленело бы на загрузчике, отвергающем всё.
//
// Раздел `seed` фикстуры взят ДОСЛОВНО из проверенного черновика; перепись его
// валидатора — учётных записей 1 · групп 2 · выдач 2 · вступлений 1, и проба
// утверждает ровно эти четыре числа плюс значения.
//
// Третье «И» сценария — ИЗМЕРЕННАЯ ГРАНИЦА, а не утверждение этой пробы: схема к
// документу НЕ ПРИМЕНЯЕТСЯ. Применить её нечем — библиотеки JSON Schema для Go в
// дереве нет ни одной (`grep -ci jsonschema go.mod` → 0, код возврата 1), и схема
// читается КАК ФАЙЛ (os.ReadFile в пробе согласия). Отсутствие библиотеки —
// решение, а не срок: §2.1 приёмки запрещает заводить второго судью формы, потому
// что два судьи расходятся МОЛЧА — оба отвечают «валидно» на валидном входе, а
// расходятся лишь на невалидном. Согласие схемы и структур держит вместо него
// MOD-MF-21: он сличает МНОЖЕСТВА ключей, не разбирая документ схемой.
//
// Здесь стояло требование, которого сценарий больше не несёт: оно снято по #1818
// как требование БЕЗ ПРОИЗВОДИТЕЛЯ. Дословно оно тут не воспроизводится, и это не
// осторожность: предикат снятия #1818 считает вхождения его фразы, а цитата в
// объяснении для счётчика неотличима от живого требования — проверка краснела бы
// на собственном объяснении (testing.md §«Гейт на класс», п. 4). Разбор снятия —
// приёмка §5.1, врезка.
//
// Ещё раньше отказ объяснялся тем, что «схемы в дереве ещё нет». Объяснение было
// ложным и опасным в одну сторону: схема есть (services/iam/schema/), и читатель,
// действующий по нему, заключил бы, что предмет появился и пора утверждать, — и
// потянулся бы ровно за той библиотекой, против которой написан MOD-MF-21.
func TestMODMF01RealManifestPassesTheLoader(t *testing.T) {
	data, err := os.ReadFile("testdata/vpc.seed-fixture.yaml")
	if err != nil {
		t.Fatalf("чтение фикстуры: %v", err)
	}

	m, err := manifest.Load(data)
	if err != nil {
		t.Fatalf("законный манифест отвергнут: %v", err)
	}
	if m.APIVersion != "iam/v1" || m.Module != "vpc" {
		t.Fatalf("оболочка прочитана неверно: apiVersion=%q module=%q", m.APIVersion, m.Module)
	}
	if m.Seed == nil {
		t.Fatalf("раздел seed объявлен документом, но вызывающему недоступен")
	}

	t.Logf("перепись фикстуры: учётных записей %d · групп %d · выдач %d · вступлений %d",
		len(m.Seed.ServiceAccounts), len(m.Seed.Groups), len(m.Seed.AccessBindings), len(m.Seed.Joins))

	if got := len(m.Seed.ServiceAccounts); got != 1 {
		t.Errorf("служебных записей %d, черновик несёт 1", got)
	}
	if got := len(m.Seed.Groups); got != 2 {
		t.Errorf("групп %d, черновик несёт 2", got)
	}
	if got := len(m.Seed.AccessBindings); got != 2 {
		t.Errorf("выдач %d, черновик несёт 2", got)
	}
	if got := len(m.Seed.Joins); got != 1 {
		t.Errorf("вступлений %d, черновик несёт 1", got)
	}
	if t.Failed() {
		t.FailNow() // дальше проба индексирует элементы, которых при ином числе нет
	}

	// Значения всех четырёх подразделов доступны вызывающему — иначе «прочитал»
	// означало бы лишь «не упал».
	if m.Seed.ServiceAccounts[0].Name != "kacho-vpc" || m.Seed.ServiceAccounts[0].Account != "system" {
		t.Errorf("служебная запись прочитана неверно: %+v", m.Seed.ServiceAccounts[0])
	}
	if len(m.Seed.ServiceAccounts[0].Description) < 16 {
		t.Errorf("описание служебной записи потеряно: %q", m.Seed.ServiceAccounts[0].Description)
	}
	if m.Seed.Groups[0].Name != "vpc-internal-consumers" || m.Seed.Groups[1].Name != "cloud-network-admins" {
		t.Errorf("группы прочитаны неверно: %q, %q", m.Seed.Groups[0].Name, m.Seed.Groups[1].Name)
	}
	b := m.Seed.AccessBindings[0]
	if b.RoleID != "vpc.internal_consumer" || b.ScopeType != "iam.cluster" ||
		b.ScopeID != "cluster_kacho_root" || b.Target != "allInScope" {
		t.Errorf("выдача прочитана неверно: %+v", b)
	}
	if len(b.Subjects) != 1 || b.Subjects[0].Type != "group" || b.Subjects[0].Name != "vpc-internal-consumers" {
		t.Errorf("субъект выдачи прочитан неверно: %+v", b.Subjects)
	}
	if len(b.Resources) != 0 {
		t.Errorf("выдача target=allInScope не перечисляет объектов, прочитано %d", len(b.Resources))
	}
	j := m.Seed.Joins[0]
	if j.ServiceAccount.Account != "system" || j.ServiceAccount.Name != "kacho-vpc" {
		t.Errorf("вступающая запись прочитана неверно: %+v", j.ServiceAccount)
	}
	if j.Group.Account != "system" || j.Group.Name != "module-quota-readers" {
		t.Errorf("группа вступления прочитана неверно: %+v", j.Group)
	}
	if j.Why == "" {
		t.Errorf("причина вступления потеряна")
	}
}

// ── MOD-MF-02 ───────────────────────────────────────────────────────────────

// TestMODMF02SeedAbsenceIsRepresentableApartFromEmptySeed — отсутствие раздела
// представимо ОТДЕЛЬНО от пустого раздела.
//
// Иначе вызывающий не отличит «модуль ничего не сеет» от «модуль объявил посев и
// он пуст», а это разные утверждения: первое законно, второе — повод спросить.
func TestMODMF02SeedAbsenceIsRepresentableApartFromEmptySeed(t *testing.T) {
	absent, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: vpc\n"))
	if err != nil {
		t.Fatalf("документ без раздела seed отвергнут: %v", err)
	}
	if absent.Seed != nil {
		t.Errorf("раздел seed не объявлен, а вызывающему виден: %+v", absent.Seed)
	}

	declared, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: vpc\nseed: {}\n"))
	if err != nil {
		t.Fatalf("документ с пустым разделом seed отвергнут: %v", err)
	}
	if declared.Seed == nil {
		t.Fatalf("раздел seed объявлен пустым, а неотличим от необъявленного")
	}
	if n := len(declared.Seed.ServiceAccounts) + len(declared.Seed.Groups) +
		len(declared.Seed.AccessBindings) + len(declared.Seed.Joins); n != 0 {
		t.Errorf("пустой раздел seed принёс %d элементов", n)
	}
}

// TestMODMF02SeedDeclaredNullIsRefused — ключ `seed:` без значения отвергается.
//
// Граница сценария MOD-MF-02, названная явно, а не оставленная умолчанию: пустое
// значение YAML даёт `null`, и молчаливое приведение его к «раздела нет» вернуло
// бы ровно ту неразличимость, ради снятия которой раздел сделан указателем.
func TestMODMF02SeedDeclaredNullIsRefused(t *testing.T) {
	doc := "apiVersion: iam/v1\nmodule: vpc\nseed:\n"
	_, err := manifest.Load([]byte(doc))
	if err == nil {
		t.Fatalf("объявленный и пустой ключ seed принят молча")
	}
	if !errors.Is(err, manifest.ErrSeedDeclaredNull) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	namesFieldAndLine(t, err, "seed", lineOf(t, doc, "seed:"))
}

// ── MOD-MF-03, MOD-MF-04 ────────────────────────────────────────────────────

// TestMODMF03UnknownTopLevelKeyIsRefused — неизвестный ключ верхнего уровня.
func TestMODMF03UnknownTopLevelKeyIsRefused(t *testing.T) {
	broken := strings.Replace(compactManifest, "seed:", "seedz:", 1)

	_, err := manifest.Load([]byte(broken))
	namesFieldAndLine(t, err, "seedz", lineOf(t, broken, "seedz:"))
	if err != nil && !errors.Is(err, manifest.ErrShape) {
		t.Errorf("отказ не отнесён к форме документа: %v", err)
	}

	// Парный положительный: тот же документ с `seed`.
	if _, err := manifest.Load([]byte(compactManifest)); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// TestMODMF04UnknownNestedKeyIsRefusedTheSameWay — неизвестный ключ НА ГЛУБИНЕ.
//
// Отказ обязан называть строку ТОГО элемента, а не корня: замер, из которого
// сценарий выведен, показал `line 7: field clazz not found in type verb` на
// глубине 3 — то есть свойство измерено, а не понадеяно.
func TestMODMF04UnknownNestedKeyIsRefusedTheSameWay(t *testing.T) {
	broken := strings.Replace(compactManifest, "      roleId:", "      rolelD:", 1)

	_, err := manifest.Load([]byte(broken))
	namesFieldAndLine(t, err, "rolelD", lineOf(t, broken, "rolelD:"))

	// Отказ обязан указывать на элемент выдачи, а не на корень документа.
	if err != nil && slices.Contains(reportedLines(err), lineOf(t, broken, "apiVersion:")) {
		t.Errorf("отказ на глубине показывает на корень документа: %v", err)
	}

	if _, err := manifest.Load([]byte(compactManifest)); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MF-05 ───────────────────────────────────────────────────────────────

// TestMODMF05UnknownAPIVersionIsRefused — отказ называет и полученное значение,
// и перечень принимаемых: иначе автор манифеста узнаёт, что ошибся, но не узнаёт,
// чем это чинить.
func TestMODMF05UnknownAPIVersionIsRefused(t *testing.T) {
	broken := strings.Replace(compactManifest, "apiVersion: iam/v1", "apiVersion: iam/v2", 1)

	_, err := manifest.Load([]byte(broken))
	if err == nil {
		t.Fatalf("неизвестный apiVersion принят молча")
	}
	if !errors.Is(err, manifest.ErrUnsupportedAPIVersion) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "iam/v2") {
		t.Errorf("отказ не называет полученное значение: %s", msg)
	}
	if !strings.Contains(msg, "iam/v1") {
		t.Errorf("отказ не называет перечень принимаемых: %s", msg)
	}

	if _, err := manifest.Load([]byte(compactManifest)); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MF-06 ───────────────────────────────────────────────────────────────

// TestMODMF06ModuleOutsideThePlatformSetIsRefused — `module` вне закрытого набора.
//
// Ловушка словаря, ради которой сценарий и написан: токен домена балансировки —
// `loadbalancer`, а КАТАЛОГ сервиса зовётся `services/nlb`. Манифест, названный по
// каталогу, разошёлся бы с набором молча.
func TestMODMF06ModuleOutsideThePlatformSetIsRefused(t *testing.T) {
	broken := strings.Replace(compactManifest, "module: vpc", "module: nlb", 1)

	_, err := manifest.Load([]byte(broken))
	if err == nil {
		t.Fatalf("модуль вне закрытого набора принят молча")
	}
	if !errors.Is(err, manifest.ErrUnknownModule) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(), "nlb") {
		t.Errorf("отказ не называет полученный токен: %v", err)
	}

	// Парный положительный — ИМЕННО `loadbalancer`, а не любой другой член набора:
	// он и есть предмет ловушки.
	twin := strings.Replace(compactManifest, "module: vpc", "module: loadbalancer", 1)
	if _, err := manifest.Load([]byte(twin)); err != nil {
		t.Fatalf("парный положительный (loadbalancer) отвергнут: %v", err)
	}
}

// TestMODMF06ModuleSetIsReadFromItsOwnerNotCopied — перечень модулей загрузчик
// БЕРЁТ У ВЛАДЕЛЬЦА, а не несёт свою копию.
//
// Копия разошлась бы с литералом молча — этот самый набор уже переживал такое
// (комментарий у knownModules признаёт: строка осталась при пяти именах, когда
// шестое было добавлено). Проба утверждает РАВЕНСТВО поведения владельцу, а не
// членство отдельных имён: членство росту набора не сопротивляется.
func TestMODMF06ModuleSetIsReadFromItsOwnerNotCopied(t *testing.T) {
	owned := domain.KnownModules()
	if len(owned) == 0 {
		t.Fatalf("набор владельца пуст — сверять нечего")
	}
	t.Logf("перепись: модулей у владельца %d", len(owned))

	for _, m := range owned {
		doc := strings.Replace(compactManifest, "module: vpc", "module: "+m, 1)
		if _, err := manifest.Load([]byte(doc)); err != nil {
			t.Errorf("модуль %q — член набора владельца, а загрузчик его отверг: %v", m, err)
		}
	}
	for _, m := range []string{"nlb", "geo", "vpc2", "VPC"} {
		if domain.IsKnownModule(m) {
			continue // владелец его знает — тогда это не отрицательный вход
		}
		doc := strings.Replace(compactManifest, "module: vpc", "module: "+m, 1)
		if _, err := manifest.Load([]byte(doc)); err == nil {
			t.Errorf("модуль %q владельцу неизвестен, а загрузчик его принял", m)
		}
	}
}

// ── MOD-MF-07 ───────────────────────────────────────────────────────────────

// TestMODMF07UnknownSectionIsRefusedExplicitly — раздел, которого форма не
// знает, отвергается ЯВНО, а не молча выбрасывается.
//
// Это исход 2 запрета «принято-и-проигнорировано»: молча принять и выбросить
// нельзя — вызывающий получил бы успех и уверенность, что его раздел применён.
//
// # Проба ПЕРЕПИСАНА, а не снята (MOD-MR-21)
//
// До #1778 три раздела — `resources`, `roles`, `deprecatedVerbs` — были
// «известными и ещё не описанными», отвергались по имени и называли
// задачу-преемника НОМЕРОМ. Разделы описаны, и предмет того утверждения исчез.
// Утверждение, потерявшее вход, ЗАМОЛКАЕТ, а не краснеет (`testing.md` §«Гейт на
// класс», п. 9), поэтому оно заменено на то, у которого вход есть всегда:
// неизвестный раздел обязан отвергаться и после, а текст — называть ключ.
func TestMODMF07UnknownSectionIsRefusedExplicitly(t *testing.T) {
	for _, section := range []string{"services", "resource", "Roles", "deprecated_verbs"} {
		t.Run(section, func(t *testing.T) {
			doc := "apiVersion: iam/v1\nmodule: vpc\n" + section + ": []\n"
			_, err := manifest.Load([]byte(doc))
			if err == nil {
				t.Fatalf("раздел %q принят молча", section)
			}
			if !errors.Is(err, manifest.ErrShape) {
				t.Errorf("отказ не отнесён к своей причине: %v", err)
			}
			if !strings.Contains(err.Error(), section) {
				t.Errorf("отказ не называет ключ %q: %v", section, err)
			}
		})
	}

	// Парный положительный: ВСЕ ЧЕТЫРЕ описанных раздела принимаются. Без него
	// отрицание зеленело бы на загрузчике, отвергающем всякий раздел.
	described := "apiVersion: iam/v1\nmodule: vpc\n" +
		"resources:\n  - {name: network, objectType: vpc_network, parents: [project], producer: derived, verbs: [get]}\n" +
		"roles:\n  - id: vpc.viewer\n    description: Читает топологию проекта.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - {module: vpc, resources: [network], classes: [get]}\n" +
		"deprecatedVerbs:\n  read: {class: get, since: \"2026-08-23\", reason: синоним чтения из прежней грамматики, removeWhen: выдач с таким правом ноль}\n" +
		"seed: {}\n"
	if _, err := manifest.Load([]byte(described)); err != nil {
		t.Fatalf("описанный раздел отвергнут: %v", err)
	}

	// Парный положительный: тот же документ без этих разделов.
	if _, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: vpc\n")); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// ── MOD-MF-12 ───────────────────────────────────────────────────────────────

// TestMODMF12NonStringKeyIsCaughtByTheDecoderNotLater — свойство держится в
// РАЗБОРЕ, а не позже.
//
// Замер, ради которого сценарий: типизированная цель `map[string]map[string]string`
// приводит ключ `true` к строке `"true"` с `err == nil`. К моменту валидатора
// связности предмета уже нет — свойство, вынесенное туда, было бы вакуумным.
// Здесь утверждается наблюдаемое следствие: вызывающий не получает НИ ОДНОГО
// разобранного документа, значит дальше по пути такой вход не уезжает вовсе.
func TestMODMF12NonStringKeyIsCaughtByTheDecoderNotLater(t *testing.T) {
	doc := "apiVersion: iam/v1\nmodule: vpc\nseed:\n  true: x\n"

	m, err := manifest.Load([]byte(doc))
	if err == nil {
		t.Fatalf("булев ключ внутри seed принят молча")
	}
	if !errors.Is(err, manifest.ErrNonStringKey) {
		t.Fatalf("отказ пришёл не от разбора ключей: %v", err)
	}
	if m != nil {
		t.Errorf("отвергнутый документ всё же отдан вызывающему: %+v", m)
	}
	namesFieldAndLine(t, err, "true", lineOf(t, doc, "true:"))

	// Парный положительный: тот же ключ в кавычках — до типизированной цели он
	// доходит и отвергается уже ФОРМОЙ (неизвестное поле), а не типом ключа.
	quoted := "apiVersion: iam/v1\nmodule: vpc\nseed:\n  \"true\": x\n"
	_, err = manifest.Load([]byte(quoted))
	if err == nil {
		t.Fatalf("неизвестное поле \"true\" принято молча")
	}
	if errors.Is(err, manifest.ErrNonStringKey) {
		t.Errorf("ключ в кавычках объявлен нестрокой: %v", err)
	}
}

// ── границы документа ───────────────────────────────────────────────────────

// TestLoadRefusesDocumentsThatAreNotAManifest — пустой документ, не-отображение
// в корне и второй документ в потоке.
//
// Не сценарий приёмки, а полнота загрузчика в его границах (ban #14): каждый из
// трёх входов достижим, и молчаливое приведение любого из них к «пустому
// манифесту» было бы утверждением, которого документ не делал.
func TestLoadRefusesDocumentsThatAreNotAManifest(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want error
	}{
		{"пустой документ", "", manifest.ErrEmptyDocument},
		{"только комментарий", "# ничего\n", manifest.ErrEmptyDocument},
		{"корень — список", "- apiVersion: iam/v1\n", manifest.ErrRootNotMapping},
		{"корень — скаляр", "iam/v1\n", manifest.ErrRootNotMapping},
		{"второй документ в потоке", compactManifest + "---\napiVersion: iam/v1\nmodule: vpc\n", manifest.ErrMultipleDocuments},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := manifest.Load([]byte(c.doc))
			if !errors.Is(err, c.want) {
				t.Fatalf("ожидался %v, получен %v", c.want, err)
			}
		})
	}
}

// TestLoadRequiresTheEnvelopeKeys — оболочка обязательна.
//
// §1.2 приёмки: схема, написанная по телу задачи, `apiVersion` и `module` не
// описывает вовсе, и тогда реальный манифест не проходит НИ ПРИ КАКОМ значении.
// Здесь утверждается обратная половина: они не только описаны, но и обязательны —
// манифест без них не говорит, чей он и по какой версии читается.
func TestLoadRequiresTheEnvelopeKeys(t *testing.T) {
	if _, err := manifest.Load([]byte("module: vpc\n")); !errors.Is(err, manifest.ErrAPIVersionRequired) {
		t.Errorf("документ без apiVersion: ожидался ErrAPIVersionRequired, получен %v", err)
	}
	if _, err := manifest.Load([]byte("apiVersion: iam/v1\n")); !errors.Is(err, manifest.ErrModuleRequired) {
		t.Errorf("документ без module: ожидался ErrModuleRequired, получен %v", err)
	}
	if _, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: vpc\n")); err != nil {
		t.Errorf("парный положительный отвергнут: %v", err)
	}
}
