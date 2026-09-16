// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// doc_header_names_its_declaration_injection_test.go — доказательство
// способности гейта упасть И смолчать.
//
// Инъекция подаёт НАСТОЯЩИЙ вход — тот, из которого гейт и выведен: шапка
// `APIServerConfig` с разбором двух форм адреса слушателя, склеенная в одну
// группу с шапкой `SubscriptionConfig` и доставшаяся второй (kaname#118).
// Законные близнецы — те же формы записи там, где они законны.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// docHeaderDetachedSrc — настоящий дефект: между блоком `APIServerConfig` и его
// объявлением встало другое объявление со своей шапкой, пустая строка между
// блоками потерялась, и Go склеил обе группы в одну.
const docHeaderDetachedSrc = `package config

// APIServerConfig — api-server section.
//
// Endpoint / InternalEndpoint accept two formats:
//   - ` + "`tcp://0.0.0.0:9090`" + ` (full URL-style, recommended);
//   - ` + "`9090`" + ` (legacy: bare port).
//
// SubscriptionConfig — посадка потока изменений ресурсов.
type SubscriptionConfig struct {
	MaxStreams int
}

type APIServerConfig struct {
	Endpoint string
}
`

// docHeaderRenamedSrc — второй путь к тому же исходу: объявление переименовали,
// шапку не тронули.
const docHeaderRenamedSrc = `package p

// sqlIdentifierAt — первый идентификатор начиная с позиции i.
func sqlIdentifierAtPos(s string, i int) string { return s }
`

// docHeaderTwinSrc — законный близнец по трём осям сразу: шапка называет своё
// объявление; каноническая форма Go без разделителя шапкой НЕ считается;
// чужое имя, названное в теле и в строке, шапкой не является.
const docHeaderTwinSrc = `package p

// ScopeForMethod — охват метода по каталогу.
func ScopeForMethod(fqn string) string {
	// ActionForMethod — соседний глагол, назван здесь и шапкой не становится.
	const note = "ActionForMethod — тоже не шапка"
	return note + fqn
}

// ActionForMethod returns the permission name the catalog gives a method.
func ActionForMethod(fqn string) string { return fqn }
`

// docHeaderFormsSrc — ВСЕ формы объявления, у которых шапка бывает. У каждой
// шапка ВЕРНА: перечень проверяет, что форма ОПОЗНАНА, а не что она нарушена.
const docHeaderFormsSrc = `package p

// F — функция.
func F() {}

// M — метод.
func (t T) M() {}

// T — тип одиночным объявлением.
type T struct{}

type (
	// A — тип в блоке.
	A struct{}
	// B — второй тип того же блока.
	B struct{}
)

// C — константа одиночным объявлением.
const C = 1

const (
	// D — константа в блоке.
	D = 2
)

// V — переменная одиночным объявлением.
var V = 3

var (
	// W — переменная в блоке.
	W = 4
)
`

// TestDocHeaderGateRedsOnADetachedBlock — инъекция настоящим дефектом.
func TestDocHeaderGateRedsOnADetachedBlock(t *testing.T) {
	const rel = "internal/apps/kaname/config/config.go"
	sites, census, err := check.ScanDocHeaders(rel, []byte(docHeaderDetachedSrc))
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if census.Headers == 0 {
		t.Fatalf("перепись инъекции пуста — разбор ничего не прочитал, и его молчание "+
			"сказано ни о чём: %+v", census)
	}
	findings := docHeaderFindings(sites)
	if len(findings) != 1 {
		t.Fatalf("отвязавшаяся шапка НЕ стала находкой: находок %d при переписи %+v\n"+
			"Гейт, не краснеющий на дефекте, из которого он выведен, не удерживает ничего",
			len(findings), census)
	}
	for _, want := range []string{rel, `"APIServerConfig"`, `"SubscriptionConfig"`} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %s: %q", want, findings[0])
		}
	}
	// Второе объявление осталось БЕЗ шапки — та самая половина дефекта, которую
	// отвязавшаяся шапка и прячет.
	if census.Documented != 1 || census.Decls != 2 {
		t.Errorf("перепись не показывает, что одно из двух объявлений осталось без "+
			"шапки: %+v", census)
	}
}

// TestDocHeaderGateRedsOnAStaleRename — второй путь к тому же исходу.
func TestDocHeaderGateRedsOnAStaleRename(t *testing.T) {
	sites, census, err := check.ScanDocHeaders("internal/check/key_algorithm_dictionary.go",
		[]byte(docHeaderRenamedSrc))
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	findings := docHeaderFindings(sites)
	if len(findings) != 1 {
		t.Fatalf("переименование без правки шапки НЕ стало находкой: находок %d при "+
			"переписи %+v", len(findings), census)
	}
	if !strings.Contains(findings[0], `"sqlIdentifierAt"`) ||
		!strings.Contains(findings[0], `"sqlIdentifierAtPos"`) {
		t.Errorf("находка не называет ОБА имени: %q", findings[0])
	}
}

// TestDocHeaderGateStaysSilentOnLegalTwins — гейт обязан молчать там, где форма
// законна. Без этого он ловит форму, а не существо, и первый же ложный
// срабатыв его отключит.
func TestDocHeaderGateStaysSilentOnLegalTwins(t *testing.T) {
	sites, census, err := check.ScanDocHeaders("internal/apps/kaname/seed/permissions.go",
		[]byte(docHeaderTwinSrc))
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	if f := docHeaderFindings(sites); len(f) != 0 {
		t.Fatalf("гейт судит подстроку, а не шапку узла разбора: находок %d — он краснел "+
			"бы на собственном объяснении: %v", len(f), f)
	}
	// Шапка формы «Имя — текст» здесь ровно одна: каноническая форма Go без
	// разделителя шапкой не считается, и это граница, названная прямо.
	if census.Headers != 1 {
		t.Errorf("шапок формы «Имя — текст» прочитано %d, ожидалась одна: каноническая "+
			"форма Go («F returns …») разделителя не несёт и под разбор не подпадает: %+v",
			census.Headers, census)
	}
	if census.Documented != 2 {
		t.Errorf("объявлений с шапкой прочитано %d из двух — перепись обязана показывать "+
			"обе величины, иначе «шапок ноль» неотличимо от «шапок не искали»: %+v",
			census.Documented, census)
	}
}

// TestDocHeaderScannerKnowsEveryDeclarationForm — распознаватель обязан знать
// ВСЕ формы записи предмета. Форма, о которой он не знает, даёт не красное и не
// зелёное, а МОЛЧАНИЕ: объявление уезжает вне наблюдения.
func TestDocHeaderScannerKnowsEveryDeclarationForm(t *testing.T) {
	sites, census, err := check.ScanDocHeaders("internal/x/a.go", []byte(docHeaderFormsSrc))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	got := map[string][]string{}
	for _, s := range sites {
		got[s.Form] = append(got[s.Form], s.Named)
	}
	want := map[string][]string{
		"func":   {"F"},
		"method": {"M"},
		"type":   {"T", "A", "B"},
		"const":  {"C", "D"},
		"var":    {"V", "W"},
	}
	for form, names := range want {
		if len(got[form]) != len(names) {
			t.Errorf("форма объявления %q опознана %d раз(а) из %d — объявление в этой "+
				"форме уехало бы вне наблюдения: %v", form, len(got[form]), len(names), got[form])
		}
	}
	if census.Headers != 9 {
		t.Errorf("прочитано %d шапок из девяти: %+v", census.Headers, census)
	}
	if f := docHeaderFindings(sites); len(f) != 0 {
		t.Fatalf("верные шапки объявлены находками: %v", f)
	}
}

// TestDocHeaderGateReadsEveryNameOfAMultiNameSpec — у `var a, b = …` шапка
// вправе называть ЛЮБОЕ из имён. Находкой это становится, только когда она не
// называет НИ ОДНОГО: иначе законная форма стала бы красным на ровном месте.
func TestDocHeaderGateReadsEveryNameOfAMultiNameSpec(t *testing.T) {
	const legal = `package p

// second — шапка называет второе имя спецификации.
var first, second = 1, 2
`
	const defect = `package p

// third — имени с таким названием спецификация не несёт.
var first, second = 1, 2
`
	sites, _, err := check.ScanDocHeaders("internal/x/a.go", []byte(legal))
	if err != nil {
		t.Fatalf("разбор законного: %v", err)
	}
	if f := docHeaderFindings(sites); len(f) != 0 {
		t.Fatalf("шапка, называющая второе имя спецификации, объявлена находкой: %v", f)
	}
	sites, _, err = check.ScanDocHeaders("internal/x/a.go", []byte(defect))
	if err != nil {
		t.Fatalf("разбор дефекта: %v", err)
	}
	if f := docHeaderFindings(sites); len(f) != 1 {
		t.Fatalf("шапка, не называющая НИ ОДНОГО имени спецификации, находкой не стала: %v", f)
	}
}

// TestDocHeaderWalkExcludesGeneratedAndProbes — отбор гейта. Проверяется ТОТ ЖЕ
// предикат, которым судит гейт: отбор, переписанный на стороне пробы, остаётся
// зелёным, когда гейт отбирает иначе.
func TestDocHeaderWalkExcludesGeneratedAndProbes(t *testing.T) {
	for _, rel := range []string{
		"pkg/api/kaname/cloud/iam/v1/access_binding.pb.go",        // порождено генератором
		"internal/check/doc_header_names_its_declaration_test.go", // проба
		"internal/apps/kaname/config/config.yaml",                 // не Go вовсе
	} {
		if docHeaderWalkable(rel) {
			t.Errorf("отбор гейта берёт %s — предмет там не его", rel)
		}
	}
	if !docHeaderWalkable("internal/apps/kaname/config/config.go") {
		t.Fatalf("отбор гейта не берёт прод-файл — тогда осматривать нечего")
	}
}
