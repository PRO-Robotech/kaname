// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package manifest_test

// producerdelivery_test.go — ПРОБА СКВОЗЬ ОБЕ СТОРОНЫ доставки, по КАЖДОМУ
// объявившему её стенду (задачи #1901, #1909).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ОНА, КОГДА ОБЕ ПОЛОВИНЫ УЖЕ ПРОВЕРЕНЫ ПОРОЗНЬ
//
// Половин у доставки три, и каждая проверяется своим: производитель — гейтом в
// `deploy` (объект собирается, имя одно с чартом), читатель — пробами рядом
// (каталог читается, пустой отвергается), чарт — гейтом объявлений. Все три
// зелены по отдельности ровно так же и тогда, когда СТЫК между ними разорван:
// производитель кладёт ключи, которых читатель не видит, — и это в точности тот
// дефект, ради которого задача заведена.
//
// Поэтому здесь вопрос ставится сквозь обе стороны: то, что производитель
// собрал из дерева, раскладывается ТАК ЖЕ, как это делает kubelet, и читается
// ТЕМ ЖЕ кодом, которым читает старт службы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОПУЛЯЦИЯ ВЫВОДИТСЯ, А НЕ ПРИКОЛОЧЕНА К ОДНОМУ ПРОФИЛЮ — ЦЕНА ИЗМЕРЕНА
//
// Прежняя редакция этой пробы гоняла круг по ОДНОЙ константе —
// профилю стенда разработки, — и потому утверждала о стенде. Тем временем
// доставку объявили ВСЕ шесть стендов, включая боевой, и объявили её
// ОБЯЗАТЕЛЬНОЙ (`manifests.required: true`): служба, получившая сорванную
// доставку, стартовать откажется. То есть полоса, на которой отказ дороже
// всего, кругом не проверялась вовсе — и не по недосмотру, а BY CONSTRUCTION:
// её профилей проба не называла ни одним именем.
//
// Это тот же класс, что и у соседнего гейта путей выкатки (kacho#1909): предмет
// один — доставка на БОЕВУЮ площадку, — а слепы обе проверки были каждая в свою
// сторону. Там популяция уже выведена обходом дерева; здесь она выводится из
// `deploy/stacks.txt` — ЕДИНСТВЕННОГО объявления состава стендов. Цепочка ни
// одного стенда здесь не выписана: выписанная разошлась бы с таблицей молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ НЕ ПРОВЕРЯЕТСЯ — НАЗВАНО, ЧТОБЫ «ЗЕЛЕНО» НЕ ЧИТАЛОСЬ ШИРЕ СДЕЛАННОГО
//
// Единственное звено, оставшееся за пробой, — сам kubelet: раскладка тома здесь
// ВОСПРОИЗВЕДЕНА (служебные записи, ключи символьными ссылками), а не
// смонтирована. Что том объявлен и смонтирован, судит гейт объявлений чарта
// (`deploy/iam_module_manifest_delivery_test.go`); что путь выкатки кладёт
// объект перед helm — гейт путей (`iam_module_manifest_bringup_paths_test.go`).
// Здесь предмет третий и последний: доставленное СОДЕРЖИМОЕ каждой цепочки
// принимается стартовым читателем.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kacho/internal/treecorpus"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/tools/modulemanifests"
)

// stacksTablePath — единственное объявление состава стендов, от корня дерева.
const stacksTablePath = "deploy/stacks.txt"

// umbrellaProfileDir — каталог профилей умбреллы, от корня дерева.
const umbrellaProfileDir = "deploy/helm/umbrella"

// stackTableLine — строка таблицы стендов: `<имя>:<профиль>[,<профиль>…]`.
//
// Разбор обязан узнавать КАЖДУЮ непустую строку: нераспознанная — это не
// «стендов меньше», а «предикат перестал их узнавать».
var stackTableLine = regexp.MustCompile(`^([a-z0-9][a-z0-9-]*):(values[^,\s]*(?:,values[^,\s]*)*)$`)

// deliveryStack — стенд, его корень дерева и цепочка профилей.
//
// Корень носит САМ стенд, а не проба: инъекция подставляет синтетический корень
// одному стенду, не трогая ни дерева, ни остальных.
type deliveryStack struct {
	Name     string
	Root     string   // корень, из которого производитель берёт манифесты
	Profiles []string // абсолютные пути профилей, слева направо
}

// roundTripCensus — объём осмотренного. Печатается ВСЕГДА, на всяком исходе:
// без него «ноль находок» не отличается от «ноль прочитанного».
type roundTripCensus struct {
	Stacks       int // стендов в таблице
	Declaring    int // из них объявили доставку
	RoundTripped int // из них прошли круг производитель → раскладка → читатель
	Keys         int // ключей объекта суммарно
	Bytes        int // байт манифестов суммарно
	Modules      []string
}

// Summary — перепись одной строкой.
func (c roundTripCensus) Summary() string {
	return fmt.Sprintf(
		"стендов %d · объявляют доставку %d · круг прошли %d · ключей %d · байт %d · модули: %s",
		c.Stacks, c.Declaring, c.RoundTripped, c.Keys, c.Bytes,
		strings.Join(c.Modules, ", "))
}

// repoRootFromTest — корень дерева, найденный подъёмом до go.mod.
//
// Выведен, а не выписан числом «..»: количество уровней меняется вместе с
// раскладкой пакета и разошлось бы молча.
func repoRootFromTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не прочитан: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("корень дерева не найден подъёмом от %s — предпосылка пробы исчезла", dir)
		}
		dir = parent
	}
}

// deliveryStacksOfTree — популяция: КАЖДЫЙ стенд таблицы со своей цепочкой.
//
// Отказывает на непрочитанной таблице, на нераспознанной строке и на пустом
// перечне: «стендов не осталось» и «таблица не прочиталась» обязаны быть
// различимы, иначе проба объявит дерево осмотренным, не прочитав ни строки.
func deliveryStacksOfTree(t *testing.T, root string) []deliveryStack {
	t.Helper()
	table := filepath.Join(root, stacksTablePath)
	// #nosec G304 -- путь собран из корня дерева и константы.
	raw, err := os.ReadFile(table)
	if err != nil {
		t.Fatalf("таблица стендов %s не прочитана: %v — непрочитанное есть НАХОДКА, "+
			"а не «стендов нет»", stacksTablePath, err)
	}
	var out []deliveryStack
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := stackTableLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("строка таблицы стендов не разобрана: %q (%s) — это НЕ «стендов "+
				"меньше», это «предикат перестал их узнавать»", line, stacksTablePath)
		}
		s := deliveryStack{Name: m[1], Root: root}
		for _, p := range strings.Split(m[2], ",") {
			abs := filepath.Join(root, umbrellaProfileDir, p)
			if _, err := os.Stat(abs); err != nil {
				t.Fatalf("стенд %q называет профиль %s, которого нет: %v", s.Name, p, err)
			}
			s.Profiles = append(s.Profiles, abs)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		t.Fatalf("в %s нет ни одной строки стенда — проба не вправе считать, что "+
			"стендов не осталось", stacksTablePath)
	}
	return out
}

// auditDeliveryRoundTrip — круг по каждому стенду популяции.
//
// ЧИСТАЯ по отношению к дереву: работает над переданной популяцией, поэтому
// инъекция подставляет свой стенд и ничего не трогает.
//
// Стенд, доставку НЕ объявивший, находкой не является: это решение посадки
// («доставки здесь нет»), и судит его соседний гейт пары. Здесь такой стенд
// только не входит в число прошедших круг — и это видно в переписи.
func auditDeliveryRoundTrip(t *testing.T, stacks []deliveryStack) ([]string, roundTripCensus) {
	t.Helper()
	var findings []string
	census := roundTripCensus{Stacks: len(stacks)}
	modules := map[string]bool{}

	for _, s := range stacks {
		delivery, err := modulemanifests.Collect(s.Root, s.Profiles)
		if errors.Is(err, modulemanifests.ErrNotDeclared) {
			continue
		}
		census.Declaring++
		if err != nil {
			findings = append(findings, fmt.Sprintf(
				"%s: производитель не собрал объект: %v (%s)",
				s.Name, err, delivery.Census.Summary()))
			continue
		}
		rendered, err := modulemanifests.Render(delivery)
		if err != nil {
			findings = append(findings, fmt.Sprintf("%s: объект не напечатан: %v", s.Name, err))
			continue
		}
		var object struct {
			Data map[string]string `yaml:"data"`
		}
		if err := yaml.Unmarshal(rendered, &object); err != nil {
			findings = append(findings, fmt.Sprintf(
				"%s: напечатанный объект не разбирается: %v — «собрал» обязано означать "+
					"«применимо», а не «похоже»", s.Name, err))
			continue
		}
		if len(object.Data) == 0 {
			findings = append(findings, fmt.Sprintf(
				"%s: в объекте нет ни одного ключа — под смонтирует пустой каталог "+
					"доставки, а служба читает его как сорванную доставку", s.Name))
			continue
		}

		// Раскладка ТА ЖЕ, что кладёт kubelet: служебные записи тома на месте,
		// ключи — символьными ссылками. Собери проба обычные файлы — она
		// утверждала бы о раскладке, которой на стенде не бывает.
		mount := configMapMount(t, object.Data)

		report, err := manifest.LoadDelivered(mount)
		if err != nil {
			findings = append(findings, fmt.Sprintf(
				"%s: служба отвергла то, что положил производитель: %v\n"+
					"    перепись доставки: %s\n    перепись производителя: %s",
				s.Name, err, report.Summary(), delivery.Census.Summary()))
			continue
		}
		if report.ManifestsRead != len(object.Data) {
			findings = append(findings, fmt.Sprintf(
				"%s: положено ключей %d, прочитано манифестов %d — доставленный и "+
					"невидимый читателю файл есть тот самый класс, ради которого "+
					"доставка заводилась", s.Name, len(object.Data), report.ManifestsRead))
			continue
		}
		if len(report.Manifests) != report.ManifestsRead {
			findings = append(findings, fmt.Sprintf(
				"%s: разобрано %d при прочитанных %d — потребителю пришлось бы читать "+
					"каталог вторым проходом", s.Name, len(report.Manifests), report.ManifestsRead))
			continue
		}

		census.RoundTripped++
		census.Keys += len(object.Data)
		census.Bytes += delivery.Census.Bytes
		for _, m := range report.Modules() {
			modules[m] = true
		}
	}

	census.Modules = make([]string, 0, len(modules))
	for m := range modules {
		census.Modules = append(census.Modules, m)
	}
	sort.Strings(census.Modules)
	return findings, census
}

// TestEveryStackDeliversWhatTheStartupReaderAccepts — то, что положил
// производитель по цепочке КАЖДОГО стенда, служба прочитывает целиком.
func TestEveryStackDeliversWhatTheStartupReaderAccepts(t *testing.T) {
	// Вердикт, поданный из кеша `go test`, здесь недействителен: проба читает
	// файлы ВНЕ своего пакета (таблицу стендов, профили умбреллы, манифесты
	// служб), а инструмент кеширует по содержимому пакета и его импортов. Над
	// красным деревом печаталось бы `ok (cached)`.
	if msg := treecorpus.CachedVerdictRefusal(); msg != "" {
		t.Fatalf("%s — «ноль находок» стало бы свойством рабочего каталога", msg)
	}

	root := repoRootFromTest(t)
	stacks := deliveryStacksOfTree(t, root)

	findings, census := auditDeliveryRoundTrip(t, stacks)
	t.Logf("осмотрено: %s", census.Summary())

	// Предпосылка пробы: доставку объявляет хоть кто-то. Иначе круг не пройден
	// ни разу, а проба зелена — то есть утверждает о дереве ровно ничего.
	if census.Declaring == 0 {
		t.Fatalf("доставку не объявил ни один из %d стендов — вердикт беспредметен "+
			"(%s)", census.Stacks, census.Summary())
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
	if len(findings) != 0 {
		return
	}
	if census.RoundTripped != census.Declaring {
		t.Fatalf("объявили доставку %d, круг прошли %d при нуле находок — счёт "+
			"разошёлся с исходом (%s)", census.Declaring, census.RoundTripped, census.Summary())
	}
}
