// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// operator_supplied_roster_test.go — ПЕРЕЧЕНЬ ОБЯЗАТЕЛЬНЫХ КООРДИНАТ ПОЛОН
// СВОЕМУ ПРАВИЛУ: что он ОБЕЩАЕТ судить, то он и судит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#2488)
//
// `kaname-svc.requireOperatorSuppliedNames` заведён затем, чтобы отказ случился
// В УСТАНОВКЕ, а не в кластере, где он на порядок дороже: до кластера надо
// доехать, и там он приходит по одному за перекат.
//
// Он судил ЧЕТЫРЕ координаты (образ, узел базы, имя и ключ секрета пароля), а
// текст его отказа утверждал, что чарт «не заводит ни образа, ни базы, НИ
// СЕКРЕТОВ» — обобщённо. Секретов TLS, которые чарт ровно так же не создаёт и
// чьи имена он ровно так же подставляет в манифест, в перечне не было: при
// незаданных томов нет, а пути в карте переменных остаются, и процесс получает
// координату файла, которого в поде не существует.
//
// То есть перечень был ШИРЕ СВОЕГО СОДЕРЖИМОГО. Это и ловит гейт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОПУЛЯЦИЯ ВЫВОДИТСЯ, А НЕ ВЫПИСЫВАЕТСЯ
//
// Класс координаты — «имя объекта либо координата, которых чарт НЕ СОЗДАЁТ, а
// подставляет в манифест». Он находится ПОЗИЦИЕЙ в шаблоне, теми же
// производителями, что у соседних гейтов, и ни один перечень здесь не
// переписывается:
//
//	collectObjectRefs        — позиции ссылки на объект (`secretName:`,
//	                           `name:`/`key:` под `secretKeyRef:`, `name:` под
//	                           `configMap:`) плюс имена, которые чарт создаёт САМ;
//	collectImageCoordinates  — позиции координаты образа в реестре.
//
// Выписанный перечень разошёлся бы с шаблоном МОЛЧА: новая ссылка на секрет
// появляется коммитом в шаблон, перечень о ней не знает и остаётся зелёным —
// ровно так две координаты TLS и выпали.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ «СУДИМЫМ», И ПОЧЕМУ ЭТО ДВА ИЗМЕРЕНИЯ СРАЗУ
//
// Координата судима, когда перечень (а) СТЕРЕЖЁТ её условием и (б) НАЗЫВАЕТ её
// в тексте отказа. Одного мало ни с какой стороны:
//
//	условие без имени — отказ, не называющий, что задать: оператор получает
//	                    отказ установки и не знает, какой ключ дописать;
//	имя без условия   — ровно исходный дефект: текст обещает больше, чем перечень
//	                    делает, и обещание читается как исполненное.
//
// Поэтому оба множества выводятся ПОРОЗНЬ и сверяются между собой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЯЗАТЕЛЬНОСТЬ БЫВАЕТ УСЛОВНОЙ, И ЭТО РЕШЕНИЕ, А НЕ ПОСЛАБЛЕНИЕ
//
// Требовать имени секрета TLS БЕЗУСЛОВНО нельзя: посадка без TLS законна на
// стенде (её отвергает страж старта, а не рендер), и безусловный отказ запретил
// бы форму, которую дерево выбрало осознанно. Обязательность наступает от
// АНТЕЦЕДЕНТА: карта переменных называет файл под каталогом этого тома. Тогда
// координата и есть та половина пары «адрес + удостоверение», которая выглядит
// настроенной и не работает.
//
// Условная координата обязана быть судима ТЕМ ЖЕ перечнем — иначе отказ снова
// приходит в кластере.
//
// ─────────────────────────────────────────────────────────────────────────────
// САМОИСТЕЧЕНИЕ В ОБЕ СТОРОНЫ
//
// Координата класса, которой перечень не судит, — находка (перечень неполон).
// Запись перечня о координате, у которой ПОЯВИЛОСЬ умолчание, — тоже находка:
// чарт стал её заводить, и требовать её от оператора больше нечего.
package deploy_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// rosterDefine — имя шаблона, чей перечень судится.
const rosterDefine = `kaname-svc.requireOperatorSuppliedNames`

// rosterAppendRe — одна запись перечня. Читается ПЕРВЫЙ токен сообщения: именно
// его видит оператор как имя ключа.
//
// ФОРМ ЗАПИСИ ДВЕ, И ОБЕ ЗАКОННЫ — литерал и `printf`, когда текст несёт
// подставляемую величину (имя переменной, из-за которой координата стала
// обязательной). Форма, о которой распознаватель не знает, не даёт ни красного,
// ни зелёного: она молчит, и всё записанное в ней оказывается вне наблюдения.
// Обе доказаны инъекцией.
var rosterAppendRe = regexp.MustCompile(`\$missing\s*=\s*append\s+\$missing\s+(?:\(printf\s+)?"\s*([A-Za-z0-9_.]+)`)

// rosterGuardRe — условие записи: `if not .Values.image`, `if not $db.host`.
var rosterGuardRe = regexp.MustCompile(`\{\{-?\s*if\s+(.*?)-?\}\}`)

// rosterBody — тело именованного шаблона перечня, дословно.
//
// Читается ТЕЛО, а не весь файл: шапка того же файла несёт ПРОЗУ об этих же
// ключах, и распознаватель, читающий её как объявление, краснел бы на
// собственном объяснении (тот же довод, что у соседних гейтов этого каталога).
func rosterBody(t *testing.T, chartDir string) string {
	t.Helper()
	rawBytes, err := os.ReadFile(filepath.Join(chartDir, templatesDir, helpersFile))
	require.NoError(t, err, "файл именованных шаблонов не читается")
	raw := string(rawBytes)
	marker := `{{- define "` + rosterDefine + `" -}}`
	start := strings.Index(raw, marker)
	require.GreaterOrEqual(t, start, 0,
		"в %s нет объявления %s — перечня, о котором этот гейт, в дереве не существует",
		helpersFile, rosterDefine)
	rest := raw[start+len(marker):]
	// Границей служит СЛЕДУЮЩЕЕ объявление, а не первый `{{- end -}}`: тело
	// перечня само состоит из условных блоков, и обрыв на первом закрытии дал бы
	// одну запись из четырёх — то есть гейт судил бы кусок перечня, отчитываясь
	// про весь. Первая редакция этого файла так и сделала, и перепись сказала об
	// этом числом: «стережёт 1, называет 1» при четырёх записях в дереве.
	if end := strings.Index(rest, `{{- define "`); end >= 0 {
		rest = rest[:end]
	}
	require.Contains(t, rest, `{{- end -}}`, "тело %s не закрыто — читать нечего", rosterDefine)
	return rest
}

// rosterJudged — что перечень СТЕРЕЖЁТ (условиями) и что НАЗЫВАЕТ (текстами).
//
// Пути приводятся к форме дерева значений с учётом псевдонимов тела, иначе
// `$db.host` читался бы как отдельный корень и не сходился бы с `db.host`.
func rosterJudged(body string) (guarded, named map[string]bool) {
	guarded, named = map[string]bool{}, map[string]bool{}
	aliases := templateAliases(body)
	for _, m := range rosterGuardRe.FindAllStringSubmatch(body, -1) {
		for _, p := range resolveRefs(m[1], aliases) {
			guarded[p] = true
		}
	}
	for _, m := range rosterAppendRe.FindAllStringSubmatch(body, -1) {
		named[m[1]] = true
	}
	return guarded, named
}

// foreignCoordinateClass — координаты класса «чарт их НЕ создаёт, а подставляет
// в манифест», выведенные позицией в шаблонах.
func foreignCoordinateClass(t *testing.T, chartDir string) (paths []string, positions int) {
	t.Helper()

	created := map[string]bool{}
	refs, _, _, createdExprs := collectObjectRefs(t)
	values, err := readChartValues(filepath.Join(chartDir, chartDefaultsFile))
	require.NoError(t, err, "базовые значения чарта не читаются")
	for _, expr := range createdExprs {
		created[renderNameExpr(t, values, chartDefaultsFile, expr)] = true
	}

	seen := map[string]bool{}
	for _, r := range refs {
		positions++
		if r.path == "" {
			continue
		}
		// Ссылка на объект, который чарт СОЗДАЁТ САМ, стоит в такой же позиции и
		// нарушением не является: у неё непустое умолчание, и оно попадает в
		// множество созданных имён.
		if leaf, ok := leafAt(values, r.path); ok {
			if s, isStr := leaf.(string); isStr && created[renderNameExpr(t, values, chartDefaultsFile, s)] {
				continue
			}
		}
		seen[r.path] = true
	}

	coords, _, _, err := collectImageCoordinates(chartDir)
	require.NoError(t, err, "координаты образа не читаются")
	for _, c := range coords {
		positions++
		if c.path != "" {
			seen[c.path] = true
		}
	}

	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, positions
}

// judgeOperatorSuppliedRoster — ЧИСТОЕ ТЕЛО ВЕРДИКТА. Вынесено ради инъекции:
// доказать способность гейта упасть можно только подачей ему перечня, из
// которого координата выпала, а такого перечня в дереве быть не должно.
func judgeOperatorSuppliedRoster(class, guarded, named, emptyDefault map[string]bool) []string {
	findings := []string{}
	keys := make([]string, 0, len(class))
	for p := range class {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, p := range keys {
		// Координата с НЕПУСТЫМ умолчанием оператору не адресована: чарт её
		// заводит сам, и требовать её было бы запретом на собственное умолчание.
		if !emptyDefault[p] {
			continue
		}
		if !guarded[p] {
			findings = append(findings, "  "+p+" — координата, которой чарт НЕ ЗАВОДИТ и которую "+
				"подставляет в манифест, а перечень отказа её не стережёт: при незаданной установка "+
				"пройдёт, объект создастся с пустой величиной, и отказ придёт уже в кластере — где он "+
				"на порядок дороже и не называет, чего не хватило. Добавьте её в "+rosterDefine+
				" (безусловно либо под антецедентом, если полоса необязательна).")
			continue
		}
		if !named[p] {
			findings = append(findings, "  "+p+" — перечень стережёт координату УСЛОВИЕМ, но не "+
				"НАЗЫВАЕТ её в тексте отказа: оператор получает отказ установки и не знает, какой ключ "+
				"дописать. Отказ обязан называть ключ профиля, путь подачи и что сделать дальше.")
		}
	}
	// САМОИСТЕЧЕНИЕ: перечень называет то, чему предмета больше нет.
	namedKeys := make([]string, 0, len(named))
	for p := range named {
		namedKeys = append(namedKeys, p)
	}
	sort.Strings(namedKeys)
	for _, p := range namedKeys {
		if class[p] {
			continue
		}
		findings = append(findings, "  "+p+" — перечень называет координату, которой в классе больше "+
			"нет: чарт либо перестал её подставлять, либо начал заводить сам. Запись пережила свой "+
			"предмет — снимите её тем же изменением, которым снята обязательность.")
	}
	return findings
}

// TestOperatorSuppliedRosterIsCompleteToItsOwnRule — несущая проба.
func TestOperatorSuppliedRosterIsCompleteToItsOwnRule(t *testing.T) {
	chartDir := filepath.Join(serviceRoot(t), "deploy")

	classPaths, positions := foreignCoordinateClass(t, chartDir)
	guarded, named := rosterJudged(rosterBody(t, chartDir))

	values, err := readChartValues(filepath.Join(chartDir, chartDefaultsFile))
	require.NoError(t, err, "базовые значения чарта не читаются")
	empty := map[string]bool{}
	for _, p := range emptyStringDefaults(values) {
		empty[p] = true
	}

	class := map[string]bool{}
	obligatory := 0
	for _, p := range classPaths {
		class[p] = true
		if empty[p] {
			obligatory++
		}
	}
	// Перечень судит и то, что классом позиций не опознаётся (узел базы — не
	// объект Kubernetes, а сетевое имя). Такие координаты входят в класс, ТОЛЬКО
	// пока ключ ЖИВ в дереве значений чарта: иначе самоистечение выродилось бы в
	// ничто — запись сама себя вносила бы в класс и никогда бы не протухала.
	for p := range named {
		if class[p] {
			continue
		}
		if _, alive := leafAt(values, p); !alive {
			continue // ключа в чарте больше нет — пусть вердикт назовёт запись протухшей
		}
		class[p] = true
		if empty[p] {
			obligatory++
		}
	}

	// «Ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.NotZero(t, positions, "обход пуст: позиций ссылки на объект и образ 0 — вердикт беспредметен")
	require.NotEmpty(t, classPaths, "обход пуст: координат класса 0 — судить нечего")
	require.NotEmpty(t, named, "обход пуст: перечень не называет ни одной координаты — читать нечего")

	findings := judgeOperatorSuppliedRoster(class, guarded, named, empty)

	classNames := make([]string, 0, len(class))
	for p := range class {
		if empty[p] {
			classNames = append(classNames, p)
		}
	}
	sort.Strings(classNames)
	t.Logf("перепись: позиций осмотрено %d · координат класса %d · из них без умолчания (обязательных) %d (%s) · "+
		"судимых перечнем: стережёт %d, называет %d · находок %d",
		positions, len(class), obligatory, strings.Join(classNames, ", "),
		len(guarded), len(named), len(findings))

	require.Empty(t, findings,
		"перечень обязательных координат не полон своему правилу:\n%s", strings.Join(findings, "\n"))
}
