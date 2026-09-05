// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// Форма идентификатора в контракте iam обязана совпадать с той, которую продукт
// ЧЕКАНИТ.
//
// # ПРЕДМЕТ
//
// Платформа производит идентификаторы ТРЕМЯ разными построениями, и они дают три
// разных написания одного и того же:
//
//	ids.NewID(p)         → "<p><17>"    — слитная форма, разделителя нет
//	ids.NewHyphenID(p)   → "<p>-<17>"   — дефис (going-forward канон, B3)
//	domain.NewKac127ID(p)→ "<p>_<17>"   — подчёркивание (живёт у одного префикса)
//
// Контракт показывает клиенту ПРИМЕР значения, и пример — это исполняемое
// утверждение: по нему строят валидатор и его подставляют в фильтр. Пример
// в форме, которой продукт не чеканит, наблюдаем НИЧЕМ: фильтр сравнивает строку
// на равенство, поэтому клиент получает `200` и пустую страницу — уверенный
// неверный ответ без кода, без текста и без признака, по которому его отличить от
// настоящего пустого результата.
//
// # ПОЧЕМУ ЭТО ГЕЙТ, А НЕ ОДНОРАЗОВАЯ ПРАВКА
//
// Выписанный перечень форм разошёлся бы с деревом молча: каждый сервис мигрирует
// свой префикс на дефисную генерацию в собственном редизайне, и в день миграции
// верным становится ДРУГОЕ написание. Поэтому здесь не перечень написаний, а
// таблица «префикс → построение», у каждой строки которой ДВА производителя:
//
//   - форма доказывается ИСПОЛНЕНИЕМ — генератор зовётся и его вывод читается;
//   - живость строки доказывается ПОИСКОМ места чеканки в непробном дереве.
//
// Мигрирует сервис префикс — исчезает место чеканки, строка теряет производителя
// и падает здесь, а не молча переживает свой предмет.
//
// # ГРАНИЦА
//
// Гейт судит ФОРМУ, а не СМЫСЛ. Пример, назвавший префикс операции там, где
// нужен префикс ресурса, он пропустит: разделитель у обоих одинаков, а какой
// именно ресурс имелся в виду, из текста не выводится. Такой пример в этом
// контракте был и найден чтением, а не гейтом. Документацию он не читает вовсе —
// её ведёт своя полоса; предмет здесь только контракт.

// idMintForm — построение, которым чеканится идентификатор префикса.
type idMintForm int

const (
	mintConcatenated idMintForm = iota // ids.NewID        → "<p><body>"
	mintHyphen                         // ids.NewHyphenID  → "<p>-<body>"
	mintUnderscore                     // NewKac127ID      → "<p>_<body>"
	mintHyphenSQL                      // SQL-функция      → "<p>-<body>"
)

func (f idMintForm) separator() string {
	switch f {
	case mintHyphen, mintHyphenSQL:
		return "-"
	case mintUnderscore:
		return "_"
	default:
		return ""
	}
}

// mintedPrefix — одна строка таблицы: префикс, его построение и МЕСТО ЧЕКАНКИ.
//
// `producer` — литерал, который обязан встретиться в непробном дереве. Это и есть
// предикат живости строки: снимут чеканку — строка покраснеет.
type mintedPrefix struct {
	prefix   string
	form     idMintForm
	producer string
	// producerRoots — где искать производителя (относительно корня монорепо).
	producerRoots []string
}

// mintedPrefixes — ЕДИНСТВЕННАЯ таблица форм для префиксов, которые встречаются
// в контракте iam. Префикс, найденный в контракте и отсутствующий здесь, —
// находка, а не умолчание: у его формы нет сверенного производителя.
var mintedPrefixes = []mintedPrefix{
	{"acc", mintConcatenated, "ids.NewID(domain.PrefixAccount)", []string{"services/iam"}},
	{"prj", mintConcatenated, "ids.NewID(domain.PrefixProject)", []string{"services/iam"}},
	{"usr", mintConcatenated, "ids.NewID(domain.PrefixUser)", []string{"services/iam"}},
	{"sva", mintConcatenated, "ids.NewID(domain.PrefixServiceAccount)", []string{"services/iam"}},
	{"grp", mintConcatenated, "ids.NewID(domain.PrefixGroup)", []string{"services/iam"}},
	{"rol", mintConcatenated, "ids.NewID(domain.PrefixRole)", []string{"services/iam"}},
	{"acb", mintConcatenated, "ids.NewID(domain.PrefixAccessBinding)", []string{"services/iam"}},
	{"uoc", mintConcatenated, "ids.NewID(domain.PrefixUserOAuthClient)", []string{"services/iam"}},
	{"soc", mintConcatenated, "ids.NewID(domain.PrefixSAOAuthClient)", []string{"services/iam"}},
	{"iop", mintConcatenated, "domain.PrefixOperationIAM", []string{"services/iam"}},
	{"cag", mintUnderscore, "domain.NewKac127ID(domain.PrefixClusterAdminGrant)", []string{"services/iam"}},
	{"lim", mintHyphen, "ids.NewHyphenID(ids.PrefixLimitHyphen)", []string{"services/iam"}},
	{"ic", mintHyphen, "ids.NewHyphenID(ids.PrefixInteractiveClientHyphen)", []string{"services/iam"}},
	{"mbr", mintHyphenSQL, "'mbr-' || substr", []string{"services/iam/internal/migrations"}},
	// Чужие домены, чьи идентификаторы контракт iam приводит в примерах.
	{"net", mintConcatenated, "ids.NewID(ids.PrefixNetwork)", []string{"services/vpc"}},
	{"enp", mintConcatenated, "ids.PrefixOperationVPC", []string{"services/vpc"}},
	{"reg", mintConcatenated, "ids.NewID(ids.PrefixRegistry)", []string{"services/registry"}},
}

// legacyAcceptedForm — написание, которое продукт БОЛЬШЕ НЕ ЧЕКАНИТ, но всё ещё
// ПРИНИМАЕТ у существующих строк. Контракт вправе его называть — но только пока
// у послабления есть предмет: `acceptor` обязан встретиться в миграциях.
// Ужесточат проверку — запись потеряет предмет и упадёт здесь.
type legacyAcceptedForm struct {
	prefix   string
	sep      string
	acceptor string
}

var legacyAcceptedForms = []legacyAcceptedForm{
	{"soc", "_", "'^soc_?[0-9a-hjkmnp-tv-z]{17}$'"},
	{"uoc", "_", "'^uoc_?[0-9a-hjkmnp-tv-z]{17}$'"},
}

const iamContractDir = "proto/kacho/cloud/iam/v1"

// TestMintedFormsAreProvenByExecution — форма каждой строки таблицы доказывается
// ВЫЗОВОМ генератора, а не объявлением рядом с ним.
func TestMintedFormsAreProvenByExecution(t *testing.T) {
	checked := 0
	for _, m := range mintedPrefixes {
		var got string
		switch m.form {
		case mintConcatenated:
			got = ids.NewID(m.prefix)
		case mintHyphen:
			got = ids.NewHyphenID(m.prefix)
		case mintUnderscore:
			got = domain.NewKac127ID(m.prefix)
		case mintHyphenSQL:
			// SQL-чеканку исполнить нельзя без базы; её форма доказывается
			// литералом производителя (см. соседний тест).
			continue
		}
		want := m.prefix + m.form.separator()
		require.Truef(t, strings.HasPrefix(got, want),
			"префикс %q: генератор дал %q, а таблица объявляет форму %q", m.prefix, got, want+"…")
		// Обратная сторона: у слитной формы разделителя быть НЕ должно.
		if m.form == mintConcatenated {
			rest := got[len(m.prefix):]
			require.NotContains(t, rest, "-", "префикс %q: слитная форма не несёт дефиса, получено %q", m.prefix, got)
			require.NotContains(t, rest, "_", "префикс %q: слитная форма не несёт подчёркивания, получено %q", m.prefix, got)
		}
		checked++
	}
	require.NotZero(t, checked, "исполнением не проверена ни одна форма — обход беспредметен")
	t.Logf("перепись: строк таблицы %d · форм доказано исполнением %d", len(mintedPrefixes), checked)
}

// TestEveryMintedPrefixStillHasAProducer — у каждой строки таблицы есть МЕСТО
// ЧЕКАНКИ в непробном дереве. Без этого таблица переживает свой предмет.
func TestEveryMintedPrefixStillHasAProducer(t *testing.T) {
	root := monorepoRoot(t)
	orphans, filesRead := prefixesWithoutAProducer(t, root, mintedPrefixes)
	require.NotZero(t, filesRead, "обход пуст — вердикт беспредметен")
	t.Logf("перепись: строк таблицы %d · прочитано файлов %d · без производителя %d",
		len(mintedPrefixes), filesRead, len(orphans))
	require.Emptyf(t, orphans,
		"у строк таблицы нет места чеканки в непробном дереве — они пережили свой предмет:\n%s",
		strings.Join(orphans, "\n"))
}

// prefixesWithoutAProducer — строки таблицы, чьего места чеканки в дереве нет.
func prefixesWithoutAProducer(t *testing.T, root string, rows []mintedPrefix) ([]string, int) {
	t.Helper()
	var orphans []string
	filesRead := 0
	for _, m := range rows {
		found := false
		for _, sub := range m.producerRoots {
			n, hit := grepTree(t, filepath.Join(root, sub), m.producer)
			filesRead += n
			if hit {
				found = true
				break
			}
		}
		if !found {
			orphans = append(orphans, fmt.Sprintf("префикс %q: места чеканки %q нет", m.prefix, m.producer))
		}
	}
	return orphans, filesRead
}

// TestLegacyAcceptedFormsStillHaveASubject — послабление живёт, пока есть, что
// прощать.
func TestLegacyAcceptedFormsStillHaveASubject(t *testing.T) {
	root := monorepoRoot(t)
	expired, filesRead := legacyFormsWithoutASubject(t, root, legacyAcceptedForms)
	require.NotZero(t, filesRead, "обход миграций пуст — вердикт беспредметен")
	t.Logf("перепись: послаблений %d · прочитано файлов миграций %d · без предмета %d",
		len(legacyAcceptedForms), filesRead, len(expired))
	require.Emptyf(t, expired,
		"послаблению нечего исключать — принимающей проверки в миграциях больше нет:\n%s",
		strings.Join(expired, "\n"))
}

// legacyFormsWithoutASubject — записи послаблений, чей принимающий предикат исчез.
func legacyFormsWithoutASubject(t *testing.T, root string, rows []legacyAcceptedForm) ([]string, int) {
	t.Helper()
	migrations := filepath.Join(root, "services", "iam", "internal", "migrations")
	var expired []string
	filesRead := 0
	for _, l := range rows {
		n, hit := grepTree(t, migrations, l.acceptor)
		filesRead += n
		if !hit {
			expired = append(expired, fmt.Sprintf("послабление %q%q: проверки %s нет", l.prefix, l.sep, l.acceptor))
		}
	}
	return expired, filesRead
}

// TestContractIdFormMatchesWhatTheProductMints — несущее утверждение.
func TestContractIdFormMatchesWhatTheProductMints(t *testing.T) {
	root := monorepoRoot(t)
	dir := filepath.Join(root, iamContractDir)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	filesRead, examples := 0, 0
	var findings []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".proto") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- путь собран из корня собственного модуля
		require.NoError(t, err)
		filesRead++
		for _, ex := range scanIDExamples(string(raw)) {
			examples++
			if msg := judgeExample(ex); msg != "" {
				findings = append(findings, fmt.Sprintf("%s:%d: %s", e.Name(), ex.line, msg))
			}
		}
	}
	require.NotZero(t, filesRead, "контракт iam не прочитан — вердикт беспредметен")
	require.NotZero(t, examples, "ни одного примера идентификатора не распознано — распознаватель ослеп")

	sort.Strings(findings)
	t.Logf("перепись: файлов контракта %d · примеров идентификатора распознано %d · расхождений %d",
		filesRead, examples, len(findings))
	require.Emptyf(t, findings,
		"форма идентификатора в контракте расходится с чеканкой:\n%s", strings.Join(findings, "\n"))
}

// judgeExample — вердикт по одному распознанному примеру. Пустая строка = сходится.
func judgeExample(ex idExample) string {
	for _, l := range legacyAcceptedForms {
		if l.prefix == ex.prefix && l.sep == ex.sep {
			return ""
		}
	}
	for _, m := range mintedPrefixes {
		if m.prefix != ex.prefix {
			continue
		}
		if ex.sep == m.form.separator() {
			return ""
		}
		return fmt.Sprintf("%q — префикс %q чеканится в форме %q, разделитель %q не производится ничем",
			ex.raw, ex.prefix, ex.prefix+m.form.separator()+"…", ex.sep)
	}
	return fmt.Sprintf("%q — префикс %q не назван в таблице форм: сверить его чеканку не с чем",
		ex.raw, ex.prefix)
}

// idExample — распознанный пример идентификатора в тексте контракта.
type idExample struct {
	prefix string
	sep    string // "", "-" или "_"
	raw    string
	line   int
}

// scanIDExamples — распознаватель. Он знает ВСЕ написания, которыми этот корпус
// приводит пример идентификатора, и каждое доказано инъекцией
// (contract_id_form_injection_test.go):
//
//	acc…            — многоточие, слитно
//	usr-…           — многоточие, дефис
//	usr_xxx         — «xxx», подчёркивание
//	mbr-<17>        — угловая скобка с цифрой в теле
//	soc<17-crockford> — то же слитно
//	soc_<body>      — угловая скобка со словом `body`
//	^usr_[0-9a-hjkmnp-tv-z]{17}$ — регулярное выражение
//	// Resource id prefix: `acc-`. — ОБЪЯВЛЕНИЕ, тела у него нет вовсе
//
// Написаний ДВА ВИДА, и второй нельзя вывести из первого. В примере ищется ТЕЛО,
// а от него распознаватель идёт назад к разделителю и префиксу: поиск от
// префикса дал бы находки внутри обычных слов, а тело в этом корпусе пишется
// закрытым набором способов. У объявления тела нет — оно распознаётся своей
// приметой, и без этой ветви семь объявлений формы остались бы вне наблюдения.
func scanIDExamples(text string) []idExample {
	out := scanIDDeclarations(text)
	bodies := []string{"…", "xxx", "[0-9a-hjkmnp-tv-z]"}
	for i := 0; i < len(text); i++ {
		body := ""
		for _, b := range bodies {
			if strings.HasPrefix(text[i:], b) {
				body = b
				break
			}
		}
		if body == "" && text[i] == '<' {
			if end := strings.IndexByte(text[i:], '>'); end > 0 {
				inner := text[i+1 : i+end]
				if isBodyPlaceholder(inner) {
					body = text[i : i+end+1]
				}
			}
		}
		if body == "" {
			continue
		}
		j := i
		sep := ""
		if j > 0 && (text[j-1] == '-' || text[j-1] == '_') {
			sep = string(text[j-1])
			j--
		}
		k := j
		for k > 0 && text[k-1] >= 'a' && text[k-1] <= 'z' {
			k--
		}
		run := text[k:j]
		if len(run) < 2 || len(run) > 4 {
			continue
		}
		out = append(out, idExample{
			prefix: run,
			sep:    sep,
			raw:    run + sep + body,
			line:   1 + strings.Count(text[:k], "\n"),
		})
	}
	return out
}

// idPrefixDeclaration — примета объявления формы в шапке сообщения ресурса.
const idPrefixDeclaration = "Resource id prefix: `"

// scanIDDeclarations — вторая ветвь распознавателя: объявление формы, у которого
// ТЕЛА нет. Разбирается дословной приметой, а не телом.
func scanIDDeclarations(text string) []idExample {
	var out []idExample
	for i := 0; ; {
		k := strings.Index(text[i:], idPrefixDeclaration)
		if k < 0 {
			return out
		}
		start := i + k + len(idPrefixDeclaration)
		end := strings.IndexByte(text[start:], '`')
		if end < 0 {
			return out
		}
		token := text[start : start+end]
		i = start + end
		sep := ""
		if n := len(token); n > 0 && (token[n-1] == '-' || token[n-1] == '_') {
			sep = string(token[n-1])
			token = token[:n-1]
		}
		if len(token) < 2 || len(token) > 4 {
			continue
		}
		ok := true
		for j := 0; j < len(token); j++ {
			if token[j] < 'a' || token[j] > 'z' {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		out = append(out, idExample{
			prefix: token,
			sep:    sep,
			raw:    idPrefixDeclaration + token + sep + "`",
			line:   1 + strings.Count(text[:start], "\n"),
		})
	}
}

// isBodyPlaceholder — содержимое `<…>` есть ТЕЛО идентификатора, а не обычная
// угловая скобка контракта (`map<string, string>`): либо в нём есть цифра
// (`17`, `17-crockford`), либо это дословно `body`.
func isBodyPlaceholder(s string) bool {
	if s == "body" {
		return true
	}
	if s == "" {
		return false
	}
	digit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z', c == '-':
		default:
			return false
		}
	}
	return digit
}

// grepTree — сколько файлов прочитано и встретился ли литерал в непробном дереве.
//
// Состав берётся у ИНДЕКСА (`pkg/treecorpus`), а не обходом диска: правила
// игнорирования действуют на любой глубине, и под `services/` на всякой машине,
// где поднимали стенд, лежит неотслеживаемое — рабочие копии агентов,
// распаковки чартов, отчёты прогонов. Обход диска сделал бы вердикт свойством
// рабочего каталога, а не коммита; пустой корпус там же становится отказом, а
// не тихим «ноль находок».
func grepTree(t *testing.T, root, literal string) (int, bool) {
	t.Helper()
	paths, err := treecorpus.UnderWithSuffix(root, ".go", ".sql")
	require.NoError(t, err)
	filesRead, found := 0, false
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		raw, readErr := os.ReadFile(path) // #nosec G304 -- путь получен из индекса собственного дерева
		require.NoError(t, readErr)
		filesRead++
		if strings.Contains(string(raw), literal) {
			found = true
		}
	}
	return filesRead, found
}
