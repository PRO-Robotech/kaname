// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package clagate — вклад стороннего автора не попадает в дерево без
// подтверждённого соглашения о вкладе.
//
// Что здесь на кону. Продукт выходит под AGPL-3.0-or-later, и владелец
// сохраняет за собой возможность выдать его же на других условиях (двойное
// лицензирование). Возможность эта держится ровно на одном: у правообладателя
// есть право выдавать лицензии на ВЕСЬ код, включая чужие вклады. Первый же
// сторонний вклад без соглашения эту возможность закрывает — и закрывает
// НЕОБРАТИМО: вернуться можно только собрав подпись каждого стороннего автора
// поимённо, а найти их через год некому и не по чему.
//
// Класс, который здесь закрывается, тем и живуч, что не производит симптома.
// Вклад принят, сборка зелёная, продукт работает; неверным становится
// утверждение о правах, а его никто не прогоняет. Заметить это можно только в
// тот день, когда лицензию решат сменить, — то есть тогда, когда чинить уже
// нечем.
//
// ЧТО СЧИТАЕТСЯ ВКЛАДОМ — две формы, и обе под наблюдением: автор коммита и
// соавтор, названный трейлером `Co-authored-by`. Гейт, знающий только первую,
// вторую не отвергает и не принимает — он её НЕ ВИДИТ, а вклад существует.
// Коммиттер намеренно не считается вкладчиком: тот, кто перенёс или влил чужой
// коммит, содержимого не создавал.
//
// ЧТО СЧИТАЕТСЯ ПОДТВЕРЖДЕНИЕМ — тоже две формы: подпись в завершающем блоке
// трейлеров (`Signed-off-by`, ключ регистронезависим) и явная запись в
// ведомости `cla-ledger.yaml` для тех, кто принял соглашение вне коммита.
// Подпись засчитывается ТОЛЬКО своей личности: «в сообщении есть Signed-off-by»
// и «вкладчик подтвердил соглашение» — разные утверждения, и подписаться за
// другого нельзя.
//
// Гейт проверяет СВОЮ предпосылку. Он обоснован тем, что объявленная область
// существует в дереве и имеет историю: область, названная мимо дерева, даёт
// пустой обход — ноль коммитов, ноль находок и вид исправной работы. Поэтому
// объём осмотренного объявляется отдельным числом: «ноль находок» обязано быть
// отличимо от «ноль прочитанного».
//
// Чего гейт НЕ делает и делать не может: он не устанавливает юридическую
// действительность соглашения и не проверяет, что подписавший имел право
// подписывать. Его предмет — что подтверждение ЕСТЬ и относится к тому, кто
// вложил.
package clagate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// Entry — одна личность в ведомости.
type Entry struct {
	// Email — личность вкладчика. Единица счёта здесь адрес, а не имя: имя у
	// одного человека пишется по-разному (в истории домена один автор
	// представлен двумя написаниями имени при одном адресе), поэтому предикат
	// по имени мерил бы соглашение об именовании, а не личность.
	Email string `yaml:"email"`
	// Note — зачем эта запись здесь. Пустая причина записью не считается:
	// «не спрашиваем» без основания и есть тот дефект, который гейт ищет.
	Note string `yaml:"note"`
}

// Ledger — ведомость: кто свой, кто подтвердил соглашение вне коммита и чья
// личность освобождена от вопроса.
type Ledger struct {
	// Scope — пути, чьи коммиты судятся. В монорепо это каталог продукта; в
	// вынесенном репозитории — корень. Поле есть именно поэтому: без него гейт
	// пришлось бы править при выносе.
	Scope []string `yaml:"scope"`
	// Owners — личности правообладателя. Соглашение к ним не применяется:
	// нельзя заключить его с самим собой.
	Owners []Entry `yaml:"owners"`
	// Signatories — сторонние авторы, принявшие соглашение вне коммита
	// (подписанный документ, запись в задаче). Note называет, чем и когда.
	Signatories []Entry `yaml:"signatories"`
	// Waivers — машинные личности, чей вклад авторским произведением не
	// является (обновление версий зависимостей). Note называет, почему.
	Waivers []Entry `yaml:"waivers"`
}

// Finding — один вклад без подтверждения соглашения.
type Finding struct {
	Commit   string
	Identity string
	Form     string // чем внесён вклад: автор либо соавтор
	Why      string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: %s (%s) — %s", short(f.Commit), f.Identity, f.Form, f.Why)
}

// Report — итог обхода: и находки, и перепись осмотренного.
type Report struct {
	LedgerPath             string
	Scope                  []string
	RevRange               string
	CommitsExamined        int
	ContributionsInspected int // пар «коммит × личность»
	IdentitiesSeen         int // различных адресов
	ByOwners               int
	ConfirmedBySignOff     int
	ConfirmedByLedger      int
	Waived                 int
	Findings               []Finding
	UnusedEntries          []string
	PremiseFailures        []string
}

// Summary — находки в ОГРАНИЧЕННОМ по объёму виде, годном для текста отказа.
//
// Заведено инъекцией, а не предусмотрено: на синтетике находка была одна, и
// отказ читался; на живом дереве снятие своей личности из ведомости дало 928
// находок разом, и вывод пробы схлопнулся В ПУСТОТУ — гейт краснел, не называя
// НИЧЕГО. Находка, не называющая координаты, посылает читателя искать не там, а
// потом её снимают как непонятную; поэтому объём отказа ограничен, а остаток
// назван числом, а не отброшен молча.
func (r Report) Summary(limit int) string {
	if len(r.Findings) == 0 {
		return "находок нет"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "находок %d", len(r.Findings))
	if len(r.Findings) > limit {
		fmt.Fprintf(&b, " (ниже первые %d)", limit)
	}
	for i, f := range r.Findings {
		if i >= limit {
			break
		}
		fmt.Fprintf(&b, "\n  %s", f)
	}
	// Личности важнее отдельных коммитов: подтверждение собирается с ЧЕЛОВЕКА,
	// а не с коммита, поэтому в отказе они названы целиком.
	ids := map[string]int{}
	for _, f := range r.Findings {
		ids[f.Identity]++
	}
	names := make([]string, 0, len(ids))
	for id := range ids {
		names = append(names, id)
	}
	sort.Strings(names)
	fmt.Fprintf(&b, "\n  личностей без подтверждения: %d", len(names))
	for _, n := range names {
		fmt.Fprintf(&b, "\n    %s — вкладов %d", n, ids[n])
	}
	return b.String()
}

const (
	formAuthor   = "автор коммита"
	formCoAuthor = "соавтор в трейлере"
)

// Inspect судит историю объявленной области в диапазоне revRange.
//
// ledgerRel — путь к ведомости ОТНОСИТЕЛЬНО repoRoot. Отсутствие ведомости —
// отказ, а не пустая ведомость: молчаливое умолчание здесь означало бы либо
// «своих нет, всё находки», либо «все свои», и ни то ни другое не выводится.
func Inspect(repoRoot, ledgerRel, revRange string) (Report, error) {
	rep := Report{LedgerPath: ledgerRel, RevRange: revRange}

	// Путь ведомости сводится ПОД КОРЕНЬ судимого дерева. Без этого единственным,
	// что удерживало чтение внутри дерева, была добросовестность вызывающего:
	// `ledgerRel` приезжает строкой, а `..` в ней уводит чтение за корень. Гейт,
	// прочитавший документ снаружи, выносит вердикт о дереве по ведомости, которой
	// в этом дереве нет, — и вердикт выглядит обычным.
	root := filepath.Clean(repoRoot)
	ledgerAbs := filepath.Join(root, ledgerRel)
	inside, rerr := filepath.Rel(root, ledgerAbs)
	if rerr != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return rep, fmt.Errorf("ведомость %s лежит вне судимого дерева %s: "+
			"читать за корнем гейт не станет", ledgerRel, repoRoot)
	}
	// #nosec G304 -- путь сведён под корень судимого дерева проверкой строкой выше:
	// всё, что `filepath.Rel` относит за пределы root, отвергается до чтения.
	raw, err := os.ReadFile(ledgerAbs)
	if err != nil {
		return rep, fmt.Errorf("ведомость %s не прочитана: %w", ledgerRel, err)
	}
	var ledger Ledger
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	// Неизвестный ключ — отказ, а не тишина: ключ, который ведомость объявляет,
	// а гейт не читает, есть принятое-и-проигнорированное.
	dec.KnownFields(true)
	if err := dec.Decode(&ledger); err != nil {
		return rep, fmt.Errorf("ведомость %s не разобрана: %w", ledgerRel, err)
	}
	rep.Scope = ledger.Scope

	owners, ownerFails := index(ledger.Owners, "owners")
	signatories, signFails := index(ledger.Signatories, "signatories")
	waivers, waiverFails := index(ledger.Waivers, "waivers")
	rep.PremiseFailures = append(rep.PremiseFailures, ownerFails...)
	rep.PremiseFailures = append(rep.PremiseFailures, signFails...)
	rep.PremiseFailures = append(rep.PremiseFailures, waiverFails...)

	if len(owners) == 0 {
		rep.PremiseFailures = append(rep.PremiseFailures,
			"ведомость не называет ни одной своей личности: различать своего и стороннего станет нечем")
	}
	if len(ledger.Scope) == 0 {
		rep.PremiseFailures = append(rep.PremiseFailures,
			"ведомость не называет области: обход будет пуст, а вердикт беспредметен")
	}
	for _, p := range ledger.Scope {
		if _, err := os.Stat(filepath.Join(repoRoot, p)); err != nil {
			rep.PremiseFailures = append(rep.PremiseFailures, fmt.Sprintf(
				"область %q в дереве не разрешается: обход будет пуст, ноль находок станет неотличим от чистого дерева", p))
		}
	}

	commits, err := gitLog(repoRoot, revRange, ledger.Scope)
	if err != nil {
		return rep, err
	}
	rep.CommitsExamined = len(commits)

	// Полная история области — отдельный вопрос от заданного диапазона. Узкий
	// диапазон законно бывает пустым (изменение области не касалось); пустая
	// ПОЛНАЯ история означает, что область объявлена мимо дерева, и это уже
	// слепота.
	if len(ledger.Scope) > 0 {
		all, err := gitLog(repoRoot, "HEAD", ledger.Scope)
		if err != nil {
			return rep, err
		}
		if len(all) == 0 {
			rep.PremiseFailures = append(rep.PremiseFailures, fmt.Sprintf(
				"у объявленных областей %v нет ни одного коммита во всей истории: гейт слеп", ledger.Scope))
		}
	}

	seen := map[string]bool{}
	used := map[string]bool{}
	for _, c := range commits {
		signOffs := trailerEmails(c.body, "signed-off-by")
		for _, contrib := range contributors(c) {
			rep.ContributionsInspected++
			seen[contrib.email] = true

			switch {
			case owners[contrib.email] != nil:
				rep.ByOwners++
			case waivers[contrib.email] != nil:
				rep.Waived++
				used[contrib.email] = true
			case signatories[contrib.email] != nil:
				rep.ConfirmedByLedger++
				used[contrib.email] = true
			case signOffs[contrib.email]:
				rep.ConfirmedBySignOff++
			default:
				rep.Findings = append(rep.Findings, Finding{
					Commit:   c.sha,
					Identity: fmt.Sprintf("%s <%s>", contrib.name, contrib.email),
					Form:     contrib.form,
					Why:      "вклад стороннего автора без подтверждения соглашения о вкладе",
				})
			}
		}
	}
	rep.IdentitiesSeen = len(seen)

	// Послабление живёт, пока у него есть предмет. Своих личностей это не
	// касается: они объявлены политикой, а не освобождением от вопроса, и их
	// молчание в узком диапазоне — норма.
	for _, group := range []struct {
		name    string
		entries []Entry
	}{{"signatories", ledger.Signatories}, {"waivers", ledger.Waivers}} {
		for _, e := range group.entries {
			email := norm(e.Email)
			if email == "" || used[email] {
				continue
			}
			rep.UnusedEntries = append(rep.UnusedEntries, fmt.Sprintf(
				"%s: %s — записи больше нечего покрывать; снимите её, иначе она молча покроет следующего с этим адресом",
				group.name, e.Email))
		}
	}

	sort.Slice(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Commit != rep.Findings[j].Commit {
			return rep.Findings[i].Commit < rep.Findings[j].Commit
		}
		return rep.Findings[i].Identity < rep.Findings[j].Identity
	})
	sort.Strings(rep.UnusedEntries)
	return rep, nil
}

// index строит отбор по адресу и заодно судит саму ведомость: запись без
// адреса либо без причины — дефект основания гейта, а не тишина.
func index(entries []Entry, group string) (map[string]*Entry, []string) {
	out := map[string]*Entry{}
	var fails []string
	for i := range entries {
		e := &entries[i]
		email := norm(e.Email)
		if email == "" {
			fails = append(fails, fmt.Sprintf("%s: запись без адреса — покрывать нечего", group))
			continue
		}
		if strings.TrimSpace(e.Note) == "" {
			fails = append(fails, fmt.Sprintf(
				"%s: запись %q без названной причины — «не спрашиваем» без основания и есть искомый дефект", group, e.Email))
			continue
		}
		out[email] = e
	}
	return out, fails
}

type commitRec struct {
	sha, name, email, body string
}

type contributor struct {
	name, email, form string
}

// contributors — все формы вклада в одном коммите: автор и каждый соавтор.
// Личность, названная обеими формами, считается один раз.
func contributors(c commitRec) []contributor {
	out := []contributor{{name: c.name, email: norm(c.email), form: formAuthor}}
	seen := map[string]bool{norm(c.email): true}
	for email, name := range trailerNamed(c.body, "co-authored-by") {
		if seen[email] {
			continue
		}
		seen[email] = true
		out = append(out, contributor{name: name, email: email, form: formCoAuthor})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].email < out[j].email })
	return out
}

// trailerKey — ключ трейлера в форме, которую производит git.
var trailerKey = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*):[ \t](.*)$`)

// trailerBlock — завершающий блок трейлеров, а не всё тело.
//
// Граница объявлена намеренно: читай гейт подпись откуда угодно в сообщении,
// строка, процитированная в прозе (разбор чужого коммита, откат), начала бы
// подтверждать соглашение задним числом.
func trailerBlock(body string) map[string][]string {
	lines := strings.Split(strings.TrimRight(body, "\n \t"), "\n")
	start := 0
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			start = i + 1
			break
		}
	}
	out := map[string][]string{}
	for _, l := range lines[start:] {
		if strings.TrimSpace(l) == "" {
			continue
		}
		m := trailerKey.FindStringSubmatch(l)
		if m == nil {
			// Хотя бы одна строка блока трейлером не является — значит это
			// проза, и трейлеров в сообщении нет.
			return map[string][]string{}
		}
		key := strings.ToLower(m[1])
		out[key] = append(out[key], strings.TrimSpace(m[2]))
	}
	return out
}

// trailerEmails — адреса из трейлера с названным ключом.
func trailerEmails(body, key string) map[string]bool {
	out := map[string]bool{}
	for _, v := range trailerBlock(body)[key] {
		if email := extractEmail(v); email != "" {
			out[email] = true
		}
	}
	return out
}

// trailerNamed — адрес → имя из трейлера с названным ключом.
func trailerNamed(body, key string) map[string]string {
	out := map[string]string{}
	for _, v := range trailerBlock(body)[key] {
		email := extractEmail(v)
		if email == "" {
			continue
		}
		name := strings.TrimSpace(v)
		if i := strings.LastIndex(name, "<"); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		out[email] = name
	}
	return out
}

// extractEmail достаёт адрес из значения трейлера в обеих законных формах:
// `Имя <адрес>` и голый адрес.
func extractEmail(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.LastIndex(v, "<"); i >= 0 {
		if j := strings.Index(v[i:], ">"); j > 0 {
			return norm(v[i+1 : i+j])
		}
	}
	if strings.Contains(v, "@") && !strings.ContainsAny(v, " \t") {
		return norm(v)
	}
	return ""
}

// norm приводит адрес к сравнимой форме. Регистр адреса значения не имеет:
// один и тот же человек пишет его по-разному, и предикат, чувствительный к
// регистру, молча завёл бы вторую личность.
func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// gitLog читает историю области. Разделители — управляющие символы, а не
// перевод строки: тело сообщения содержит и переводы строк, и пустые строки.
// gitLog спрашивает историю ЧЕРЕЗ pkg/gitenv, а не прямым вызовом.
//
// `cmd.Dir` не выбирает репозиторий, когда в окружении есть `GIT_DIR`:
// переменная сильнее рабочего каталога. Прямой вызов с `cmd.Env =
// append(os.Environ(), …)` возвращал снятые переменные обратно — и гейт вынес бы
// вердикт о вкладе по истории ЧУЖОГО репозитория, оставаясь на вид исправным.
// Дополнять окружение можно только ДОПИСЫВАНИЕМ к `gitenv.Env()`.
func gitLog(repoRoot, revRange string, scope []string) ([]commitRec, error) {
	args := []string{"log", "-z", "--format=%H%x1f%an%x1f%ae%x1f%B", revRange}
	if len(scope) > 0 {
		args = append(args, "--")
		args = append(args, scope...)
	}
	cmd := gitenv.Command(repoRoot, args...)
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log %s: %w: %s", revRange, err, stderr.String())
	}

	var recs []commitRec
	for _, chunk := range strings.Split(string(out), "\x00") {
		if strings.TrimSpace(chunk) == "" {
			continue
		}
		parts := strings.SplitN(chunk, "\x1f", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("неразобранная запись git log: %q", short(chunk))
		}
		recs = append(recs, commitRec{
			sha:   strings.TrimSpace(parts[0]),
			name:  parts[1],
			email: parts[2],
			body:  parts[3],
		})
	}
	return recs, nil
}
