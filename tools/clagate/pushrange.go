// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clagate

import (
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// pushrange.go — судья отправки (kaname#459): подпись ОТПРАВЛЯЕМОГО диапазона
// судится той же ведомостью `cla-ledger.yaml`, что и история гейтом дерева.
//
// ПОЧЕМУ ВЕДОМОСТЬ, А НЕ НАСТРОЙКА GIT. До судьи хук отправки сверял подпись с
// корневой настройкой git (`git config --global user.email`, страж
// scripts/hooks/branch-rule.sh). У предмета было два источника личности:
// ведомость и настройка, — и второй расходился с первым МОЛЧА: адрес, которого
// в ведомости нет, уезжал на сервер, и находкой он становился лишь у гейта
// дерева, то есть уже опубликованным, когда чинить можно только переписью
// истории. Судья спрашивает ведомость о том, что отправка ОПУБЛИКУЕТ, — до
// публикации. Страж правила при этом остаётся: он требует ОДНУ корневую
// личность, судья — чтобы любая подпись была в ведомости; расхождение двух
// перечней теперь отказ отправки, а не тишина.
//
// ЧТО СУДИТСЯ. Каждый коммит, которого на сервере ещё нет, в трёх ролях: автор,
// коммиттер и соавтор из трейлера `Co-authored-by`. Коммиттер судится НАРАВНЕ
// с автором: гейт дерева его вкладчиком не считает (перенёсший чужой коммит
// содержимого не создавал), но подпись коммита — его адрес, и публикуется она
// ровно так же. Область ведомости (`scope`) здесь не сужает обход: публикуется
// коммит целиком, а не его пути.
//
// ЧТО ВЫЧИТАЕТСЯ. Опубликованное на ТОМ remote, куда идёт отправка: sha на
// сервере из строк отправки и ссылки `refs/remotes/<remote>/*`. Не все
// `--remotes`: чужой коммит, известный через ссылку ВТОРОГО remote (вклад,
// взятый из чужой копии), при отправке в первый иначе не судился бы вовсе, хотя
// в первом его нет. Отправка по адресу (хук получает адрес вместо имени)
// вычитает только sha на сервере — судится больше, а не меньше.
//
// КАКОЙ ВЕДОМОСТЬЮ. Той, что лежит в отправляемой ВЕРШИНЕ: публикуется
// ведомость вместе с подписями, и правка рабочего каталога, которую никто не
// отправит, подписи не покрывает.

// Исходы судьи. Хук читает всякий ненулевой как отказ отправки.
const (
	ExitGreen = 0 // ЗЕЛЁНОЕ: судилось, находок нет, объём назван
	ExitRed   = 1 // КРАСНОЕ: подпись не покрыта ведомостью либо ведомость негодна
	ExitUnmet = 2 // УСЛОВИЕ НЕ СОЗДАНО: судить было нечем — это не проход
)

// roleCommitter — третья роль, которую гейт дерева не судит.
const roleCommitter = "коммиттер"

// basis — чем покрыта роль.
type basis string

const (
	basisOwners      basis = "owners"
	basisSignatories basis = "signatories"
	basisWaivers     basis = "waivers"
	basisSignOff     basis = "своя подпись Signed-off-by"
)

// pushRoleTable — какие основания покрывают какую роль в отправке.
//
// ОСВОБОЖДЕНИЕ НЕ ПОДПИСЫВАЕТ. Раздел `waivers` отвечает на вопрос соглашения
// — «нужна ли подпись под этим ВКЛАДОМ», — а не на вопрос подписи КОММИТА.
// Освобождённая машинная личность автором или коммиттером отправляемого
// коммита и есть подстановка адреса окружением, ради которой судья заведён;
// соавтором она законна — там вопрос только о соглашении.
//
// Своя подпись `Signed-off-by` в завершающем блоке трейлеров покрывает роль
// ТОЙ личности, что подписалась, — так же, как у гейта дерева: подписаться за
// другого нельзя.
var pushRoleTable = map[string][]basis{
	formAuthor:    {basisOwners, basisSignatories, basisSignOff},
	roleCommitter: {basisOwners, basisSignatories, basisSignOff},
	formCoAuthor:  {basisOwners, basisSignatories, basisWaivers, basisSignOff},
}

// pushRoleOrder — порядок ролей в переписи.
var pushRoleOrder = []string{formAuthor, roleCommitter, formCoAuthor}

// maxPushInput — предел строк отправки. Git подаёт строку на ссылку; мегабайт —
// десятки тысяч ссылок. Больше — не строки отправки, и судить их нечего.
const maxPushInput = 1 << 20

var (
	hexSHA     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	zeroSHA    = regexp.MustCompile(`^0+$`)
	remoteName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// UnmetError — «условие не создано»: строку не разобрать, вершины в клоне нет,
// у вершины нет ведомости, git не ответил. Вызывающий обязан прочесть её как
// отказ отправки: «проверить было нечем» — не проход.
type UnmetError struct{ Why string }

func (e *UnmetError) Error() string { return e.Why }

// PushReport — итог суждения по отправке: находки и перепись осмотренного.
type PushReport struct {
	LedgerPath       string
	Remote           string
	Refs             int // строк отправки
	Deletions        int // из них снятий ссылки
	Tips             int // различных отправляемых вершин
	ServerSHAs       int // sha на сервере, вычтенных по строкам отправки
	UnknownRemoteSHA int // sha на сервере, которых в этом клоне нет: вычитать нечем
	TrackingGlob     string
	Commits          int // различных публикуемых коммитов
	Contributions    int // пар «коммит × роль»
	ByRole           map[string]int
	Identities       int
	Findings         []Finding
	LedgerDefects    []string
}

// Census — объём осмотренного одной строкой: «ноль находок» обязано быть
// отличимо от «ноль прочитанного».
func (r PushReport) Census() string {
	roles := make([]string, 0, len(pushRoleOrder))
	for _, ro := range pushRoleOrder {
		roles = append(roles, fmt.Sprintf("%s %d", ro, r.ByRole[ro]))
	}
	glob := "отслеживаемых ссылок нет (remote не назван именем либо не настроен)"
	if r.TrackingGlob != "" {
		glob = r.TrackingGlob
	}
	return fmt.Sprintf("remote %s · ссылок %d (снятий %d) · вершин %d · публикуемых коммитов %d · "+
		"вкладов %d (%s) · личностей %d · вычтено: sha на сервере %d, %s · sha сервера, которых нет в клоне, %d · "+
		"ведомость %s отправляемой вершины",
		r.Remote, r.Refs, r.Deletions, r.Tips, r.Commits, r.Contributions, strings.Join(roles, ", "),
		r.Identities, r.ServerSHAs, glob, r.UnknownRemoteSHA, r.LedgerPath)
}

// pushLedger — ведомость одной вершины, разобранная в отбор по разделам.
type pushLedger struct {
	owners, signatories, waivers map[string]*Entry
}

// JudgePushRange судит строки, которые git подаёт хуку pre-push:
// `<локальная ссылка> <локальная sha> <удалённая ссылка> <sha на сервере>`.
//
// Ошибка *UnmetError — «условие не создано»; негодная ведомость — не ошибка, а
// LedgerDefects отчёта (красное).
func JudgePushRange(repoRoot, ledgerRel, remote string, in io.Reader) (PushReport, error) {
	rep := PushReport{LedgerPath: ledgerRel, Remote: remote, ByRole: map[string]int{}}

	ledgerPath, err := ledgerInTree(ledgerRel)
	if err != nil {
		return rep, err
	}
	raw, err := io.ReadAll(io.LimitReader(in, maxPushInput+1))
	if err != nil {
		return rep, &UnmetError{Why: fmt.Sprintf("строки отправки не прочитаны: %v", err)}
	}
	if len(raw) > maxPushInput {
		return rep, &UnmetError{Why: fmt.Sprintf("строки отправки длиннее %d байт — это не вход хука pre-push", maxPushInput)}
	}

	var tips, negatives []string
	seenTip := map[string]bool{}
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		f := strings.Fields(ln)
		if len(f) != 4 {
			return rep, &UnmetError{Why: fmt.Sprintf("строка отправки не разобрана: %q — что публикуется, неизвестно", ln)}
		}
		rep.Refs++
		lsha, rsha := f[1], f[3]
		if !hexSHA.MatchString(lsha) || !hexSHA.MatchString(rsha) {
			return rep, &UnmetError{Why: fmt.Sprintf("в строке отправки не sha: %q", ln)}
		}
		if zeroSHA.MatchString(lsha) {
			rep.Deletions++
			continue
		}
		tip, err := gitOutput(repoRoot, "rev-parse", "--verify", "--quiet", lsha+"^{commit}")
		if err != nil {
			return rep, &UnmetError{Why: fmt.Sprintf("отправляемая ревизия %s — не коммит этого клона", short(lsha))}
		}
		if t := strings.TrimSpace(string(tip)); !seenTip[t] {
			seenTip[t] = true
			tips = append(tips, t)
		}
		if zeroSHA.MatchString(rsha) {
			continue
		}
		known, err := gitOutput(repoRoot, "rev-parse", "--verify", "--quiet", rsha+"^{commit}")
		if err != nil {
			// Сервер несёт ревизию, которой здесь нет (её отправили из другой
			// копии): вычитать её нечем, и судится больше, а не меньше.
			rep.UnknownRemoteSHA++
			continue
		}
		rep.ServerSHAs++
		negatives = append(negatives, strings.TrimSpace(string(known)))
	}
	rep.Tips = len(tips)

	if remoteName.MatchString(remote) {
		if _, err := gitOutput(repoRoot, "config", "--get", "remote."+remote+".url"); err == nil {
			rep.TrackingGlob = "refs/remotes/" + remote + "/*"
		}
	}

	judged := map[string]bool{}
	reported := map[string]bool{}
	identities := map[string]bool{}
	for _, tip := range tips {
		li, defects, err := ledgerAt(repoRoot, tip, ledgerPath)
		if err != nil {
			return rep, err
		}
		if len(defects) > 0 {
			for _, d := range defects {
				rep.LedgerDefects = append(rep.LedgerDefects, fmt.Sprintf("вершина %s: %s", short(tip), d))
			}
			continue
		}

		// `--not` обращает смысл ВСЕХ следующих указателей, включая `--glob`:
		// вычитается и sha на сервере, и отслеживаемые ссылки remote.
		revs := []string{tip}
		if len(negatives) > 0 || rep.TrackingGlob != "" {
			revs = append(revs, "--not")
			revs = append(revs, negatives...)
			if rep.TrackingGlob != "" {
				revs = append(revs, "--glob="+rep.TrackingGlob)
			}
		}
		recs, err := readCommits(repoRoot, revs)
		if err != nil {
			return rep, &UnmetError{Why: fmt.Sprintf("отправляемый диапазон вершины %s не прочитан: %v", short(tip), err)}
		}
		for _, c := range recs {
			first := !judged[c.sha]
			judged[c.sha] = true
			for _, ct := range pushContributions(c) {
				if first {
					rep.Contributions++
					rep.ByRole[ct.role]++
					if ct.email != "" {
						identities[ct.email] = true
					}
				}
				f, ok := li.judge(c, ct)
				if ok {
					continue
				}
				// Коммит, достижимый из двух вершин, судится ведомостью каждой;
				// одна и та же находка называется один раз.
				key := c.sha + "\x00" + ct.role + "\x00" + f.Identity
				if !reported[key] {
					reported[key] = true
					rep.Findings = append(rep.Findings, f)
				}
			}
		}
	}
	rep.Commits = len(judged)
	rep.Identities = len(identities)
	sort.SliceStable(rep.Findings, func(i, j int) bool { return rep.Findings[i].Commit < rep.Findings[j].Commit })
	return rep, nil
}

// ledgerInTree — путь ведомости внутри дерева вершины. Абсолютный путь и `..`
// увели бы чтение за корень: судья вынес бы вердикт по ведомости, которой в
// отправляемом дереве нет.
func ledgerInTree(ledgerRel string) (string, error) {
	p := path.Clean(filepath.ToSlash(ledgerRel))
	if ledgerRel == "" || path.IsAbs(p) || p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return "", &UnmetError{Why: fmt.Sprintf("ведомость %q — не путь внутри судимого дерева", ledgerRel)}
	}
	return p, nil
}

// ledgerAt — ведомость, лежащая в вершине tip. Нет файла — «условие не
// создано»; файл негоден — дефекты (красное).
func ledgerAt(repoRoot, tip, ledgerPath string) (*pushLedger, []string, error) {
	raw, err := gitOutput(repoRoot, "cat-file", "blob", tip+":"+ledgerPath)
	if err != nil {
		return nil, nil, &UnmetError{Why: fmt.Sprintf("в вершине %s нет ведомости %s — судить подпись нечем", short(tip), ledgerPath)}
	}
	ledger, err := decodeLedger(raw, ledgerPath)
	if err != nil {
		return nil, []string{err.Error()}, nil
	}
	owners, defects := index(ledger.Owners, "owners")
	signatories, signFails := index(ledger.Signatories, "signatories")
	waivers, waiverFails := index(ledger.Waivers, "waivers")
	defects = append(defects, signFails...)
	defects = append(defects, waiverFails...)
	if len(owners) == 0 {
		defects = append(defects, "ведомость не называет ни одной своей личности: различать своего и стороннего нечем")
	}
	return &pushLedger{owners: owners, signatories: signatories, waivers: waivers}, defects, nil
}

// pushContribution — личность в роли коммита.
type pushContribution struct {
	role        string
	name, email string // email пуст — значение трейлера не разобрано
	raw         string
}

// pushContributions — автор, коммиттер и каждый соавтор коммита. Соавтор,
// совпавший с автором или коммиттером, уже судим строже — его строка таблицы
// уже, поэтому второй раз он не считается.
func pushContributions(c commitRec) []pushContribution {
	author, committer := norm(c.email), norm(c.committerEmail)
	out := []pushContribution{
		{role: formAuthor, name: c.name, email: author},
		{role: roleCommitter, name: c.committerName, email: committer},
	}
	seen := map[string]bool{author: true, committer: true}
	for _, v := range trailerBlock(c.body)["co-authored-by"] {
		email := extractEmail(v)
		if email == "" {
			// Значение без разборного адреса — не пропуск: вклад назван, а
			// личность не установлена.
			out = append(out, pushContribution{role: formCoAuthor, raw: v})
			continue
		}
		if seen[email] {
			continue
		}
		seen[email] = true
		name := strings.TrimSpace(v)
		if i := strings.LastIndex(name, "<"); i >= 0 {
			name = strings.TrimSpace(name[:i])
		}
		out = append(out, pushContribution{role: formCoAuthor, name: name, email: email, raw: v})
	}
	return out
}

// judge — покрыта ли роль по таблице; нет — находка с причиной.
func (li *pushLedger) judge(c commitRec, ct pushContribution) (Finding, bool) {
	if ct.email != "" {
		signOffs := trailerEmails(c.body, "signed-off-by")
		for _, b := range pushRoleTable[ct.role] {
			switch b {
			case basisOwners:
				if li.owners[ct.email] != nil {
					return Finding{}, true
				}
			case basisSignatories:
				if li.signatories[ct.email] != nil {
					return Finding{}, true
				}
			case basisWaivers:
				if li.waivers[ct.email] != nil {
					return Finding{}, true
				}
			case basisSignOff:
				if signOffs[ct.email] {
					return Finding{}, true
				}
			}
		}
	}

	identity := fmt.Sprintf("%s <%s>", ct.name, ct.email)
	var why string
	switch {
	case ct.email == "":
		identity = ct.raw
		why = "адрес соавтора не разобран — личность не установлена, подтверждать нечего"
	case li.waivers[ct.email] != nil:
		why = "освобождение (waivers) коммит не подписывает: оно отвечает на вопрос соглашения о вкладе, а не подписи коммита"
	case ct.role == formCoAuthor:
		why = "вклад стороннего автора без подтверждения соглашения о вкладе"
	default:
		why = "личности нет в ведомости — подпись вне ведомости не публикуется"
	}
	return Finding{Commit: c.sha, Identity: identity, Form: ct.role, Why: why}, false
}

// RunPushRange — режим `push-range` целиком: читает строки отправки из in,
// судит, печатает объём осмотренного и находки в out и возвращает код исхода.
// Вынесено из main ради инъекции: исход проверяется подачей входа.
func RunPushRange(repoRoot, ledgerRel, remote string, in io.Reader, out io.Writer) int {
	// Отказ записи в поток диагностики вердикта не меняет: исход несёт код.
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format, a...) }

	rep, err := JudgePushRange(repoRoot, ledgerRel, remote, in)
	say("clagate push-range: %s\n", rep.Census())
	var unmet *UnmetError
	switch {
	case errors.As(err, &unmet):
		say("clagate push-range: УСЛОВИЕ НЕ СОЗДАНО — %s.\n"+
			"  Судить было нечем, и это не проход: вердикта о подписи нет ни в одну сторону.\n", unmet.Why)
		return ExitUnmet
	case err != nil:
		say("clagate push-range: УСЛОВИЕ НЕ СОЗДАНО — %v\n", err)
		return ExitUnmet
	}
	if len(rep.LedgerDefects) > 0 {
		say("clagate push-range: КРАСНОЕ — ведомость негодна к суждению (%d):\n", len(rep.LedgerDefects))
		for _, d := range rep.LedgerDefects {
			say("  %s\n", d)
		}
		return ExitRed
	}
	if len(rep.Findings) > 0 {
		say("clagate push-range: КРАСНОЕ — отправка опубликовала бы подпись, не покрытую ведомостью: %s\n",
			Report{Findings: rep.Findings}.Summary(40))
		say("  Чинится переподписью НЕОТПРАВЛЕННЫХ коммитов личностью из ведомости либо закоммиченной " +
			"записью ведомости с названной причиной — не обходом хука.\n")
		return ExitRed
	}
	say("clagate push-range: ЗЕЛЁНОЕ — каждая роль каждого публикуемого коммита покрыта ведомостью\n")
	return ExitGreen
}
