// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// probe_home.go — РЕЗОЛВ НАЗВАННОГО ДОМА: координата чужого дерева проверяется
// В НЁМ, а не просто считается.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Приставка `<владелец>/<репозиторий>:` снимает координату с суждения соседнего
// гейта: подтвердить объявление функции в чужом репозитории он не мог. Пока это
// было так, у приставки была вторая, незаявленная роль — СПОСОБ СНЯТЬ
// КООРДИНАТУ С ПРОВЕРКИ. Имя, снятое в чужом дереве завтра, здесь не покраснело
// бы ни разу, и приёмка посылала бы читателя по адресу, которого нет.
//
// ПОЧЕМУ ЭТО НЕ ЗАВОДИЛОСЬ РАНЬШЕ — И ПОЧЕМУ ДОВОД БЫЛ ВЕРЕН. Ветвь резолва без
// производителя входа есть мёртвый страж: объявлен и никогда не исполняется. Он
// заводится ВМЕСТЕ с производителем, и производитель здесь — две синтетические
// копии с РАЗНЫМИ идентичностями (`probe_home_injection_test.go`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОРЯДОК КАНДИДАТОВ ЗАКРЫТ И ОБЪЯВЛЕН
//
//  1. переменная `KACHO_HOME_<ИМЯ>` — оператор назвал копию явно;
//  2. соседний клон: у каждого предка своего корня — `<предок>/<имя>` и
//     `<предок>/project/<имя>`;
//  3. ничего — ТРЕТЬЯ КАТЕГОРИЯ.
//
// ДОМ ОПОЗНАЁТСЯ ИДЕНТИЧНОСТЬЮ `origin`, А НЕ ИМЕНЕМ КАТАЛОГА. Каталог зовут как
// угодно, и совпадение имени ничего не обещает: копия под именем `kacho` бывает
// клоном чего угодно. Поэтому кандидат, чей `origin` не тот, ОТВЕРГАЕТСЯ и
// называется в причине — «указатель, ведущий в чужой репозиторий, дома не даёт».
//
// ПРИЧИНА ПЕРЕЧИСЛЯЕТ КАЖДОГО ОТВЕРГНУТОГО. Без перечня «дома нет» читается как
// «искали одно место», а починки у «переменная указывает мимо» и «клона нет»
// разные — и первая состоит в правке того, что уже объявлено.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ СУДИТСЯ — В СТВОЛЕ ДОМА, А НЕ В ИНДЕКСЕ ЛЕЖАЩЕЙ РЯДОМ КОПИИ
//
// Координата резолвится по `origin/main` дома. Копия ОБЩАЯ: её ревизию
// переключает соседняя сессия, не спрашивая отправляющего, и вердикт, прочитанный
// с индекса, есть функция чужого переключения. Класс наблюдался целиком
// (`PRO-Robotech/kacho-workspace#543`): копия стояла на линии, где каталог
// переименован, и проверка объявила несуществующими координаты, которые в стволе
// ЕСТЬ.
//
// Координата, СВЯЗАННАЯ РЕВИЗИЕЙ (`owner/repo@<хеш>:Имя`), судится на ЭТОЙ
// ревизии, а не на стволе: она указывает в прошлое состояние чужого дерева
// намеренно, и сводить её к стволу значило бы судить не то, что написано.
//
// Ствол не резолвится (клон без этой ссылки) — ТРЕТЬЯ КАТЕГОРИЯ, а не находка:
// судить не по чему, и молчаливый откат на индекс копии здесь запрещён той же
// причиной, что выше.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТОТ РЕЗОЛВ СЕГОДНЯ ДАЁТ В КОНВЕЙЕРЕ — СКАЗАНО ПРЯМО, А НЕ ПОДРАЗУМЕВАЕТСЯ
//
// На машине разработчика, где копия дома лежит рядом, резолв ИСПОЛНЯЕТСЯ: замер
// на дереве службы — домов 2, координат проверено в доме 101, находок 0.
//
// В конвейере службы копии дома рядом НЕТ: единственная выборка чужого дерева
// (`ci.yml`, задание сверки каталога прав) кладёт его в каталог с ДРУГИМ именем и
// берёт один подкаталог. Кандидатом она поэтому не становится, и резолв даёт
// ТРЕТЬЮ КАТЕГОРИЮ со своим числом — то есть безопасный исход, а не ложную
// находку: «дома нет» никогда не читается как «имени нет».
//
// ОСТАТОК НАЗВАН С ПРЕДИКАТОМ, А НЕ ОБЕЩАНИЕМ. Чтобы резолв исполнялся и в
// конвейере, заданию, гоняющему этот гейт, нужна выборка дома и переменная
// `KACHO_HOME_KACHO`, указывающая на неё. Предикат снятия: прогон конвейера
// печатает «координат проверено в доме N > 0». Цена шага не измерена здесь и
// решается своим изменением: у разрежённой выборки другой состав и другой вес.
package check

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// HomeEnvVar — имя переменной, которой оператор называет копию дома явно.
func HomeEnvVar(identity string) string {
	name := identity
	if i := strings.LastIndex(identity, "/"); i >= 0 {
		name = identity[i+1:]
	}
	up := strings.ToUpper(name)
	up = strings.ReplaceAll(up, "-", "_")
	up = strings.ReplaceAll(up, ".", "_")
	return "KACHO_HOME_" + up
}

// RepoIdentity — идентичность рабочей копии: `owner/name` из `origin`.
// Пустая строка означает, что идентичность непроверяема.
func RepoIdentity(dir string) string {
	out, err := exec.Command("git", "-C", dir, "remote", "get-url", "origin").Output() // #nosec G204 -- путь кандидата дома
	if err != nil {
		return ""
	}
	url := strings.TrimSpace(string(out))
	url = strings.TrimSuffix(url, ".git")
	if i := strings.Index(url, "://"); i >= 0 {
		url = url[i+3:]
	}
	if i := strings.Index(url, "@"); i >= 0 && !strings.Contains(url[:i], "/") {
		url = url[i+1:]
	}
	url = strings.ReplaceAll(url, ":", "/")
	seg := strings.Split(strings.Trim(url, "/"), "/")
	if len(seg) < 2 {
		return ""
	}
	return strings.Join(seg[len(seg)-2:], "/")
}

// HomeTree — (путь, причина). Пустой путь означает: дома нет, и это ТРЕТЬЯ
// категория, а не вердикт о документе.
func HomeTree(ownRoot, identity string) (string, string) {
	name := identity
	if i := strings.LastIndex(identity, "/"); i >= 0 {
		name = identity[i+1:]
	}
	env := HomeEnvVar(identity)

	type cand struct{ path, whence string }
	var candidates []cand
	if v := os.Getenv(env); v != "" {
		candidates = append(candidates, cand{v, "$" + env})
	}
	// Соседний клон ищется ВВЕРХ от своего корня, а не фиксированной глубиной:
	// раскладка у посадок разная (рабочая копия полосы, `project/<имя>`,
	// соседний каталог), и счёт сегментов был бы свойством одной из них.
	dir := ownRoot
	for i := 0; i < 8 && dir != "/" && dir != ""; i++ {
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		candidates = append(candidates,
			cand{filepath.Join(parent, name), filepath.Join(parent, name)},
			cand{filepath.Join(parent, "project", name), filepath.Join(parent, "project", name)})
		dir = parent
	}

	var tried []string
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c.path, ".git")); err != nil {
			tried = append(tried, fmt.Sprintf("%s — рабочей копии там нет", c.whence))
			continue
		}
		got := RepoIdentity(c.path)
		if got == "" {
			tried = append(tried, fmt.Sprintf("%s — у копии нет origin, идентичность непроверяема", c.whence))
			continue
		}
		if !strings.EqualFold(got, identity) {
			tried = append(tried, fmt.Sprintf("%s — это копия %s, а не %s", c.whence, got, identity))
			continue
		}
		return c.path, ""
	}
	shown := tried
	if len(shown) > 6 {
		shown = append(append([]string{}, shown[:6]...),
			fmt.Sprintf("…и ещё %d кандидат(ов)", len(tried)-6))
	}
	return "", fmt.Sprintf("копия дома %s рядом не найдена [%s]. Условие создаётся так: "+
		"git clone https://github.com/%s.git <путь> и %s=<путь>",
		identity, strings.Join(shown, "; "), identity, env)
}

// HomeRef — ссылка, по которой судится дом. Ствол, если ревизия не названа.
func HomeRef(dir, rev string) (string, string) {
	if rev != "" {
		if err := exec.Command("git", "-C", dir, "cat-file", "-e", rev+"^{commit}").Run(); err != nil { // #nosec G204 -- ревизия проверена формой
			return "", fmt.Sprintf("ревизия %s в копии дома не резолвится", rev)
		}
		return rev, ""
	}
	if err := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", "origin/main").Run(); err != nil { // #nosec G204 -- путь кандидата дома
		return "", "ствол origin/main в копии дома не резолвится — судить не по чему. " +
			"Условие создаётся так: git -C " + dir + " fetch origin main"
	}
	return "origin/main", ""
}

// probeDeclRe — объявление пробы в чужом дереве. Та же форма, что у своего.
func probeDeclRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^func ` + regexp.QuoteMeta(name) + `\s*\(`)
}

// ProbeDeclaredInHome — объявлена ли проба в названном доме на названной ссылке.
func ProbeDeclaredInHome(dir, ref, name string) bool {
	out, err := exec.Command("git", "-C", dir, "grep", "-l", "-E", // #nosec G204 -- имя проверено ProbeCoordinateShape
		`^func `+regexp.QuoteMeta(name)+`[[:space:]]*\(`, ref, "--", "*_test.go").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return true
	}
	// Вторая форма чтения — на случай, когда `git grep` по ссылке недоступен:
	// содержимое ссылки читается и разбирается тем же образцом. Молчание первой
	// формы иначе было бы неотличимо от отсутствия имени.
	files, ferr := exec.Command("git", "-C", dir, "ls-tree", "-r", "--name-only", ref).Output() // #nosec G204 -- путь кандидата дома
	if ferr != nil {
		return false
	}
	re := probeDeclRe(name)
	for _, rel := range strings.Split(string(files), "\n") {
		if !strings.HasSuffix(rel, "_test.go") {
			continue
		}
		body, berr := exec.Command("git", "-C", dir, "show", ref+":"+rel).Output() // #nosec G204 -- путь из перечня ссылки
		if berr == nil && re.Match(body) {
			return true
		}
	}
	return false
}

// HomeVerdict — исход резолва координаты в названном доме.
type HomeVerdict struct {
	// Findings — имя, которого в доме НЕТ. Вердикт, а не третья категория.
	Findings []string
	// Voids — ТРЕТЬЯ КАТЕГОРИЯ: дома рядом нет либо судить в нём не по чему.
	// В проход НЕ засчитывается и находок не гасит.
	Voids []string
	// Resolved — координат, найденных в своём доме.
	Resolved int
	// HomesResolved — дома, копии которых нашлись; HomesAbsent — которых нет.
	HomesResolved []string
	HomesAbsent   []string
}

// JudgeHomes — резолв координат чужих домов В НАЗВАННОМ ДОМЕ.
//
// НАХОДКИ И ТРЕТЬЯ КАТЕГОРИЯ РАЗВЕДЕНЫ, и вызывающий обязан объявлять находки
// ПЕРВЫМИ: иначе «дома нет» становится маской — одной такой строки хватило бы,
// чтобы настоящая находка перестала блокировать отправку.
//
// Дом резолвится ОДИН раз на имя: без этого перепись печатала бы его столько
// раз, сколько координат на него ссылается.
func JudgeHomes(ownRoot string, coords []ProbeCoordinate) HomeVerdict {
	var v HomeVerdict
	type slot struct {
		dir    string
		reason string
	}
	homes := map[string]slot{}
	seenResolved := map[string]bool{}
	seenAbsent := map[string]bool{}

	for _, co := range coords {
		s, known := homes[co.Home]
		if !known {
			dir, reason := HomeTree(ownRoot, co.Home)
			s = slot{dir: dir, reason: reason}
			homes[co.Home] = s
			if dir == "" {
				if !seenAbsent[co.Home] {
					seenAbsent[co.Home] = true
					v.HomesAbsent = append(v.HomesAbsent, co.Home)
				}
			} else if !seenResolved[co.Home] {
				seenResolved[co.Home] = true
				v.HomesResolved = append(v.HomesResolved, co.Home)
			}
		}
		if s.dir == "" {
			v.Voids = append(v.Voids, fmt.Sprintf(
				"[VOID] %s: %s — координата НЕ ПРОВЕРЕНА, и это «условие не создано», "+
					"а не вердикт о приёмке", co.Span, s.reason))
			continue
		}
		ref, rerr := HomeRef(s.dir, co.Rev)
		if rerr != "" {
			v.Voids = append(v.Voids, fmt.Sprintf(
				"[VOID] %s: %s — координата НЕ ПРОВЕРЕНА", co.Span, rerr))
			continue
		}
		if ProbeDeclaredInHome(s.dir, ref, co.Name) {
			v.Resolved++
			continue
		}
		v.Findings = append(v.Findings, fmt.Sprintf(
			"%s: имени %s в доме %s на %s НЕТ — приёмка посылает читателя по адресу, "+
				"которого в чужом дереве больше не существует", co.Span, co.Name, co.Home, ref))
	}
	sort.Strings(v.HomesResolved)
	sort.Strings(v.HomesAbsent)
	return v
}
