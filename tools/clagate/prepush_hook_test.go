// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clagate_test

// prepush_hook_test.go — отказ судьи отправки ОСТАНАВЛИВАЕТ отправку
// (kaname#459): опыт гоняет НАСТОЯЩИЙ `scripts/hooks/pre-push` на синтетическом
// клоне и настоящую `git push` в голый репозиторий.
//
// ПОЧЕМУ ЗДЕСЬ, А НЕ ПРОБОЙ ФУНКЦИИ. Судья, который судит верно, но которого хук
// не зовёт либо чей отказ хук не читает, оставляет отправку непроверенной — и
// снаружи это неотличимо от зелёного. Свойство держит ПРОВЯЗКА, поэтому опыт
// спрашивает исход отправки: уехала ли ссылка на сервер.
//
// КАК ОТДЕЛЁН СУДЬЯ ОТ СТРАЖА ПРАВИЛА. Хук первым зовёт страж правила ветки и
// коммита, и тот сверяет автора и коммиттера с КОРНЕВОЙ учётной записью git
// (`git config --global user.email`). Подпись чужим адресом страж отверг бы сам —
// и опыт не узнал бы, судил ли судья. Поэтому личность во всех кейсах ОДНА и
// совпадает с корневой учётной записью: страж правила молчит в каждом кейсе, а
// кейсы различаются ОДНИМ фактом — разделом ведомости, в котором стоит эта
// личность. Ровно этот случай и есть предмет задачи: второй перечень личностей
// (настройка git) разошёлся с первым (ведомостью) — прежде молча.
//
// ПОЧЕМУ ВСЕ КЕЙСЫ С KANAME_SKIP_PREPUSH=1. Обход снимает наборы проверок, но не
// подпись: судья стоит ДО обхода, как и страж правила. Отказ при обходе — значит
// отказал именно судья (наборы не гонялись), а проход при обходе — значит судья
// пропустил. Заодно закреплено, что обход судью не снимает.
//
// СУДЬЯ СОБИРАЕТСЯ ИЗ ЭТОГО МОДУЛЯ. Хук собирает его из
// `./tools/clagate/cmd/clagate` корня клона; в синтетическом клоне исходников
// нет, поэтому в PATH стоит переходник `go`, исполняющий настоящий `go` из корня
// ЭТОГО модуля. Судья поэтому настоящий, а судимое дерево — синтетическое: его
// хук называет судье доводом `--root`.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/treeroot"
)

// hookIdentity — корневая учётная запись синтетического клона: ею подписан
// каждый коммит, поэтому страж правила ветки и коммита молчит во всех кейсах.
var hookIdentity = struct{ name, email string }{"Подписант", "signer@example.org"}

// hookFiles — что хук отправки читает из своего каталога до наборов проверок:
// страж правила, страж новых blob'ов (kaname#894; без него хук отказывает) и
// определитель категории.
var hookFiles = []string{"pre-push", "prepush-rule.sh", "branch-rule.sh", "prepush-added-files.sh", "prepush-classify.sh"}

type hookClone struct {
	dir, remote string
	env         []string
}

// newHookClone — синтетический клон с настоящим хуком отправки и ведомостью
// ledger, закоммиченной корневой учётной записью, и пустой голый удалённый.
func newHookClone(t *testing.T, ledger string) *hookClone {
	t.Helper()
	modRoot, err := treeroot.ModuleRootFrom(".")
	require.NoError(t, err)
	realGo, err := exec.LookPath("go")
	require.NoError(t, err, "предпосылка опыта: go в PATH — судью собрать нечем")

	work := t.TempDir()
	c := &hookClone{dir: filepath.Join(work, "clone"), remote: filepath.Join(work, "remote.git")}
	shim := filepath.Join(work, "bin")
	require.NoError(t, os.MkdirAll(shim, 0o750))
	// Переходник `go`: настоящий инструмент из корня ЭТОГО модуля — там лежат
	// исходники судьи. Судимое дерево хук называет доводом, а не каталогом.
	goShim := "#!/bin/sh\ncd '" + modRoot + "' || exit 97\nexec '" + realGo + "' \"$@\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(shim, "go"), []byte(goShim), 0o700)) // #nosec G306 -- исполняемый переходник пробы
	// Переходник `systemd-run` отказывает: потолок памяти — предмет другого опыта
	// (prepush-budget-inject.sh), и пользовательский systemd машины здесь не нужен.
	require.NoError(t, os.WriteFile(filepath.Join(shim, "systemd-run"),
		[]byte("#!/bin/sh\nexit 1\n"), 0o700)) // #nosec G306 -- исполняемый переходник пробы

	gitconfig := filepath.Join(work, "gitconfig")
	require.NoError(t, os.WriteFile(gitconfig, []byte(
		"[user]\n\tname = "+hookIdentity.name+"\n\temail = "+hookIdentity.email+"\n"+
			"[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n"), 0o600))
	c.env = append(gitenv.Env(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+gitconfig,
		"GIT_TERMINAL_PROMPT=0",
		"KANAME_SKIP_PREPUSH=1",
		"TMPDIR="+t.TempDir(),
		"PATH="+shim+string(os.PathListSeparator)+os.Getenv("PATH"),
	)

	require.NoError(t, os.MkdirAll(filepath.Join(c.dir, "scripts", "hooks"), 0o750))
	for _, f := range hookFiles {
		raw, rerr := os.ReadFile(filepath.Join(modRoot, "scripts", "hooks", f)) // #nosec G304 -- файл хука этого модуля
		require.NoError(t, rerr)
		require.NoError(t, os.WriteFile(filepath.Join(c.dir, "scripts", "hooks", f), raw, 0o700)) // #nosec G306 -- исполняемый хук
	}
	require.NoError(t, os.WriteFile(filepath.Join(c.dir, "cla-ledger.yaml"), []byte(ledger), 0o600))

	c.git(t, work, "init", "-q", "--bare", c.remote)
	c.git(t, c.dir, "init", "-q")
	c.git(t, c.dir, "config", "core.hooksPath", "scripts/hooks")
	c.git(t, c.dir, "add", "-A")
	c.git(t, c.dir, "commit", "-q", "--no-verify", "-m", "#1 фикстура судьи отправки")
	c.git(t, c.dir, "remote", "add", "origin", c.remote)
	return c
}

func (c *hookClone) git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := gitenv.Command(dir, args...)
	cmd.Env = c.env
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "фикстура: git %s: %s", strings.Join(args, " "), out)
	return strings.TrimSpace(string(out))
}

// push — настоящая отправка; исход — код и уехала ли ссылка на сервер.
func (c *hookClone) push(t *testing.T) (out string, pushed bool, err error) {
	t.Helper()
	cmd := gitenv.Command(c.dir, "push", "origin", "HEAD:refs/heads/1")
	cmd.Env = c.env
	raw, err := cmd.CombinedOutput()
	// Вопрос о СОСТАВЕ ССЫЛОК голого удалённого фикстуры («есть ли ссылка»), а не
	// об истории: потому show-ref, а не rev-parse --verify.
	probe := gitenv.Command(c.remote, "show-ref", "--verify", "--quiet", "refs/heads/1")
	probe.Env = c.env
	return string(raw), probe.Run() == nil, err
}

// hookLedger — ведомость, в которой корневая учётная запись стоит в разделе
// section (owners · signatories · waivers) либо нигде (section == "").
func hookLedger(section string) string {
	entry := func(s string) string {
		if s != section {
			return " []\n"
		}
		return "\n  - email: " + hookIdentity.email + "\n    note: личность опыта — раздел " + s + "\n"
	}
	owners := "\n  - email: owner@example.com\n    note: своя личность опыта\n"
	if section == "owners" {
		owners += "  - email: " + hookIdentity.email + "\n    note: личность опыта — раздел owners\n"
	}
	return "scope:\n  - .\nowners:" + owners + "signatories:" + entry("signatories") + "waivers:" + entry("waivers")
}

// TestPrePush_SignerInTheLedgerIsPushed — законный близнец: личность стоит в
// ведомости своей, отправка уезжает, судья напечатал объём осмотренного.
func TestPrePush_SignerInTheLedgerIsPushed(t *testing.T) {
	for _, section := range []string{"owners", "signatories"} {
		t.Run(section, func(t *testing.T) {
			c := newHookClone(t, hookLedger(section))
			out, pushed, err := c.push(t)
			require.NoError(t, err, "отправка подписи из ведомости отказана:\n%s", out)
			require.True(t, pushed, "код 0, а ссылки на сервере нет:\n%s", out)
			require.Contains(t, out, "clagate push-range: ", "судья не напечатал объёма осмотренного:\n%s", out)
			require.Contains(t, out, "публикуемых коммитов 1", "судья осмотрел не тот диапазон:\n%s", out)
		})
	}
}

// TestPrePush_SignerOutsideTheLedgerStopsThePush — инъекция: та же личность
// вне ведомости. Отказ называет sha и адрес, ссылка на сервер не уехала.
func TestPrePush_SignerOutsideTheLedgerStopsThePush(t *testing.T) {
	c := newHookClone(t, hookLedger(""))
	head := c.git(t, c.dir, "rev-parse", "HEAD")
	out, pushed, err := c.push(t)
	require.Error(t, err, "отправка подписи вне ведомости ПРОШЛА — судьи в хуке нет либо его отказ не читается:\n%s", out)
	require.False(t, pushed, "ссылка уехала на сервер при отказе:\n%s", out)
	require.Contains(t, out, head[:12], "отказ не называет коммит:\n%s", out)
	require.Contains(t, out, hookIdentity.email, "отказ не называет адрес:\n%s", out)
	// Форма находки «… <адрес> (роль) — причина»: перепись тоже называет роль
	// «коммиттер», поэтому утверждается именно форма находки.
	require.Contains(t, out, "<"+hookIdentity.email+"> (коммиттер)", "отказ не называет коммиттера находкой:\n%s", out)
}

// TestPrePush_WaiverDoesNotSignThePush — клетка «освобождение»: личность стоит
// в waivers. Освобождение отвечает на вопрос соглашения о ВКЛАДЕ, а не подписи
// коммита, — отправка остановлена.
func TestPrePush_WaiverDoesNotSignThePush(t *testing.T) {
	c := newHookClone(t, hookLedger("waivers"))
	out, pushed, err := c.push(t)
	require.Error(t, err, "отправка подписи освобождённым адресом ПРОШЛА:\n%s", out)
	require.False(t, pushed, "ссылка уехала на сервер при отказе:\n%s", out)
	require.Contains(t, out, hookIdentity.email, "отказ не называет адрес:\n%s", out)
}
