// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clagate_test

// pushrange_test.go — судья отправки (kaname#459) доказывается инъекцией в обе
// стороны, а таблица исходов по ролям закреплена КЕЙСОМ НА КЛЕТКУ.
//
// Ожидаемая таблица выписана здесь ОТДЕЛЬНО от судьи, а не выведена из его
// таблицы: выведенное ожидание совпадало бы с судьёй при любой его ошибке.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/tools/clagate"
)

type person struct{ name, email string }

var (
	pOwner    = person{"Свой", "owner@example.com"}
	pSigned   = person{"Подписавший", "signed@example.org"}
	pBot      = person{"Робот", "bot@example.org"}
	pSelf     = person{"Сам-подписал", "self@example.org"}
	pStranger = person{"Чужой", "stranger@example.org"}
)

const zeroSHA = "0000000000000000000000000000000000000000"

// cellLedger — все основания разом: клетка отличается от соседней только
// личностью в судимой роли.
const cellLedger = `scope:
  - .
owners:
  - email: owner@example.com
    note: своя личность
signatories:
  - email: signed@example.org
    note: подписал соглашение вне коммита — задача опыта
waivers:
  - email: bot@example.org
    note: машинная личность — вклад не авторское произведение
`

// prRepo — синтетический репозиторий в собственном каталоге пробы. Окружение
// строится от gitenv.Env(): унаследованный GIT_DIR увёл бы фикстуру в чужой
// индекс.
type prRepo struct {
	t   *testing.T
	dir string
	env []string
}

func newPRRepo(t *testing.T) *prRepo {
	t.Helper()
	home := t.TempDir()
	r := &prRepo{t: t, dir: t.TempDir(), env: append(gitenv.Env(),
		"HOME="+home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, "gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
	)}
	r.git(nil, "-c", "init.defaultBranch=main", "init", "-q")
	r.git(nil, "config", "commit.gpgsign", "false")
	return r
}

func (r *prRepo) git(extra []string, args ...string) string {
	r.t.Helper()
	cmd := gitenv.Command(r.dir, args...)
	cmd.Env = append(append([]string{}, r.env...), extra...)
	out, err := cmd.CombinedOutput()
	require.NoError(r.t, err, "фикстура: git %s: %s", strings.Join(args, " "), out)
	return strings.TrimSpace(string(out))
}

// commit — пустой коммит с заданными автором, коммиттером и сообщением.
func (r *prRepo) commit(author, committer person, msg string) string {
	r.t.Helper()
	r.git([]string{
		"GIT_AUTHOR_NAME=" + author.name, "GIT_AUTHOR_EMAIL=" + author.email,
		"GIT_COMMITTER_NAME=" + committer.name, "GIT_COMMITTER_EMAIL=" + committer.email,
	}, "commit", "-q", "--no-verify", "--allow-empty", "-m", msg)
	return r.git(nil, "rev-parse", "HEAD")
}

// ledger — кладёт ведомость и КОММИТИТ её своей личностью: судья читает
// ведомость отправляемой вершины, а не рабочего каталога.
func (r *prRepo) ledger(body string) string {
	r.t.Helper()
	require.NoError(r.t, os.WriteFile(filepath.Join(r.dir, "cla-ledger.yaml"), []byte(body), 0o600))
	r.git(nil, "add", "cla-ledger.yaml")
	return r.commit(pOwner, pOwner, "ведомость")
}

// publish — фиксирует состояние «сервер уже несёт эту вершину»: голый удалённый
// с отслеживаемой ссылкой refs/remotes/origin/main.
func (r *prRepo) publish() {
	r.t.Helper()
	remote := filepath.Join(r.t.TempDir(), "remote.git")
	r.git(nil, "init", "-q", "--bare", remote)
	r.git(nil, "remote", "add", "origin", remote)
	r.git(nil, "push", "-q", "--no-verify", "origin", "HEAD:refs/heads/main")
	r.git(nil, "fetch", "-q", "origin")
}

func line(local, remote string) string {
	return "refs/heads/main " + local + " refs/heads/main " + remote + "\n"
}

func judge(t *testing.T, r *prRepo, remote, stdin string) clagate.PushReport {
	t.Helper()
	rep, err := clagate.JudgePushRange(r.dir, "cla-ledger.yaml", remote, strings.NewReader(stdin))
	require.NoError(t, err)
	return rep
}

// TestPushRange_RoleTableCellByCell — кейс на клетку таблицы исходов.
//
// Строка — роль, столбец — основание. Каждая клетка — отдельный отправляемый
// коммит, где судимая роль занята личностью этого основания, а прочие роли —
// своей личностью; находка о судимой роли поэтому может прийти только от неё.
func TestPushRange_RoleTableCellByCell(t *testing.T) {
	type cell struct {
		basis   string
		who     person
		signOff bool // сообщение несёт Signed-off-by этой личности
		covered bool
	}
	// Ожидание — здесь, а не из таблицы судьи. Коммиттер судится наравне с
	// автором; освобождение не подписывает коммит ни в одной из двух ролей и
	// покрывает только соавтора — его вопрос соглашения, а не подписи.
	row := func(waiverCovers bool) []cell {
		return []cell{
			{"owners", pOwner, false, true},
			{"signatories", pSigned, false, true},
			{"waivers", pBot, false, waiverCovers},
			{"signoff", pSelf, true, true},
			{"вне ведомости", pStranger, false, false},
		}
	}
	table := map[string][]cell{
		"автор коммита":      row(false),
		"коммиттер":          row(false),
		"соавтор в трейлере": row(true),
	}
	require.Len(t, table, 3, "ролей три — строк таблицы три")

	for role, cells := range table {
		for _, c := range cells {
			t.Run(role+"/"+c.basis, func(t *testing.T) {
				r := newPRRepo(t)
				r.ledger(cellLedger)
				r.publish()

				author, committer := pOwner, pOwner
				msg := "клетка " + role + " × " + c.basis
				var trailers []string
				switch role {
				case "автор коммита":
					author = c.who
				case "коммиттер":
					committer = c.who
				case "соавтор в трейлере":
					trailers = append(trailers, "Co-authored-by: "+c.who.name+" <"+c.who.email+">")
				}
				if c.signOff {
					trailers = append(trailers, "Signed-off-by: "+c.who.name+" <"+c.who.email+">")
				}
				if len(trailers) > 0 {
					msg += "\n\n" + strings.Join(trailers, "\n")
				}
				base := r.git(nil, "rev-parse", "HEAD")
				sha := r.commit(author, committer, msg)

				rep := judge(t, r, "origin", line(sha, base))
				require.Equal(t, 1, rep.Commits, "осмотрен не тот диапазон")
				if c.covered {
					require.Empty(t, rep.Findings, "клетка покрыта, а судья нашёл: %v", rep.Findings)
					return
				}
				require.Len(t, rep.Findings, 1, "клетка не покрыта — ровно одна находка: %v", rep.Findings)
				f := rep.Findings[0]
				require.Equal(t, sha, f.Commit)
				require.Equal(t, role, f.Form, "находка не о судимой роли")
				require.Contains(t, f.Identity, c.who.email)
			})
		}
	}
}

// TestPushRange_WaiverDoesNotSign — клетка «освобождение» отдельно, в обе
// стороны: освобождённый адрес автором или коммиттером — отказ; тот же адрес
// соавтором при своих авторе и коммиттере — молчание.
func TestPushRange_WaiverDoesNotSign(t *testing.T) {
	for _, tc := range []struct {
		name              string
		author, committer person
		trailer           string
		want              int
	}{
		{"автором", pBot, pOwner, "", 1},
		{"коммиттером", pOwner, pBot, "", 1},
		{"автором и коммиттером", pBot, pBot, "", 2},
		{"соавтором — законный близнец", pOwner, pOwner, "\n\nCo-authored-by: Робот <bot@example.org>", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPRRepo(t)
			r.ledger(cellLedger)
			r.publish()
			base := r.git(nil, "rev-parse", "HEAD")
			sha := r.commit(tc.author, tc.committer, "освобождение"+tc.trailer)
			rep := judge(t, r, "origin", line(sha, base))
			require.Len(t, rep.Findings, tc.want, "%v", rep.Findings)
			for _, f := range rep.Findings {
				require.Contains(t, f.Identity, pBot.email)
				require.Contains(t, f.Why, "waivers")
			}
		})
	}
}

// TestPushRange_RunFromStdin — режим целиком, как его зовёт хук: строки
// pre-push со stdin, объём осмотренного и исход кодом. Адрес из ведомости — 0;
// коммиттер вне ведомости — 1 с sha и адресом.
func TestPushRange_RunFromStdin(t *testing.T) {
	r := newPRRepo(t)
	r.ledger(cellLedger)
	r.publish()
	base := r.git(nil, "rev-parse", "HEAD")
	good := r.commit(pOwner, pOwner, "своё")

	var out bytes.Buffer
	code := clagate.RunPushRange(r.dir, "cla-ledger.yaml", "origin", strings.NewReader(line(good, base)), &out)
	require.Equal(t, clagate.ExitGreen, code, out.String())
	require.Contains(t, out.String(), "ссылок 1", out.String())
	require.Contains(t, out.String(), "публикуемых коммитов 1", out.String())
	require.Contains(t, out.String(), "вкладов 2", "автор и коммиттер одного коммита — два вклада:\n%s", out.String())

	bad := r.commit(pOwner, pStranger, "чужой коммиттер")
	out.Reset()
	code = clagate.RunPushRange(r.dir, "cla-ledger.yaml", "origin", strings.NewReader(line(bad, base)), &out)
	require.Equal(t, clagate.ExitRed, code, out.String())
	require.Contains(t, out.String(), bad[:12], out.String())
	require.Contains(t, out.String(), pStranger.email, out.String())
	require.Contains(t, out.String(), "публикуемых коммитов 2", out.String())
}

// TestPushRange_PublishedCommitsAreSubtracted — опубликованное на ТОМ remote не
// судится: чужой коммит, уже лежащий на сервере, отправку не останавливает.
// Законный близнец — тот же чужой коммит, ещё не опубликованный.
func TestPushRange_PublishedCommitsAreSubtracted(t *testing.T) {
	r := newPRRepo(t)
	r.ledger(cellLedger)
	r.commit(pStranger, pStranger, "чужое, уже опубликованное")
	r.publish()
	published := r.git(nil, "rev-parse", "HEAD")
	mine := r.commit(pOwner, pOwner, "своё")

	// Сервер несёт вершину: вычитается и по строке, и по отслеживаемой ссылке.
	rep := judge(t, r, "origin", line(mine, published))
	require.Equal(t, 1, rep.Commits)
	require.Empty(t, rep.Findings)

	// Новая ветка (на сервере sha нулевая): вычитает отслеживаемая ссылка remote.
	rep = judge(t, r, "origin", "refs/heads/x "+mine+" refs/heads/x "+zeroSHA+"\n")
	require.Equal(t, 1, rep.Commits, "опубликованное через refs/remotes/origin/* не вычтено")
	require.Empty(t, rep.Findings)

	// Близнец: remote без отслеживаемых ссылок — публикуется вся история, и чужой
	// коммит назван.
	rep = judge(t, r, "elsewhere", "refs/heads/x "+mine+" refs/heads/x "+zeroSHA+"\n")
	require.Equal(t, 3, rep.Commits)
	require.Len(t, rep.Findings, 2, "чужой автор и чужой коммиттер неопубликованного: %v", rep.Findings)
}

// TestPushRange_DeletionPublishesNothing — снятие ссылки ничего не публикует,
// но в переписи названо.
func TestPushRange_DeletionPublishesNothing(t *testing.T) {
	r := newPRRepo(t)
	r.ledger(cellLedger)
	r.publish()
	head := r.git(nil, "rev-parse", "HEAD")
	var out bytes.Buffer
	code := clagate.RunPushRange(r.dir, "cla-ledger.yaml", "origin",
		strings.NewReader("(delete) "+zeroSHA+" refs/heads/x "+head+"\n"), &out)
	require.Equal(t, clagate.ExitGreen, code, out.String())
	require.Contains(t, out.String(), "ссылок 1 (снятий 1)", out.String())
	require.Contains(t, out.String(), "публикуемых коммитов 0", out.String())
}

// TestPushRange_UnreadableInputIsNotAPass — «судить было нечем» не проход:
// неразобранная строка, вершина не из этого клона, вершина без ведомости.
func TestPushRange_UnreadableInputIsNotAPass(t *testing.T) {
	r := newPRRepo(t)
	r.commit(pOwner, pOwner, "без ведомости")
	noLedger := r.git(nil, "rev-parse", "HEAD")
	r.ledger(cellLedger)
	head := r.git(nil, "rev-parse", "HEAD")

	for name, stdin := range map[string]string{
		"строка из трёх полей":    "refs/heads/main " + head + " refs/heads/main\n",
		"не sha":                  line("HEAD", zeroSHA),
		"вершины в клоне нет":     line(strings.Repeat("ab", 20), zeroSHA),
		"у вершины нет ведомости": line(noLedger, zeroSHA),
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			code := clagate.RunPushRange(r.dir, "cla-ledger.yaml", "origin", strings.NewReader(stdin), &out)
			require.Equal(t, clagate.ExitUnmet, code, out.String())
			require.Contains(t, out.String(), "УСЛОВИЕ НЕ СОЗДАНО", out.String())
		})
	}
}

// TestPushRange_BrokenLedgerIsRed — ведомость, негодная к суждению, — красное с
// причиной, а не тишина и не «всё своё».
func TestPushRange_BrokenLedgerIsRed(t *testing.T) {
	for name, body := range map[string]string{
		"нет своих личностей": "scope:\n  - .\nowners: []\nsignatories: []\nwaivers: []\n",
		"запись без причины":  "scope:\n  - .\nowners:\n  - email: owner@example.com\n    note: ''\n",
		"неизвестный ключ":    cellLedger + "extra: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			r := newPRRepo(t)
			sha := r.ledger(body)
			var out bytes.Buffer
			code := clagate.RunPushRange(r.dir, "cla-ledger.yaml", "origin", strings.NewReader(line(sha, zeroSHA)), &out)
			require.Equal(t, clagate.ExitRed, code, out.String())
			require.Contains(t, out.String(), "ведомость", out.String())
		})
	}
}
