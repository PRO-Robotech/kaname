// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// one_clock_revoke_all_integration_test.go — момент выдачи долговременного
// удостоверения человека и момент отсечки отзыва-всех ставит ОДИН источник
// времени (задача kaname#388).
//
// # Предмет
//
// Правило отсечки (`revocationpolicy`) сравнивает отсечку с моментом выдачи
// удостоверения. Отсечку пишут варианты использования своими часами процесса,
// а момент выдачи ставили часы базы (умолчание столбца). Точность границы
// задавало расхождение двух часов, а не правило: при часах процесса впереди
// базы ключ, выданный ПОСЛЕ отсечки, отвергался; при часах позади — ключ,
// выданный ДО отсечки, проходил.
//
// # Что утверждается
//
// Часы процесса сдвинуты относительно базы в обе стороны (±1 ч). Удостоверение
// выдаётся настоящим вариантом использования с этими часами, отсечку пишет
// настоящая дверь с моментом тех же часов — так, как его пишет всякий писатель
// отсечки «сейчас». На КАЖДОЙ полосе правила, выведенной переписью дерева
// (вызовы `revocationpolicy.AtIssuance` и `revocationpolicy.Forbids` в
// не-тестовом коде), выданное до отсечки отвергается, выданное после —
// принимается.
//
// Отрицательный контроль — возврат второго источника (момент выдачи из часов
// базы): проба краснеет на обеих сторонах сдвига.
package user_tokens

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ruleLanesInTree — файлы не-тестового кода, где правило отсечки судит
// полномочие: вызовы `revocationpolicy.AtIssuance` и `revocationpolicy.Forbids`.
// Узел разбора, а не слово: имя в комментарии или в строке не считается.
func ruleLanesInTree(t *testing.T) (lanes []string, parsed int) {
	t.Helper()
	root, err := filepath.Abs("../../../../..")
	require.NoError(t, err)
	_, statErr := os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, statErr, "предпосылка переписи: корень модуля не найден (%s)", root)
	seen := map[string]bool{}
	for _, top := range []string{"internal", "cmd"} {
		werr := filepath.WalkDir(filepath.Join(root, top), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(token.NewFileSet(), p, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			parsed++
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if ok && pkg.Name == "revocationpolicy" && (sel.Sel.Name == "AtIssuance" || sel.Sel.Name == "Forbids") {
					rel, _ := filepath.Rel(root, p)
					seen[filepath.ToSlash(rel)] = true
				}
				return true
			})
			return nil
		})
		require.NoError(t, werr)
	}
	for l := range seen {
		lanes = append(lanes, l)
	}
	sort.Strings(lanes)
	return lanes, parsed
}

// oneClockStand — база с человеком, подтвердившим адрес.
type oneClockStand struct {
	pool *pgxpool.Pool
	user domain.User
}

func newOneClockStand(t *testing.T) oneClockStand {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	const account, user = "acc000000000000clk01", "usr000000000000clk01"
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1,'one-clock',$2)`, account, user)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, email_verified_at)
		VALUES ($1,$2,'ext-one-clock','clock@example.com','Clock','ACTIVE', now())`, user, account)
	require.NoError(t, err)
	seedWayIn(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))
	return oneClockStand{pool: pool, user: domain.User{ID: domain.UserID(user), AccountID: domain.AccountID(account)}}
}

// issueSecret — выдача удостоверения настоящим вариантом использования с
// часами процесса clock. Вид SECRET завершается на пути запроса.
func (s oneClockStand) issueSecret(t *testing.T, clock func() time.Time) (id, secret string) {
	t.Helper()
	uc := NewIssueUserTokenUseCase(kanamepg.NewUserOAuthClientRepo(s.pool), kanamepg.NewPoolTxBeginner(s.pool),
		shared.NewTerminalRefusalRepo(operations.NewRepo(s.pool, "kaname")))
	uc.now = clock
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: string(s.user.ID)})
	op, err := uc.Execute(ctx, IssueInput{
		UserID: s.user.ID, CreatedByUserID: string(s.user.ID),
		CredentialKind: domain.CredentialKindSecret, TTLSeconds: int64((24 * time.Hour).Seconds()),
	})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Nil(t, op.Error, "выдача обязана состояться")
	var resp iamv1.IssueUserTokenResponse
	require.NoError(t, op.Response.UnmarshalTo(&resp))
	require.NotEmpty(t, resp.GetSecret())
	return resp.GetToken().GetId(), resp.GetSecret()
}

// issueSession — сессия человека с моментом аутентификации по часам процесса,
// как её выдаёт вход.
func (s oneClockStand) issueSession(t *testing.T, clock func() time.Time) time.Time {
	t.Helper()
	ctx := context.Background()
	w, err := kanamepg.NewHumanSessionRepo(s.pool).Writer(ctx)
	require.NoError(t, err)
	sess, _, err := humansession.IssueSession(ctx, w, humansession.IssueInput{
		User: s.user, Presented: []assurance.Presentation{assurance.PasswordPresented()},
		At: clock().Truncate(time.Microsecond), TTL: time.Hour,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	var at time.Time
	require.NoError(t, s.pool.QueryRow(ctx,
		`SELECT authenticated_at FROM kaname.human_sessions WHERE id = $1`, string(sess.ID)).Scan(&at))
	return at
}

// standingIssuedAt — момент выдачи из строки удостоверения: ровно то, что
// полоса нашего токен-эндпоинта кладёт в принципала.
func (s oneClockStand) standingIssuedAt(t *testing.T, id string) time.Time {
	t.Helper()
	row, err := kanamepg.NewUserOAuthClientRepo(s.pool).Get(context.Background(), domain.UserOAuthClientID(id))
	require.NoError(t, err)
	return row.CreatedAt
}

func TestRevokeAll_IssuanceAndCutoffShareOneClockOnEveryRuleLane(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	lanes, parsed := ruleLanesInTree(t)
	require.NotEmptyf(t, lanes, "перепись полос правила пуста среди %d файлов — не выполнилась", parsed)
	t.Logf("перепись: прочитано файлов %d · полос правила %d", parsed, len(lanes))

	// Полосы, которые проба судит. Сверяется с переписью: полоса, заведённая
	// позже и сюда не поданная, краснеет названием.
	covered := []string{
		"internal/apps/kaname/api/client_token/issue.go",   // наш токен-эндпоинт: якорь — выдача ключа
		"internal/ceremonyport/access_tokens.go",           // церемония: якорь — момент сессии
		"internal/repo/kaname/pg/basic_credential_repo.go", // базовый секрет: якорь — выдача строки
	}
	require.Equalf(t, covered, lanes, "перепись полос правила (%d файлов) разошлась с тем, что судит проба", parsed)

	for _, skew := range []time.Duration{time.Hour, -time.Hour} {
		t.Run("часы процесса "+skew.String()+" к базе", func(t *testing.T) {
			ctx := context.Background()
			s := newOneClockStand(t)
			clock := func() time.Time { return time.Now().Add(skew) }

			idBefore, secretBefore := s.issueSecret(t, clock)
			sessBefore := s.issueSession(t, clock)

			// Писатель отсечки «сейчас» — моментом своих часов процесса.
			adapter := kanamepg.NewSessionRevocationsAdapter(s.pool)
			require.NoError(t, adapter.RevokeAllUserTokensTx(ctx, s.user.ID, clock().UTC(), "admin-revoke", ""))

			idAfter, secretAfter := s.issueSecret(t, clock)
			sessAfter := s.issueSession(t, clock)

			// Полоса нашего токен-эндпоинта: якорь — момент выдачи ключа.
			for _, c := range []struct {
				name string
				id   string
				want revocationpolicy.Verdict
			}{
				{"выданное до отсечки", idBefore, revocationpolicy.Revoked},
				{"выданное после отсечки", idAfter, revocationpolicy.Allowed},
			} {
				issued := s.standingIssuedAt(t, c.id)
				got, err := revocationpolicy.AtIssuance(ctx, adapter, service.ResolvedPrincipal{
					Kind: service.PrincipalUser, UserID: string(s.user.ID), StandingCredentialIssuedAt: &issued,
				}, time.Time{})
				require.NoError(t, err)
				require.Equalf(t, c.want, got, "токен-эндпоинт, %s (выдано %s): вердикт по разнице часов, а не по порядку",
					c.name, issued)
			}

			// Полоса базового секрета: якорь — момент выдачи строки.
			basic, err := kanamepg.NewBasicCredentialRepo(s.pool, 5*time.Second)
			require.NoError(t, err)
			_, err = basic.ResolveBasic(ctx, secretBefore)
			reason, named := domain.BasicCredentialRefusalReasonOf(err)
			require.Truef(t, named && reason == domain.BasicRefusalOwnerRevoked,
				"базовый секрет, выданный до отсечки: ожидался отказ по отсечке, получено %v", err)
			_, err = basic.ResolveBasic(ctx, secretAfter)
			require.NoError(t, err, "базовый секрет, выданный после отсечки, обязан приниматься")

			// Полоса церемонии: якорь — момент аутентификации сессии.
			rule := kanamepg.NewCeremonyIssuanceRule(s.pool)
			for _, c := range []struct {
				name string
				at   time.Time
				want revocationpolicy.Verdict
			}{
				{"сессия до отсечки", sessBefore, revocationpolicy.Revoked},
				{"сессия после отсечки", sessAfter, revocationpolicy.Allowed},
			} {
				got, err := revocationpolicy.AtIssuance(ctx, rule, service.ResolvedPrincipal{
					Kind: service.PrincipalUser, UserID: string(s.user.ID),
				}, c.at)
				require.NoError(t, err)
				require.Equalf(t, c.want, got, "церемония, %s", c.name)
			}
		})
	}
}
