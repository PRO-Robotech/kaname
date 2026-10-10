// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// one_clock_revoke_all_integration_test.go — моменты, которые сравниваются с
// отсечкой отзыва-всех, ставит ОДИН источник на все реплики службы (задачи
// kaname#388, kaname#589).
//
// # Предмет
//
// Правило отсечки (`revocationpolicy`, `tokenrevocation`) сравнивает отсечку с
// моментом полномочия: выдачей долговременного удостоверения, аутентификацией
// сессии, `iat`. Реплик службы больше одной, и у каждой свои часы процесса.
// Пока момент ставили часы реплики, граница правила была расхождением часов
// двух реплик: при часах выдающей реплики позади пишущей отсечку удостоверение,
// выданное ПОСЛЕ отсечки, отвергалось; впереди — выданное ДО неё проходило.
//
// # Что утверждается
//
// Две реплики, чьи часы процесса сдвинуты друг относительно друга в обе
// стороны (±1 ч). Отсечку пишет настоящая дверь одной (отзыв-всех и
// принудительный выход), удостоверение, сессию и токен выдаёт другая —
// собранные так, как их собирает корень: моменты от общего источника
// (`kanamepg.SharedClock`). На КАЖДОЙ полосе правила, выведенной переписью
// дерева, и на `iat` выданное до отсечки отвергается, выданное после —
// принимается.
//
// Отрицательный контроль — инъекция «часы реплики»: писателю моментов подан
// источник, отвечающий часами процесса своей реплики, — у выдающей реплики либо
// у пишущей отсечку. Проба обязана краснеть на каждой из двух инъекций.
package user_tokens

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	sessionrev "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
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

// oneClockStand — база с человеком, подтвердившим адрес, и общий источник
// моментов — тот, что корень подаёт писателям (`buildSharedClock`).
type oneClockStand struct {
	pool   *pgxpool.Pool
	user   domain.User
	shared revocationpolicy.Clock
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
	shared, err := revocationpolicy.ClockWithDeadline(kanamepg.NewSharedClock(pool), 5*time.Second)
	require.NoError(t, err)
	return oneClockStand{pool: pool, user: domain.User{ID: domain.UserID(user), AccountID: domain.AccountID(account)}, shared: shared}
}

// replica — реплика службы: её часы процесса сдвинуты на skew, а писатели
// моментов получают источник moments — так, как его подаёт корень (общий), либо
// инъекцией (часы этой реплики).
type replica struct {
	skew    time.Duration
	moments revocationpolicy.Clock
}

// processClock — часы процесса реплики.
func (r replica) processClock() time.Time { return time.Now().Add(r.skew) }

// ownClock — инъекция «часы реплики»: источник моментов, отвечающий часами
// процесса этой реплики.
func (r replica) ownClock() revocationpolicy.Clock { return momentclock.Func(r.processClock) }

// issueSecret — выдача удостоверения настоящим вариантом использования
// реплики r. Вид SECRET завершается на пути запроса.
func (s oneClockStand) issueSecret(t *testing.T, r replica) (id, secret string) {
	t.Helper()
	uc := NewIssueUserTokenUseCase(kanamepg.NewUserOAuthClientRepo(s.pool), kanamepg.NewPoolTxBeginner(s.pool),
		shared.NewTerminalRefusalRepo(operations.NewRepo(s.pool, "kaname"))).WithIssuanceClock(r.moments)
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

// issueSession — сессия человека с моментом аутентификации от источника
// моментов реплики — так, как его ставят писатели сессии (вход паролем, вход
// ключом, восстановление, регистрация: `sharedMoment` до транзакции). Что
// каждый из них берёт момент ИЗ источника, держат `humansession` и
// `registration` пробы на управляемых часах и перепись писателей.
func (s oneClockStand) issueSession(t *testing.T, r replica) time.Time {
	t.Helper()
	ctx := context.Background()
	at, err := revocationpolicy.Moment(ctx, r.moments)
	require.NoError(t, err)
	w, err := kanamepg.NewHumanSessionRepo(s.pool).Writer(ctx)
	require.NoError(t, err)
	sess, _, err := humansession.IssueSession(ctx, w, humansession.IssueInput{
		User: s.user, Presented: []assurance.Presentation{assurance.PasswordPresented()},
		At: at.Truncate(time.Microsecond), TTL: time.Hour,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	var stored time.Time
	require.NoError(t, s.pool.QueryRow(ctx,
		`SELECT authenticated_at FROM kaname.human_sessions WHERE id = $1`, string(sess.ID)).Scan(&stored))
	return stored
}

// standingIssuedAt — момент выдачи из строки удостоверения: ровно то, что
// полоса нашего токен-эндпоинта кладёт в принципала.
func (s oneClockStand) standingIssuedAt(t *testing.T, id string) time.Time {
	t.Helper()
	row, err := kanamepg.NewUserOAuthClientRepo(s.pool).Get(context.Background(), domain.UserOAuthClientID(id))
	require.NoError(t, err)
	return row.CreatedAt
}

// pastIATResolution — `iat` несёт целые секунды, отсечка — микросекунды, и
// граница правила включающая: токен, выпущенный в ту же секунду, что
// отсечка, ею отозван (`tokenrevocation`, kaname#171) — это свойство
// разрешения `iat`, а не источника времени. «Выпущенный после отсечки» для
// `iat` поэтому значит «после следующей целой секунды». Ожидание считается от
// записанной отсечки по общему источнику и ограничено секундой; отсечка
// дальше двух секунд от источника (инъекция часов реплики) не ждётся.
func (s oneClockStand) pastIATResolution(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	cutoff, found, err := kanamepg.NewMintedTokenRevocationRepo(s.pool).RevokedBefore(ctx, string(s.user.ID))
	require.NoError(t, err)
	require.True(t, found, "отсечка отчеканенного записана дверью")
	now, err := revocationpolicy.Moment(ctx, s.shared)
	require.NoError(t, err)
	target := cutoff.Truncate(time.Second).Add(time.Second)
	if wait := target.Sub(now); wait > 0 && wait <= 2*time.Second {
		time.Sleep(wait + 10*time.Millisecond)
	}
}

// cutoffWriterNames — настоящие двери «вывести человека отовсюду».
var cutoffWriterNames = []string{"Revoke(revoke_all_user_tokens)", "ForceLogout"}

// writeCutoff — дверь name реплики r, собранная так, как её собирает корень.
func (s oneClockStand) writeCutoff(t *testing.T, name string, r replica) {
	t.Helper()
	switch name {
	case "Revoke(revoke_all_user_tokens)":
		adapter := kanamepg.NewSessionRevocationsAdapter(s.pool)
		h := sessionrev.NewHandler(sessionrev.NewRevokeUseCase(adapter, operations.NewRepo(s.pool, "kaname"), r.moments), adapter)
		_, err := h.Revoke(oneClockAdminCtx(), &iamv1.RevokeRequest{UserId: string(s.user.ID), RevokeAllUserTokens: true})
		require.NoError(t, err)
	case "ForceLogout":
		h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
			WithOwnSessions(kanamepg.NewHumanSessionRepo(s.pool)).
			WithCutoffClock(r.moments).
			WithAdminChecker(oneClockAdmin{}).
			WithOperations(operations.NewRepo(s.pool, "kaname"))
		_, err := h.ForceLogout(oneClockAdminCtx(), &iamv1.ForceLogoutRequest{UserId: string(s.user.ID)})
		require.NoError(t, err)
	default:
		t.Fatalf("дверь %q не собрана", name)
	}
}

type oneClockAdmin struct{}

func (oneClockAdmin) Check(context.Context, string, string, string) (bool, error) { return true, nil }

func oneClockAdminCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr000000000000adm01"})
}

// oneClockKeys — ключница пробы: один действующий подписной ключ.
type oneClockKeys struct{ mat tokensigner.SigningMaterial }

func (k oneClockKeys) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return k.mat, nil
}

func oneClockMaterial(t *testing.T) tokensigner.SigningMaterial {
	t.Helper()
	m, err := signingkeygen.Generate(domain.SigningAlgES256)
	require.NoError(t, err)
	return tokensigner.SigningMaterial{KID: "one-clock", Algorithm: domain.SigningAlgES256,
		PrivateKeyPEM: m.PrivateKeyPEM, PublicKeyPEM: m.PublicKeyPEM}
}

// mintIAT — токен человеку подписантом реплики r; возвращает состав
// утверждений, по которому судит правило отзыва отчеканенного.
func (s oneClockStand) mintIAT(t *testing.T, r replica, mat tokensigner.SigningMaterial) jwt.MapClaims {
	t.Helper()
	signer, err := tokensigner.New(tokensigner.Config{
		Issuer: "https://kaname.kacho.local", Clock: r.moments, MaxTokenTTL: 2 * time.Hour,
	}, oneClockKeys{mat: mat})
	require.NoError(t, err)
	tok, err := signer.Sign(context.Background(), tokensigner.Request{
		Subject: string(s.user.ID), Audience: []string{"kacho"}, TokenType: "at+jwt", TTL: time.Hour,
	})
	require.NoError(t, err)
	claims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(tok.Token, claims)
	require.NoError(t, err)
	return claims
}

// acrossReplicas — один прогон предмета: для каждого сдвига и каждой двери
// отсечки — выдача до, отсечка, выдача после; вердикт на каждой полосе правила
// и на `iat`. Возвращает расхождения вердикта с порядком событий и число
// судимых исходов. wire — как реплики получают источник моментов.
func acrossReplicas(t *testing.T, wire func(s oneClockStand, issuer, writer *replica)) (mismatches []string, judged int) {
	t.Helper()
	mat := oneClockMaterial(t)
	for _, skew := range []time.Duration{time.Hour, -time.Hour} {
		for _, writerName := range cutoffWriterNames {
			ctx := context.Background()
			s := newOneClockStand(t)
			issuer := replica{skew: skew}
			writer := replica{skew: -skew}
			wire(s, &issuer, &writer)
			label := fmt.Sprintf("%s · реплика выдачи %s к реплике отсечки", writerName, (2 * skew).String())
			miss := func(format string, args ...any) {
				mismatches = append(mismatches, label+": "+fmt.Sprintf(format, args...))
			}

			idBefore, secretBefore := s.issueSecret(t, issuer)
			sessBefore := s.issueSession(t, issuer)
			iatBefore := s.mintIAT(t, issuer, mat)

			s.writeCutoff(t, writerName, writer)

			idAfter, secretAfter := s.issueSecret(t, issuer)
			sessAfter := s.issueSession(t, issuer)
			s.pastIATResolution(t)
			iatAfter := s.mintIAT(t, issuer, mat)

			adapter := kanamepg.NewSessionRevocationsAdapter(s.pool)
			for _, c := range []struct {
				name string
				id   string
				want revocationpolicy.Verdict
			}{
				{"выданное до отсечки", idBefore, revocationpolicy.Revoked},
				{"выданное после отсечки", idAfter, revocationpolicy.Allowed},
			} {
				issued := s.standingIssuedAt(t, c.id)
				got, _, err := revocationpolicy.AtIssuance(ctx, adapter, service.ResolvedPrincipal{
					Kind: service.PrincipalUser, UserID: string(s.user.ID), StandingCredentialIssuedAt: &issued,
				}, time.Time{})
				require.NoError(t, err)
				judged++
				if got != c.want {
					miss("токен-эндпоинт, %s (выдано %s): %s, ожидался %s", c.name, issued, got, c.want)
				}
			}

			basic, err := kanamepg.NewBasicCredentialRepo(s.pool, 5*time.Second)
			require.NoError(t, err)
			_, err = basic.ResolveBasic(ctx, secretBefore)
			reason, named := domain.BasicCredentialRefusalReasonOf(err)
			judged++
			if !named || reason != domain.BasicRefusalOwnerRevoked {
				miss("базовый секрет, выданный до отсечки: ожидался отказ по отсечке, получено %v", err)
			}
			_, err = basic.ResolveBasic(ctx, secretAfter)
			judged++
			if err != nil {
				miss("базовый секрет, выданный после отсечки, отвергнут: %v", err)
			}

			rule := kanamepg.NewCeremonyIssuanceRule(s.pool)
			for _, c := range []struct {
				name string
				at   time.Time
				want revocationpolicy.Verdict
			}{
				{"сессия до отсечки", sessBefore, revocationpolicy.Revoked},
				{"сессия после отсечки", sessAfter, revocationpolicy.Allowed},
			} {
				got, _, err := revocationpolicy.AtIssuance(ctx, rule, service.ResolvedPrincipal{
					Kind: service.PrincipalUser, UserID: string(s.user.ID),
				}, c.at)
				require.NoError(t, err)
				judged++
				if got != c.want {
					miss("церемония, %s (момент %s): %s, ожидался %s", c.name, c.at, got, c.want)
				}
			}

			minted := kanamepg.NewMintedTokenRevocationRepo(s.pool)
			for _, c := range []struct {
				name   string
				claims jwt.MapClaims
				want   bool
			}{
				{"iat до отсечки", iatBefore, true},
				{"iat после отсечки", iatAfter, false},
			} {
				got, err := tokenrevocation.Revoked(ctx, minted, c.claims)
				require.NoError(t, err)
				judged++
				if got != c.want {
					miss("отчеканенный токен, %s (iat %v): отозван=%v, ожидалось %v", c.name, c.claims["iat"], got, c.want)
				}
			}
		}
	}
	return mismatches, judged
}

// rootWiring — источник моментов так, как его подаёт корень: общий.
func rootWiring(s oneClockStand, issuer, writer *replica) {
	issuer.moments = s.shared
	writer.moments = s.shared
}

// TestRevokeAll_IssuanceAndCutoffShareOneClockOnEveryRuleLane — kaname#589,
// предикат 3: две реплики со сдвинутыми часами, собранные как корень, —
// вердикт по порядку событий на каждой полосе правила и на `iat`.
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

	mismatches, judged := acrossReplicas(t, rootWiring)
	t.Logf("перепись: исходов судимо %d · расхождений %d", judged, len(mismatches))
	require.Positive(t, judged, "ни одного исхода не судимо — проба не выполнилась")
	require.Emptyf(t, mismatches, "вердикт по разнице часов реплик, а не по порядку событий:\n%s",
		strings.Join(mismatches, "\n"))
}

// TestRevokeAll_ReplicaClockInjectionIsCaught — отрицательный контроль той же
// пробы: часы реплики, поданные писателю моментов, краснят её. Две инъекции
// по одной — у выдающей реплики и у пишущей отсечку; соседний писатель в каждой
// остаётся на общем источнике, так что красное приходит от инъекции, а не от
// соседа.
func TestRevokeAll_ReplicaClockInjectionIsCaught(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	for name, wire := range map[string]func(s oneClockStand, issuer, writer *replica){
		"часы реплики у выдающей": func(s oneClockStand, issuer, writer *replica) {
			issuer.moments = issuer.ownClock()
			writer.moments = s.shared
		},
		"часы реплики у пишущей отсечку": func(s oneClockStand, issuer, writer *replica) {
			issuer.moments = s.shared
			writer.moments = writer.ownClock()
		},
	} {
		t.Run(name, func(t *testing.T) {
			mismatches, judged := acrossReplicas(t, wire)
			t.Logf("инъекция %q: исходов судимо %d · расхождений %d", name, judged, len(mismatches))
			require.NotEmptyf(t, mismatches, "инъекция %q не покраснила пробу — проба не различает источник", name)
		})
	}
}
