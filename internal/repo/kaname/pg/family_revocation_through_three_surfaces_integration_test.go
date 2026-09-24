// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_revocation_through_three_surfaces_integration_test.go — ОТЗЫВ
// СЕМЕЙСТВА доходит до КАЖДОЙ поверхности предъявления, и вопрос ставится
// сквозь обе стороны ОДНИМ прогоном (kaname#319, решение К10 вариант А;
// приёмка LINE-A-1, сценарии 01, 20, 21, 28).
//
// # Поверхностей три, и все три спрашиваются против НАСТОЯЩЕЙ базы
//
//   - `IsRevoked` службы отзыва (внутренний слушатель);
//   - авторитет отзыва `/internal/tokens/introspect` — сюда край идёт на пути
//     запроса за НАШИМ токеном;
//   - читатель предъявленного удостоверения на публичном слушателе.
//
// Писатели отзыва — настоящие: повтор обновляющего токена, повтор кода,
// снятие сессии, снятие клиента и прямой отзыв семейства по каждой причине
// закрытого словаря. Каждый повод подаётся ОТДЕЛЬНЫМ входом: реализация,
// судящая одну причину, зелена на половине класса.
//
// ВЫПУСК — НЕ НАСТОЯЩИЙ, и это граница пробы, а не её свойство. Выпуска токена
// доступа церемонии в дереве на этой ревизии нет (провязка — kaname#396), и
// `issueIn` его замещает: подписывает токен и сам пишет запись выпуска. Проба
// судит ЧТЕНИЕ решения тремя поверхностями; то, что настоящий выпуск пишет
// запись до ответа, держат ось гейта `internal/check` («выпуск пишет запись»)
// и сквозная проба выпуска, которую заводит провязка.
//
// # Таблица согласия
//
// По каждому поводу утверждается, что ВСЕ ТРИ поверхности отказывают. Одна
// поверхность, отказавшая при двух принявших, — ровно тот разрыв, ради
// которого решение сведено к одному читателю: вторая копия правила разошлась
// бы с первой молча и на своих пробах была бы зелена.
//
// # Почему отсечка субъекта обязана ОТСУТСТВОВАТЬ
//
// Токен несёт субъекта, и поверхности спрашивают и его. Повод, породивший
// вместо отзыва семейства отсечку человека, дал бы зелёную пробу при
// непровязанном семействе. Поэтому после каждого повода утверждается, что
// отсечки по субъекту НЕТ: отказ приходит от семейства, и только от него.
package pg_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// presentedAudience — адресат публичного слушателя в этой пробе.
const presentedAudience = "kaname-public.kacho.local"

// accessTokenRecorder — писатель записи выпуска: идентификатор выпуска →
// семейство. Звать его обязан выпуск токена доступа церемонии (kaname#396); на
// этой ревизии его зовёт только фикстура `issueIn`.
type accessTokenRecorder interface {
	RecordAccessToken(ctx context.Context, jti, familyID string, issuedAt, expiresAt time.Time) error
}

// recorderOf — писатель выпуска у хранилища церемонии. Отсутствие писателя —
// отсутствие предмета, и сказано оно здесь, а не ошибкой сборки.
func recorderOf(t *testing.T, repo *kanamepg.OAuthCeremonyRepo) accessTokenRecorder {
	t.Helper()
	rec, ok := any(repo).(accessTokenRecorder)
	require.True(t, ok,
		"у хранилища церемонии нет писателя выпуска токена доступа: семейство выпуска "+
			"службе узнать не из чего, и ответ о семействе не может появиться ни на одной поверхности")
	return rec
}

// familyRig — выпуск в семейство и три поверхности предъявления над одной
// базой.
type familyRig struct {
	pool     *pgxpool.Pool
	ceremony *kanamepg.OAuthCeremonyRepo
	recorder accessTokenRecorder
	signer   *tokensigner.Signer
	keys     issuanceKeys
	rig      issuanceRig
}

func newFamilyRig(t *testing.T, pool *pgxpool.Pool) familyRig {
	t.Helper()
	rig := newIssuanceRig(t)
	signer, err := tokensigner.New(tokensigner.Config{
		Issuer: assertionIssuer,
		// Выпуск в прошлом относительно часов базы: отметка выпуска секундной
		// точности не попадает в одну секунду с моментами, которые ставит база.
		Clock:       func() time.Time { return time.Now().UTC().Add(-time.Minute) },
		MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, rig.keys)
	require.NoError(t, err)
	ceremony := kanamepg.NewOAuthCeremonyRepo(pool)
	return familyRig{
		pool: pool, ceremony: ceremony, recorder: recorderOf(t, ceremony),
		signer: signer, keys: rig.keys, rig: rig,
	}
}

// issueIn выпускает токен доступа человеку сцены и записывает его в
// семейство — ЗАМЕСТО выпуска церемонии, которого в дереве пока нет: подпись и
// запись в том порядке, в каком их обязан исполнять настоящий выпуск.
func (f familyRig) issueIn(t *testing.T, scene domain.CeremonyContext) tokensigner.Token {
	t.Helper()
	tok, err := f.signer.Sign(context.Background(), tokensigner.Request{
		Subject:   scene.UserID,
		Audience:  []string{presentedAudience},
		TokenType: tokenpolicy.TokenTypeAccess,
		TTL:       assertionTokenTTL,
		Claims: map[string]any{
			domain.ClaimPrincipalType: "user",
			domain.ClaimPrincipalID:   scene.UserID,
		},
	})
	require.NoError(t, err, "подпись токена доступа")
	require.NoError(t, f.recorder.RecordAccessToken(context.Background(),
		tok.JTI, scene.FamilyID, tok.IssuedAt, tok.ExpiresAt), "запись выпуска в семейство")
	return tok
}

// surfaceVerdict — суждение трёх поверхностей об одном токене.
type surfaceVerdict struct {
	isRevoked         bool
	introspectActive  bool
	presentedAccepted bool
}

// judge спрашивает все три поверхности об одном токене.
//
// Читатель предъявленного строится НА КАЖДЫЙ вопрос: его кеш положительного
// вердикта — объявленное окно отзыва, и предмет этой пробы — не окно, а
// ответ. Окно судят пробы читателя с управляемыми часами.
func (f familyRig) judge(t *testing.T, tok tokensigner.Token) surfaceVerdict {
	t.Helper()
	ctx := context.Background()
	var out surfaceVerdict

	sr := session_revocations.NewHandler(nil, kanamepg.NewSessionRevocationsAdapter(f.pool))
	resp, err := sr.IsRevoked(ctx, &iamv1.IsRevokedRequest{TokenJti: tok.JTI})
	require.NoError(t, err, "IsRevoked обязан отвечать по существу")
	out.isRevoked = resp.GetRevoked()

	rec := askAuthority(t, newIntrospectAuthority(f.rig, kanamepg.NewMintedTokenRevocationRepo(f.pool)), tok.Token)
	require.Equal(t, http.StatusOK, rec.Code, "авторитет отзыва обязан отвечать по существу")
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	active, ok := body["active"].(bool)
	require.True(t, ok, "ответ авторитета обязан нести суждение: %v", body)
	out.introspectActive = active

	reader, err := presentedcred.New(presentedcred.Config{
		Issuer:             assertionIssuer,
		Audience:           presentedAudience,
		AllowedAlgorithms:  []string{tokenpolicy.AlgES256},
		Keys:               f.keys,
		Revocations:        kanamepg.NewMintedTokenRevocationRepo(f.pool),
		RevocationCacheTTL: time.Minute,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)
	pctx := metadata.NewIncomingContext(ctx, metadata.Pairs(presentedcred.MetadataKey, "Bearer "+tok.Token))
	_, perr := reader.UnaryOver(nil)(pctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.ProjectService/Get"},
		func(context.Context, any) (any, error) { return nil, nil })
	out.presentedAccepted = perr == nil
	if perr != nil {
		require.Zero(t, reader.Stats().Unavailable,
			"читатель предъявленного не смог ответить — это не суждение, а сбой: %v", perr)
	}
	return out
}

// requireAccepted — все три поверхности принимают.
func (f familyRig) requireAccepted(t *testing.T, tok tokensigner.Token, why string) {
	t.Helper()
	v := f.judge(t, tok)
	require.Equal(t, surfaceVerdict{isRevoked: false, introspectActive: true, presentedAccepted: true}, v,
		"%s: поверхности обязаны принимать выпуск (IsRevoked=false, active=true, принят)", why)
}

// requireRefusedByAll — все три поверхности отказывают. Отказ одной при
// принявших других — разрыв таблицы согласия, и он называется поимённо.
func (f familyRig) requireRefusedByAll(t *testing.T, tok tokensigner.Token, why string) {
	t.Helper()
	v := f.judge(t, tok)
	require.Equal(t, surfaceVerdict{isRevoked: true, introspectActive: false, presentedAccepted: false}, v,
		"%s: КАЖДАЯ поверхность обязана отказать выпуску отозванного семейства "+
			"(IsRevoked=true, active=false, отказ); получено IsRevoked=%v active=%v принят=%v",
		why, v.isRevoked, v.introspectActive, v.presentedAccepted)
}

// requireNoSubjectCutoff — отказ приходит от семейства, а не от отсечки
// человека.
func (f familyRig) requireNoSubjectCutoff(t *testing.T, userID string) {
	t.Helper()
	_, found, err := kanamepg.NewMintedTokenRevocationRepo(f.pool).RevokedBefore(context.Background(), userID)
	require.NoError(t, err)
	require.False(t, found,
		"повод породил отсечку ЧЕЛОВЕКА: отказ поверхностей неотличим от отзыва по субъекту, "+
			"и проба была бы зелена при непровязанном семействе")
}

// familyReason — причина отзыва семейства на строке; nil — семейство живо.
// Строки нет — семейство снято.
func familyReason(t *testing.T, pool *pgxpool.Pool, familyID string) (reason *string, present bool) {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM kaname.token_families WHERE id = $1`, familyID).Scan(&n))
	if n == 0 {
		return nil, false
	}
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`, familyID).Scan(&reason))
	return reason, true
}

// codeScene — семейство сцены с выданным и обменянным кодом: первое поколение
// обновляющего токена `rt` и выпуск токена доступа в семейство.
type codeScene struct {
	ctx  domain.CeremonyContext
	code string
	rt   string
	at   tokensigner.Token
}

func (f familyRig) exchangeIn(t *testing.T, scene domain.CeremonyContext, base int) codeScene {
	t.Helper()
	ctx := context.Background()
	code, rt := ceremonyDigest(base), ceremonyDigest(base+1)
	require.NoError(t, f.ceremony.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             scene,
		CodeDigest:          code,
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 time.Minute,
	}), "выдача кода")
	_, err := f.ceremony.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest: code, RefreshTokenDigest: rt, RefreshTokenTTL: time.Hour,
	})
	require.NoError(t, err, "обмен кода")
	return codeScene{ctx: scene, code: code, rt: rt, at: f.issueIn(t, scene)}
}

// siblingOf — второе семейство ТОГО ЖЕ человека, ТОГО ЖЕ клиента и той же
// сессии: другой код. Отличается от семейства сцены ровно идентификатором.
func siblingOf(scene domain.CeremonyContext, tag string) domain.CeremonyContext {
	out := scene
	out.FamilyID = "tfm-" + ceremonyPad(tag+"b")
	return out
}

// TestLINE_A_1_21_FamilyRevocationReachesEveryPresentationSurface — таблица
// согласия трёх поверхностей по каждому поводу отзыва.
func TestLINE_A_1_21_FamilyRevocationReachesEveryPresentationSurface(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	type cause struct {
		name string
		tag  string
		// apply исполняет повод НАСТОЯЩИМ писателем и возвращает ожидаемую
		// причину на строке семейства; пустая — семейство обязано быть снято.
		apply func(t *testing.T, f familyRig, a codeScene) string
		// twin — выживает ли семейство-близнец (другой код того же человека,
		// клиента и сессии). Повод, по определению снимающий всё в сессии или у
		// клиента, близнеца не имеет, и это сказано, а не умолчано.
		twin bool
	}

	causes := []cause{
		{
			name: "повтор отротированного обновляющего токена (LINE-A-1-21)",
			tag:  "frr",
			twin: true,
			apply: func(t *testing.T, f familyRig, a codeScene) string {
				// rt-1 законно ротирован в rt-2 (LINE-A-1-20), затем повторён.
				_, err := f.ceremony.RotateRefreshToken(context.Background(), kanamepg.RefreshRotation{
					PresentedDigest: a.rt, SuccessorDigest: ceremonyDigest(0x7e56), TTL: time.Hour,
				})
				require.NoError(t, err, "законная ротация rt-1 → rt-2")
				_, err = f.ceremony.RotateRefreshToken(context.Background(), kanamepg.RefreshRotation{
					PresentedDigest: a.rt, SuccessorDigest: ceremonyDigest(0x7e57), TTL: time.Hour,
				})
				require.True(t, domain.IsRefreshTokenReplay(err), "повтор обязан быть опознан: %v", err)
				return string(domain.FamilyRevokedByRefreshReplay)
			},
		},
		{
			name: "повтор кода авторизации",
			tag:  "fcr",
			twin: true,
			apply: func(t *testing.T, f familyRig, a codeScene) string {
				_, err := f.ceremony.ExchangeAuthorizationCode(context.Background(), kanamepg.CodeExchange{
					CodeDigest: a.code, RefreshTokenDigest: ceremonyDigest(0x7e58), RefreshTokenTTL: time.Hour,
				})
				require.True(t, domain.IsAuthorizationCodeReplay(err), "повтор обязан быть опознан: %v", err)
				return string(domain.FamilyRevokedByCodeReplay)
			},
		},
		{
			name: "снятие сессии распорядителем",
			tag:  "fse",
			apply: func(t *testing.T, f familyRig, a codeScene) string {
				ctx := context.Background()
				w, err := kanamepg.NewHumanSessionRepo(f.pool).ForceLogoutWriter(ctx,
					domain.UserID(a.ctx.UserID), time.Second)
				require.NoError(t, err)
				ended, err := w.EndOtherSessions(ctx, domain.UserID(a.ctx.UserID), "",
					time.Now().UTC(), domain.RevokeReasonLogout)
				require.NoError(t, err)
				require.NoError(t, w.Commit(ctx))
				require.Equal(t, 1, ended, "снята обязана быть ровно одна сессия сцены")
				return string(domain.FamilyRevokedBySessionEnd)
			},
		},
		{
			name: "снятие интерактивного клиента",
			tag:  "fcx",
			apply: func(t *testing.T, f familyRig, a codeScene) string {
				_, removed, err := kanamepg.NewInteractiveClientRepo(f.pool).Delete(context.Background(),
					domain.InteractiveClientID("ic-"+ceremonyPad("fcx")))
				require.NoError(t, err)
				require.True(t, removed, "клиент сцены обязан быть снят")
				return ""
			},
		},
	}
	for i, reason := range domain.FamilyRevocationReasons() {
		causes = append(causes, cause{
			name: "прямой отзыв семейства: " + string(reason),
			tag:  "fv" + string(rune('0'+i)),
			twin: true,
			apply: func(t *testing.T, f familyRig, a codeScene) string {
				require.NoError(t, f.ceremony.RevokeFamily(context.Background(), a.ctx.FamilyID, reason))
				return string(reason)
			},
		})
	}

	for _, c := range causes {
		t.Run(c.name, func(t *testing.T) {
			ctx, pool := catalogPool(t)
			f := newFamilyRig(t, pool)
			scene := ceremonyScene(t, ctx, pool, c.tag)

			a := f.exchangeIn(t, scene, 0x1000)
			b := f.exchangeIn(t, siblingOf(scene, c.tag), 0x2000)

			// T1 — положительный близнец: до повода все три поверхности
			// принимают выпуск обоих семейств.
			f.requireAccepted(t, a.at, "до повода, семейство A")
			f.requireAccepted(t, b.at, "до повода, семейство B")

			want := c.apply(t, f, a)

			// Условие создано: повод отозвал либо снял семейство A.
			reason, present := familyReason(t, pool, a.ctx.FamilyID)
			if want == "" {
				require.False(t, present, "семейство A обязано быть снято поводом")
			} else {
				require.True(t, present)
				require.NotNil(t, reason, "семейство A обязано быть отозвано поводом")
				require.Equal(t, want, *reason, "причина отзыва — причина повода")
			}
			f.requireNoSubjectCutoff(t, scene.UserID)

			// Сторона ПРЕДЪЯВЛЕНИЯ: ТОТ ЖЕ, ранее принятый выпуск.
			f.requireRefusedByAll(t, a.at, c.name)

			// T2 — близнец по семейству: другой код того же человека и клиента.
			if c.twin {
				f.requireAccepted(t, b.at, c.name+": семейство B не отзывали")
			}
		})
	}
}

// TestLINE_A_1_20_LawfulRotationRevokesNothing — T3: законная ротация не отзыв.
// Выпуск до ротации и выпуск после неё принимаются всеми тремя поверхностями;
// после ПОВТОРА старого обновляющего токена отвергаются оба — и тот, что выпущен
// ПОСЛЕ ротации, то есть отзыв семейства не судится моментом выпуска.
func TestLINE_A_1_20_LawfulRotationRevokesNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	f := newFamilyRig(t, pool)
	scene := ceremonyScene(t, ctx, pool, "frtn")

	a := f.exchangeIn(t, scene, 0x3000)
	rotated, err := f.ceremony.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
		PresentedDigest: a.rt, SuccessorDigest: ceremonyDigest(0x3002), TTL: time.Hour,
	})
	require.NoError(t, err, "законная ротация")
	require.EqualValues(t, 1, rotated.Generation, "ротация обязана дать следующее поколение")
	after := f.issueIn(t, scene)

	f.requireAccepted(t, a.at, "выпуск до законной ротации")
	f.requireAccepted(t, after, "выпуск после законной ротации")

	_, err = f.ceremony.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
		PresentedDigest: a.rt, SuccessorDigest: ceremonyDigest(0x3003), TTL: time.Hour,
	})
	require.True(t, domain.IsRefreshTokenReplay(err), "повтор старого обязан быть опознан: %v", err)

	f.requireRefusedByAll(t, a.at, "выпуск до ротации после повтора")
	f.requireRefusedByAll(t, after, "выпуск после ротации после повтора")
}
