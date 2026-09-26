// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// interactive_client_secret_integration_test.go — секрет конфиденциального
// интерактивного клиента собственного реестра, судимый ПО БАЗЕ (задача
// PRO-Robotech/kaname#405, приёмка
// docs/engineering/acceptance/confidential-interactive-client-secret-shown-once.md,
// сценарии IC-SECRET-01…05, 07, 08…10, 13).
//
// Мир собран из ПРОДУКТОВЫХ частей, а не из копий: глаголы ресурса над
// настоящими хранилищами ресурса и операций, исполнитель заведения посадки
// `own` с хешером того же класса, что пароли, и порт сверки секрета, которым
// сверяет церемония (`ceremonyport.ClientSecrets`), с выровненным
// проверяющим. Секрет S берётся из ответа вызова `Create` — другого места, где
// он есть, у продукта нет, и проба ищет его ПО ЗНАЧЕНИЮ.
//
// # Чего здесь нет — названо
//
// Обмен кода сквозь токен-эндпоинт с провязанной церемонией (IC-SECRET-06, 07
// сквозь корень, журнал точки токена в 13(а)) судится там, где церемония
// провязана в корне; здесь предъявление судится ПОРТОМ, которым церемония
// сверяет секрет, — тем же вызовом, с тем же вердиктом.

import (
	"context"
	"encoding/base64"
	stderrors "errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/operations"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/logbuf"
)

// icRedirect — адрес возврата R приёмки (тот же, что GOOD_REDIRECT набора
// `tests/newman/cases/iam-interactive-client.py`).
const icRedirect = "https://api.kacho.local/auth/callback"

// icPHC — форма проверочного значения колонки (ограничение
// `interactive_clients_secret_verifier_form_ck`).
var icPHC = regexp.MustCompile(`^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`)

// icSecretWorld — глаголы ресурса над настоящими хранилищами и порт сверки.
type icSecretWorld struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	repo     *kanamepg.InteractiveClientRepo
	ceremony *kanamepg.OAuthCeremonyRepo
	ops      operations.Repo
	provider *kanamepg.OwnInteractiveClientProvider
	journal  *logbuf.Buffer
	logger   *slog.Logger
	handler  *interactiveclient.Handler
	secrets  *ceremonyport.ClientSecrets
}

func newICSecretWorld(t *testing.T) *icSecretWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := operations.WithPrincipal(context.Background(), operations.SystemPrincipal())
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	w := &icSecretWorld{t: t, ctx: ctx, pool: pool,
		repo:     kanamepg.NewInteractiveClientRepo(pool),
		ceremony: kanamepg.NewOAuthCeremonyRepo(pool),
		ops:      operations.NewRepo(pool, "kaname"),
		journal:  &logbuf.Buffer{},
	}
	w.logger = slog.New(slog.NewJSONHandler(w.journal, &slog.HandlerOptions{Level: slog.LevelDebug}))
	w.provider, err = kanamepg.NewOwnInteractiveClientProvider(w.ceremony, floorHasher(t))
	require.NoError(t, err)
	w.handler = w.handlerOver(w.repo)

	checker, err := passwordverify.New(4, nopObserver{})
	require.NoError(t, err)
	decoy, err := floorHasher(t).Hash("decoy-nobody-knows")
	require.NoError(t, err)
	require.NoError(t, checker.SetDecoy(decoy))
	w.secrets, err = ceremonyport.NewClientSecrets(w.ceremony, checker)
	require.NoError(t, err)
	return w
}

// icClientStore — то, что глаголы ресурса требуют от хранилища. Объявлено
// здесь, чтобы подмена одного оператора (13(б)) была выразима обёрткой.
type icClientStore interface {
	Get(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, error)
	List(ctx context.Context, limit int, pageToken, nameFilter string) ([]domain.InteractiveClient, string, error)
	Insert(ctx context.Context, c domain.InteractiveClient, material domain.LoginVerifier) (domain.InteractiveClient, error)
	Update(ctx context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error)
	Delete(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, bool, error)
}

func (w *icSecretWorld) handlerOver(store icClientStore) *interactiveclient.Handler {
	return interactiveclient.NewHandler(
		interactiveclient.NewGetUseCase(store),
		interactiveclient.NewListUseCase(store),
		interactiveclient.NewCreateUseCase(store, w.provider, w.ops, []string{"https://api.kacho.local"}, w.logger),
		interactiveclient.NewUpdateUseCase(store, w.ops, w.logger),
		interactiveclient.NewDeleteUseCase(store, w.provider, w.ops, w.logger),
	)
}

// create — `Create` с payload сценария 01; разбор ответа — только при успехе.
func (w *icSecretWorld) create(h *interactiveclient.Handler, name string) (*operationpb.Operation, *iamv1.CreateInteractiveClientResponse, error) {
	w.t.Helper()
	op, err := h.Create(w.ctx, &iamv1.CreateInteractiveClientRequest{Name: name, RedirectUris: []string{icRedirect}})
	if err != nil {
		return op, nil, err
	}
	require.True(w.t, op.GetDone(), "Create обязан завершаться на пути запроса")
	require.Nil(w.t, op.GetError(), "Create завершился ошибкой")
	var resp iamv1.CreateInteractiveClientResponse
	require.NoError(w.t, op.GetResponse().UnmarshalTo(&resp), "ответ Create — CreateInteractiveClientResponse (Р4)")
	return op, &resp, nil
}

// mustCreate — заведение, которое обязано пройти и выдать секрет.
func (w *icSecretWorld) mustCreate(name string) (*operationpb.Operation, *iamv1.CreateInteractiveClientResponse) {
	w.t.Helper()
	op, resp, err := w.create(w.handler, name)
	require.NoError(w.t, err, "заведение %s", name)
	require.NotEmpty(w.t, resp.GetClientSecret(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: заведение секрета не выдало")
	return op, resp
}

// verdict — вердикт порта сверки церемонии на паре (clientId, секрет).
func (w *icSecretWorld) verdict(clientID, secret string) oauthceremony.SecretVerdict {
	w.t.Helper()
	v, err := w.secrets.VerifyClientSecret(w.ctx, clientID, oauthceremony.NewPresentedSecret(secret))
	require.NoError(w.t, err, "порт сверки не ответил вердиктом")
	return v
}

// basicPair — значение заголовка `Authorization: Basic` пары (RFC 6749
// §2.3.1): секрет в нём стоит только в base64, и проверка на подстроку S его
// не видит.
func basicPair(clientID, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(clientID + ":" + secret))
}

func mangle(secret string) string {
	if secret[0] == 'X' {
		return "Y" + secret[1:]
	}
	return "X" + secret[1:]
}

// requireJournalClean — захват журнала не несёт секрета, пары Basic и
// искажённого секрета (условие поверхности п.3).
func (w *icSecretWorld) requireJournalClean(clientID, secret string) {
	w.t.Helper()
	journal := w.journal.String()
	for form, v := range map[string]string{
		"секрет":            secret,
		"искажённый секрет": mangle(secret),
		"пара Basic":        basicPair(clientID, secret),
	} {
		require.NotContains(w.t, journal, v, "журнал несёт %s", form)
	}
}

// TestIntegration_IC01_02_03_SecretIsShownOnceAndStoredAsItsVerifier —
// IC-SECRET-01 (секрет в ответе вызова), 02 (строка операции его не несёт ни в
// какой момент) и 03 (строка реестра несёт проверочное значение ЭТОГО секрета,
// а не секрет).
func TestIntegration_IC01_02_03_SecretIsShownOnceAndStoredAsItsVerifier(t *testing.T) {
	w := newICSecretWorld(t)

	op, resp := w.mustCreate("ic-secret-shown-once")
	answeredAt := time.Now()
	ic := resp.GetInteractiveClient()
	s := resp.GetClientSecret()

	// 01.
	require.Regexp(t, `^ic-[0-9a-hjkmnp-tv-z]{17}$`, ic.GetId())
	require.True(t, strings.HasPrefix(ic.GetClientId(), "oic-"), "clientId = %q", ic.GetClientId())
	require.Equal(t, "client_secret_basic", ic.GetTokenEndpointAuthMethod())
	require.Equal(t, []string{"authorization_code", "refresh_token"}, ic.GetGrantTypes())
	require.Equal(t, iamv1.InteractiveClient_ACTIVE, ic.GetStatus())
	require.Zero(t, ic.GetCreatedAt().GetNanos(), "createdAt усечён до секунд")
	got, err := w.handler.Get(w.ctx, &iamv1.GetInteractiveClientRequest{InteractiveClientId: ic.GetId()})
	require.NoError(t, err)
	require.Equal(t, ic.GetClientId(), got.GetClientId())
	require.Equal(t, ic.GetTokenEndpointAuthMethod(), got.GetTokenEndpointAuthMethod())

	// 02: строка операции — в пределах той же секунды после ответа, раньше
	// любого окна затирания в дереве (120 с у ключа служебной учётки и токена
	// пользователя). Проба краснела бы на «положить и стереть позже».
	stored, err := w.ops.Get(w.ctx, op.GetId())
	require.NoError(t, err)
	var storedResp iamv1.CreateInteractiveClientResponse
	require.NoError(t, stored.Response.UnmarshalTo(&storedResp))
	var raw []byte
	require.NoError(t, w.pool.QueryRow(w.ctx,
		`SELECT response_data FROM kaname.operations WHERE id = $1`, op.GetId()).Scan(&raw))
	readAfter := time.Since(answeredAt)
	t.Logf("строка операции прочитана через %s после ответа Create", readAfter)
	require.Less(t, readAfter, time.Second, "чтение обязано быть в пределах секунды после ответа")
	require.Contains(t, string(raw), ic.GetId(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тело строки операции не несёт id клиента")
	require.NotContains(t, string(raw), s, "тело строки операции несёт секрет подстрокой")
	require.Empty(t, storedResp.GetClientSecret(), "OperationService.Get отдаёт секрет")
	require.True(t, proto.Equal(ic, storedResp.GetInteractiveClient()), "ресурс в строке операции не тот, что в ответе вызова")

	// 03.
	var row string
	require.NoError(t, w.pool.QueryRow(w.ctx,
		`SELECT row_to_json(c)::text FROM kaname.interactive_clients c WHERE id = $1`, ic.GetId()).Scan(&row))
	require.NotContains(t, row, s, "строка реестра несёт секрет")
	var material string
	var setAt *time.Time
	require.NoError(t, w.pool.QueryRow(w.ctx,
		`SELECT secret_verifier, secret_verifier_set_at FROM kaname.interactive_clients WHERE id = $1`,
		ic.GetId()).Scan(&material, &setAt))
	require.Regexp(t, icPHC, material, "проверочное значение не argon2id PHC")
	require.NotNil(t, setAt, "момент установки проверочного значения не задан")
	require.Equal(t, oauthceremony.SecretMatched, w.verdict(ic.GetClientId(), s), "порт сверки не узнал выданный секрет")
	require.Equal(t, oauthceremony.SecretMismatched, w.verdict(ic.GetClientId(), mangle(s)),
		"порт сверки принял секрет с одним изменённым знаком")

	w.requireJournalClean(ic.GetClientId(), s)
}

// TestIntegration_IC04_TakenNameIssuesNoSecretAndLeavesNoMaterial —
// IC-SECRET-04: второе заведение того же имени — синхронный 409 без операции и
// без секрета; строка его операции несёт ошибку без ответа; материал первого
// не тронут.
func TestIntegration_IC04_TakenNameIssuesNoSecretAndLeavesNoMaterial(t *testing.T) {
	w := newICSecretWorld(t)
	const name = "ic-secret-taken"
	firstOp, first := w.mustCreate(name)
	k := first.GetInteractiveClient()

	op, _, err := w.create(w.handler, name)
	require.Error(t, err, "второе заведение того же имени прошло")
	require.Nil(t, op, "отказ заведения обязан быть синхронным, без операции")
	st, _ := status.FromError(err)
	require.Equal(t, codes.AlreadyExists, st.Code())
	require.NotContains(t, err.Error(), first.GetClientSecret())

	page, err := w.handler.List(w.ctx, &iamv1.ListInteractiveClientsRequest{Filter: `name="` + name + `"`})
	require.NoError(t, err)
	require.Len(t, page.GetInteractiveClients(), 1)
	require.Equal(t, k.GetId(), page.GetInteractiveClients()[0].GetId())

	var others int
	var errCode *int32
	var respData []byte
	rows, err := w.pool.Query(w.ctx, `SELECT error_code, response_data FROM kaname.operations
		WHERE description = $1 AND id <> $2`, "Create interactive client "+name, firstOp.GetId())
	require.NoError(t, err)
	for rows.Next() {
		others++
		require.NoError(t, rows.Scan(&errCode, &respData))
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, 1, others, "строка операции отвергнутого заведения не найдена")
	require.NotNil(t, errCode, "строка операции отвергнутого заведения не несёт ошибки")
	require.Equal(t, int32(codes.AlreadyExists), *errCode)
	require.Nil(t, respData, "строка операции отвергнутого заведения несёт ответ")

	var withName, withMaterial int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*), count(*) FILTER (WHERE secret_verifier <> '')
		FROM kaname.interactive_clients WHERE name = $1`, name).Scan(&withName, &withMaterial))
	require.Equal(t, 1, withName)
	require.Equal(t, 1, withMaterial)
	require.Equal(t, oauthceremony.SecretMatched, w.verdict(k.GetClientId(), first.GetClientSecret()),
		"отказ второго заведения тронул материал первого")
	w.requireJournalClean(k.GetClientId(), first.GetClientSecret())
}

// TestIntegration_IC05_ConcurrentCreatesOfOneNameIssueOneSecret — IC-SECRET-05:
// одно имя, два одновременных заведения — одна строка, один секрет, и его
// проверочное значение — секрета победителя. Близнец: разные имена — оба
// заведены, секреты различны.
func TestIntegration_IC05_ConcurrentCreatesOfOneNameIssueOneSecret(t *testing.T) {
	w := newICSecretWorld(t)

	race := func(names ...string) ([]*iamv1.CreateInteractiveClientResponse, []error) {
		var wg sync.WaitGroup
		start := make(chan struct{})
		resps := make([]*iamv1.CreateInteractiveClientResponse, len(names))
		errs := make([]error, len(names))
		for i, n := range names {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				op, err := w.handler.Create(w.ctx, &iamv1.CreateInteractiveClientRequest{Name: n, RedirectUris: []string{icRedirect}})
				if err != nil {
					errs[i] = err
					return
				}
				var r iamv1.CreateInteractiveClientResponse
				errs[i] = op.GetResponse().UnmarshalTo(&r)
				resps[i] = &r
			}()
		}
		close(start)
		wg.Wait()
		return resps, errs
	}

	resps, errs := race("ic-secret-race", "ic-secret-race")
	var winner *iamv1.CreateInteractiveClientResponse
	refused := 0
	for i := range resps {
		switch {
		case errs[i] == nil:
			require.Nil(t, winner, "оба заведения одного имени прошли")
			winner = resps[i]
		case status.Code(errs[i]) == codes.AlreadyExists:
			refused++
		default:
			t.Fatalf("заведение отказало не по занятому имени: %v", errs[i])
		}
	}
	require.NotNil(t, winner, "ни одно заведение не прошло")
	require.Equal(t, 1, refused)
	require.NotEmpty(t, winner.GetClientSecret())
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.interactive_clients WHERE name = $1`,
		"ic-secret-race").Scan(&n))
	require.Equal(t, 1, n)
	require.Equal(t, oauthceremony.SecretMatched,
		w.verdict(winner.GetInteractiveClient().GetClientId(), winner.GetClientSecret()))

	// БЛИЗНЕЦ: разные имена.
	resps, errs = race("ic-secret-race-a", "ic-secret-race-b")
	for i := range resps {
		require.NoError(t, errs[i], "заведение с разными именами отказало")
	}
	require.NotEqual(t, resps[0].GetClientSecret(), resps[1].GetClientSecret(), "два заведения выдали один секрет")
}

// TestIntegration_IC07_SecretIsBoundToItsClient — IC-SECRET-07 на порте
// сверки: чужой секрет своему клиенту — тот же вердикт, что неверный.
func TestIntegration_IC07_SecretIsBoundToItsClient(t *testing.T) {
	w := newICSecretWorld(t)
	_, k1 := w.mustCreate("ic-secret-bound-1")
	_, k2 := w.mustCreate("ic-secret-bound-2")
	require.NotEqual(t, k1.GetClientSecret(), k2.GetClientSecret())
	id1 := k1.GetInteractiveClient().GetClientId()
	require.Equal(t, oauthceremony.SecretMatched, w.verdict(id1, k1.GetClientSecret()), "БЛИЗНЕЦ: свой секрет")
	require.Equal(t, oauthceremony.SecretMismatched, w.verdict(id1, k2.GetClientSecret()), "чужой секрет принят")
}

// TestIntegration_IC08_09_ReadsAndUpdatesCarryNoSecret — IC-SECRET-08 и 09:
// `Get`, `List` и `Update` секрета не несут; маской его не задать, способ не
// переключить. Сверка по ЗНАЧЕНИЮ S, а не образцом имени.
func TestIntegration_IC08_09_ReadsAndUpdatesCarryNoSecret(t *testing.T) {
	w := newICSecretWorld(t)
	const name = "ic-secret-reads"
	_, created := w.mustCreate(name)
	k := created.GetInteractiveClient()
	s := created.GetClientSecret()

	// 08.
	got, err := w.handler.Get(w.ctx, &iamv1.GetInteractiveClientRequest{InteractiveClientId: k.GetId()})
	require.NoError(t, err)
	body, err := protojson.Marshal(got)
	require.NoError(t, err)
	require.Contains(t, string(body), k.GetClientId(), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тело Get не несёт clientId")
	require.Equal(t, "client_secret_basic", got.GetTokenEndpointAuthMethod())
	require.NotContains(t, string(body), s, "Get отдаёт секрет")
	require.Equal(t, oauthceremony.SecretMatched, w.verdict(k.GetClientId(), s), "секрет существует — его нет в ответе")

	// 09 (а).
	page, err := w.handler.List(w.ctx, &iamv1.ListInteractiveClientsRequest{Filter: `name="` + name + `"`})
	require.NoError(t, err)
	require.Len(t, page.GetInteractiveClients(), 1)
	require.True(t, proto.Equal(got, page.GetInteractiveClients()[0]), "List отдаёт другую проекцию, чем Get")
	pageBody, err := protojson.Marshal(page)
	require.NoError(t, err)
	require.NotContains(t, string(pageBody), s, "List отдаёт секрет")

	// 09 (б) — близнец (в) и (г): изменяемое поле проходит.
	op, err := w.handler.Update(w.ctx, &iamv1.UpdateInteractiveClientRequest{
		InteractiveClientId: k.GetId(), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"description"}},
		Description: "rotated description",
	})
	require.NoError(t, err)
	require.True(t, op.GetDone())
	require.Nil(t, op.GetError())
	var updated iamv1.InteractiveClient
	require.NoError(t, op.GetResponse().UnmarshalTo(&updated))
	require.Equal(t, "rotated description", updated.GetDescription())
	require.NotContains(t, string(op.GetResponse().GetValue()), s, "ответ Update несёт секрет")
	require.Equal(t, oauthceremony.SecretMatched, w.verdict(k.GetClientId(), s), "Update тронул материал")

	// 09 (в): маска с полем секрета.
	_, err = w.handler.Update(w.ctx, &iamv1.UpdateInteractiveClientRequest{
		InteractiveClientId: k.GetId(), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"clientSecret"}},
	})
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "invalid argument", st.Message())
	var violation *errdetails.BadRequest_FieldViolation
	for _, d := range st.Details() {
		if br, ok := d.(*errdetails.BadRequest); ok && len(br.GetFieldViolations()) > 0 {
			violation = br.GetFieldViolations()[0]
		}
	}
	require.NotNil(t, violation, "текст неизвестного поля маски обязан стоять в деталях BadRequest")
	require.Equal(t, "update_mask", violation.GetField())
	require.Equal(t, "unknown field in update_mask: client_secret", violation.GetDescription())

	// 09 (г): маска со способом.
	_, err = w.handler.Update(w.ctx, &iamv1.UpdateInteractiveClientRequest{
		InteractiveClientId: k.GetId(), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"tokenEndpointAuthMethod"}},
	})
	st, _ = status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "token_endpoint_auth_method is immutable after InteractiveClient.Create", st.Message())
	require.Equal(t, oauthceremony.SecretMatched, w.verdict(k.GetClientId(), s), "отвергнутая маска тронула материал")
	w.requireJournalClean(k.GetClientId(), s)
}

// TestIntegration_IC10_DeletionLeavesNoUsableSecret — IC-SECRET-10: сняли
// клиента → предъявили прежний секрет → получили тот же вердикт, что неверный
// секрет и никогда не заводившийся клиент. Вопрос ставится сквозь обе стороны
// одной пробой.
func TestIntegration_IC10_DeletionLeavesNoUsableSecret(t *testing.T) {
	w := newICSecretWorld(t)
	_, created := w.mustCreate("ic-secret-deleted")
	k := created.GetInteractiveClient()
	s := created.GetClientSecret()
	require.Equal(t, oauthceremony.SecretMatched, w.verdict(k.GetClientId(), s), "БЛИЗНЕЦ: до снятия секрет проходит")

	op, err := w.handler.Delete(w.ctx, &iamv1.DeleteInteractiveClientRequest{InteractiveClientId: k.GetId()})
	require.NoError(t, err)
	require.True(t, op.GetDone())
	require.Nil(t, op.GetError())
	var echo iamv1.InteractiveClient
	require.NoError(t, op.GetResponse().UnmarshalTo(&echo))
	require.Equal(t, k.GetId(), echo.GetId())
	require.NotContains(t, string(op.GetResponse().GetValue()), s, "эхо снятого ресурса несёт секрет")

	never := w.verdict("oic-neverregistered000", s)
	require.Equal(t, oauthceremony.SecretMismatched, never)
	require.Equal(t, never, w.verdict(k.GetClientId(), s),
		"снятый клиент отличим от никогда не заводившегося")
	require.Equal(t, w.verdict(k.GetClientId(), mangle(s)), w.verdict(k.GetClientId(), s),
		"снятый клиент отличим от неверного секрета")

	_, err = w.handler.Get(w.ctx, &iamv1.GetInteractiveClientRequest{InteractiveClientId: k.GetId()})
	st, _ := status.FromError(err)
	require.Equal(t, codes.NotFound, st.Code())
	require.Equal(t, fmt.Sprintf("InteractiveClient %s not found", k.GetId()), st.Message())

	_, _, err = w.ceremony.ClientSecretVerifier(w.ctx, k.GetClientId())
	require.True(t, stderrors.Is(err, iamerr.ErrNotFound), "справочник проверочных значений знает снятого клиента: %v", err)

	again, err := w.handler.Delete(w.ctx, &iamv1.DeleteInteractiveClientRequest{InteractiveClientId: k.GetId()})
	require.NoError(t, err, "повторное снятие обязано дать тот же исход")
	require.True(t, again.GetDone())
	require.Nil(t, again.GetError())
	w.requireJournalClean(k.GetClientId(), s)
}

// insertSubstitute — настоящее хранилище, у которого подменён ОДИН оператор —
// вставка строки.
type insertSubstitute struct {
	*kanamepg.InteractiveClientRepo
	refusal error
}

func (r insertSubstitute) Insert(context.Context, domain.InteractiveClient, domain.LoginVerifier) (domain.InteractiveClient, error) {
	return domain.InteractiveClient{}, r.refusal
}

// TestIntegration_IC13b_InternalInsertRefusalEchoesNothing — IC-SECRET-13(б):
// отказ вставки ВНЕ словаря отказов — синхронный `INTERNAL` фиксированным
// текстом; ни маркера, ни секрета; ни строки, ни материала. Близнец — отказ
// «имя занято» той же подменой: 409 с текстом полосы 04.
func TestIntegration_IC13b_InternalInsertRefusalEchoesNothing(t *testing.T) {
	w := newICSecretWorld(t)
	const marker = "storage-marker-7d1e exploded"
	const name = "ic-secret-refused"

	h := w.handlerOver(insertSubstitute{InteractiveClientRepo: w.repo, refusal: stderrors.New(marker)})
	op, _, err := w.create(h, name)
	require.Nil(t, op, "отказ обязан быть синхронным, без операции")
	st, _ := status.FromError(err)
	require.Equal(t, codes.Internal, st.Code())
	require.Equal(t, "internal error", st.Message())
	require.NotContains(t, err.Error(), marker, "отказ эхает текст хранилища")
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.interactive_clients WHERE name = $1`, name).Scan(&n))
	require.Zero(t, n, "строка отказавшего заведения осталась")
	require.NotContains(t, w.journal.String(), marker, "журнал заведения эхает текст хранилища вне словаря")

	// БЛИЗНЕЦ: та же подмена отказывает признаком «имя занято» — текстом полосы
	// 04, снятым с настоящего хранилища.
	_, _ = w.mustCreate("ic-secret-refused-twin")
	_, _, realDup := w.create(w.handler, "ic-secret-refused-twin")
	realSt, _ := status.FromError(realDup)
	require.Equal(t, codes.AlreadyExists, realSt.Code(), "ПРЕДУСЛОВИЕ: настоящая полоса 04")
	h = w.handlerOver(insertSubstitute{InteractiveClientRepo: w.repo,
		refusal: iamerr.Wrapf(iamerr.ErrAlreadyExists, "%s", realSt.Message())})
	_, _, err = w.create(h, name)
	st, _ = status.FromError(err)
	require.Equal(t, codes.AlreadyExists, st.Code())
	require.Equal(t, realSt.Message(), st.Message())
}

// TestIntegration_MalformedVerifierIsOurDefectNotTheCallers — условие
// поверхности п.10: негодное проверочное значение, дошедшее до вставки, —
// отказ полосы «значение производителя» (`INTERNAL` фиксированным текстом),
// а не `INVALID_ARGUMENT`; ни отказ, ни журнал не несут материала.
func TestIntegration_MalformedVerifierIsOurDefectNotTheCallers(t *testing.T) {
	w := newICSecretWorld(t)
	var captured logbuf.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&captured, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	const material = "$argon2id$v=19$m=1,t=1,p=1$not-a-salt$not-a-body-marker-5f2"
	bad, err := domain.NewLoginVerifier(material)
	require.NoError(t, err)
	_, err = w.repo.Insert(w.ctx, domain.InteractiveClient{
		ID: "ic-00000000000000009", Name: "ic-secret-bad-phc",
		RedirectURIs: []string{icRedirect}, PostLogoutRedirectURIs: []string{},
		ClientID: "oic-badphc0000000000000", Audiences: []string{"https://api.kacho.local"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "client_secret_basic", Status: domain.InteractiveClientActive,
	}, bad)
	require.Error(t, err, "схема приняла негодное проверочное значение")
	mapped := shared.MapRepoErr(err)
	st, _ := status.FromError(mapped)
	require.Equal(t, codes.Internal, st.Code())
	require.Equal(t, "internal error", st.Message())
	require.NotContains(t, err.Error(), "not-a-body-marker-5f2", "отказ несёт материал")
	require.Contains(t, captured.String(), "interactive client backstop fired",
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: строки о сработавшем ограничении в журнале нет")
	require.NotContains(t, captured.String(), "not-a-body-marker-5f2", "журнал несёт материал")
}
