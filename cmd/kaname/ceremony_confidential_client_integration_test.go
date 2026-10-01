// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_confidential_client_integration_test.go — секрет клиента, выданный
// глаголом `Create`, СКВОЗЬ КОРЕНЬ с провязанной церемонией (задача
// PRO-Robotech/kaname#405, приёмка
// docs/engineering/acceptance/confidential-interactive-client-secret-shown-once.md,
// сценарии IC-SECRET-06, 07 и журнал точки токена 13(а); DoD п.7).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ ПРОБЫ СЛОЯ ДОСТУПА
//
// Проба `internal/repo/kaname/pg/interactive_client_secret_integration_test.go`
// судит предъявление ПОРТОМ, которым церемония сверяет секрет. Здесь то же
// предъявление идёт ЗАПРОСОМ на токен-эндпоинт поверхности выдачи, собранной
// теми же вызовами, что корень (мир `ceremony_world_integration_test.go`,
// перепись монтажа сверена разбором `serve.go`), а клиент заведён ГЛАГОЛОМ над
// исполнителем, которого корень выбирает под посадкой `own`
// (`ownClientSecretHasher` + `interactiveClientProvider`, как
// `TestCompositionRoot_InteractiveClientCreateHasAnExecutorUnderOwnPosture`).
// Секрет S берётся из ответа того вызова — другого места, где он есть, у
// продукта нет. Поэтому здесь видно то, чего порт не видит: решает ли
// церемония о публичности клиента по его строке так, что клиента, заведённого
// продуктом, она СВЕРЯЕТ, и отдаёт ли полоса точки токена отказ словарём.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЖУРНАЛ — ОДИН ЗАХВАТ НА ОБА ПИСАТЕЛЯ
//
// Глагол заведения пишет в тот же захват, что поверхность (`w.logs`), поэтому
// проверка «S нет ни в одной строке» покрывает и заведение, и обмен.
// Положительный контроль — строка исхода обмена с `clientId` клиента: без неё
// «секрета нет» значило бы «журнала нет».
package main

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	interactiveclientapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// icSecretR — адрес возврата R приёмки (тот же, что REDIRECT набора края
// платформы `PRO-Robotech/kacho:gateway/tests/newman/cases/iam-interactive-client.py`,
// куда набор переехал из этого дерева); K заводится с `redirectUris = [R]`.
const icSecretR = "https://api.kacho.local/auth/callback"

// createClient заводит конфиденциального клиента ГЛАГОЛОМ `Create` своей
// посадки (сценарий 01) и отдаёт его запись, прочитанную обратно, и секрет из
// ответа вызова. Отказ заведения — отказ мира: предмет этих проб — обмен.
func (w *ceremonyWorld) createClient(name string) *ceremonyClient {
	w.t.Helper()
	cfg := loginLaneCfg()
	provider := mustOwnExecutor(w.t, cfg, kanamepg.NewOAuthCeremonyRepo(w.pool))
	repo := kanamepg.NewInteractiveClientRepo(w.pool)
	ops := operations.NewRepo(w.pool, "kaname")
	logger := slog.New(slog.NewJSONHandler(w.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := interactiveclientapp.NewHandler(
		interactiveclientapp.NewGetUseCase(repo),
		interactiveclientapp.NewListUseCase(repo),
		interactiveclientapp.NewCreateUseCase(repo, provider, ops, []string{"https://api.kacho.local"}, logger),
		interactiveclientapp.NewUpdateUseCase(repo, ops, logger),
		interactiveclientapp.NewDeleteUseCase(repo, provider, ops, logger),
	)

	ctx := operations.WithPrincipal(w.ctx, operations.SystemPrincipal())
	op, err := handler.Create(ctx, &iamv1.CreateInteractiveClientRequest{Name: name, RedirectUris: []string{icSecretR}})
	if err != nil {
		w.fixture("заведение клиента %s глаголом Create: %v", name, err)
	}
	if !op.GetDone() || op.GetError() != nil {
		w.fixture("заведение клиента %s не завершилось на пути запроса: done %v, ошибка %v", name, op.GetDone(), op.GetError())
	}
	var resp iamv1.CreateInteractiveClientResponse
	if err := op.GetResponse().UnmarshalTo(&resp); err != nil {
		w.fixture("ответ Create клиента %s — не CreateInteractiveClientResponse: %v", name, err)
	}
	if resp.GetClientSecret() == "" {
		w.fixture("ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ (01): заведение клиента %s секрета не выдало (способ %q)",
			name, resp.GetInteractiveClient().GetTokenEndpointAuthMethod())
	}
	got, err := repo.Get(w.ctx, domain.InteractiveClientID(resp.GetInteractiveClient().GetId()))
	if err != nil {
		w.fixture("клиент %s не читается обратно: %v", name, err)
	}
	if got.ClientID != resp.GetInteractiveClient().GetClientId() ||
		got.TokenEndpointAuthMethod != string(oauthceremony.ClientAuthBasic) || got.Status != domain.InteractiveClientActive {
		w.fixture("клиент %s прочитан не таким, каким заведён: clientId %q против %q, способ %q, статус %s",
			name, got.ClientID, resp.GetInteractiveClient().GetClientId(), got.TokenEndpointAuthMethod, got.Status)
	}
	// Клиент, заведённый глаголом, предъявляется НЕ своим `id`: иначе проба,
	// спутавшая колонки, прошла бы на посеве, где они равны.
	if got.ClientID == string(got.ID) {
		w.fixture("у клиента %s, заведённого глаголом, clientId равен id (%q): мир не различает колонки", name, got.ClientID)
	}
	return &ceremonyClient{rec: got, secret: resp.GetClientSecret()}
}

// mangleSecret — S с одним изменённым знаком (IC-SECRET-06 (б)).
func mangleSecret(secret string) string {
	if secret[0] == 'X' {
		return "Y" + secret[1:]
	}
	return "X" + secret[1:]
}

// requireInvalidClient — отказ аутентификации клиента: 401, слово
// `invalid_client` без предъявителя и вызов схемы Basic (RFC 6749 §5.2).
func requireInvalidClient(t *testing.T, id, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("%s: %s: ожидался 401 invalid_client, получен %d; тело %q", id, what, rec.Code, rec.Body.String())
		return
	}
	if tr := decodeToken(t, id, rec); tr.Error != "invalid_client" || tr.AccessToken != "" {
		t.Errorf("%s: %s: ожидался invalid_client без предъявителя, получено %q", id, what, rec.Body.String())
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("%s: %s: отказ не вызывает схему Basic: WWW-Authenticate %q", id, what, got)
	}
}

// journalRecord — строка захвата журнала в форме JSON-обработчика службы.
type journalRecord struct {
	Msg     string `json:"msg"`
	Outcome string `json:"outcome"`
	Client  string `json:"client"`
}

// journalOutcomes — исходы полосы точки токена, записанные о клиенте clientID,
// по порядку записи. Строка, не разбираемая как JSON, — отказ мира: захват
// пишет только обработчик службы.
func (w *ceremonyWorld) journalOutcomes(clientID string) []string {
	w.t.Helper()
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(w.logs.String()), "\n") {
		if line == "" {
			continue
		}
		var r journalRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			w.fixture("строка захвата журнала не разбирается: %v; %q", err, line)
		}
		if r.Client == clientID && r.Outcome != "" {
			out = append(out, r.Outcome)
		}
	}
	return out
}

// requireJournalCarriesNoSecret — IC-SECRET-13(а): ни одна строка захвата не
// несёт секрета ни в одной из форм, в которых он побывал в запросе: как есть,
// искажённым и парой Basic (там он стоит только в base64, и проверка на
// подстроку S его не видит).
func (w *ceremonyWorld) requireJournalCarriesNoSecret(c *ceremonyClient) {
	w.t.Helper()
	journal := w.logs.String()
	for form, v := range map[string]string{
		"секрет клиента":            c.secret,
		"искажённый секрет клиента": mangleSecret(c.secret),
		"пара Basic": base64.StdEncoding.EncodeToString(
			[]byte(c.rec.ClientID + ":" + c.secret)),
	} {
		if strings.Contains(journal, v) {
			w.t.Errorf("%s: журнал службы несёт %s (клиент %s, 13(а))", w.id, form, c.rec.ClientID)
		}
	}
}

// requireOutcomeJournaled — положительный контроль журнала: исход полосы
// точки токена записан о клиенте c (LINE-A-1-24: запись на каждый исход).
func (w *ceremonyWorld) requireOutcomeJournaled(c *ceremonyClient, want ceremonyhttp.Outcome, what string) {
	w.t.Helper()
	for _, got := range w.journalOutcomes(c.rec.ClientID) {
		if got == string(want) {
			return
		}
	}
	w.t.Errorf("%s: %s: в захвате нет строки исхода %q о клиенте %s — «секрета нет» значило бы «журнала нет»; "+
		"исходы о нём: %v", w.id, what, want, c.rec.ClientID, w.journalOutcomes(c.rec.ClientID))
}

// TestIntegration_IC06_SecretFromCreatePassesTheExchangeThroughTheRoot —
// IC-SECRET-06 сквозь корень: секрет из ответа `Create` проходит обмен кода
// (положительный близнец LINE-A-1-12 на клиенте, заведённом продуктом), а на
// ТОМ ЖЕ клиенте и ТОМ ЖЕ коде отказывают обе отрицательные ветки, в каждой
// из которых клиент назван и меняется ровно доказательство:
//
//	(а) доказательство не предъявлено — заголовка нет, клиент назван полем
//	    формы `client_id`;
//	(б) доказательство неверно — пара Basic с S, искажённым в одном знаке.
//
// Отрицательные ветки идут ДО положительной и тем же кодом: отказ
// аутентификации клиента решается до именования кода (LINE-A-1-12) и кода не
// гасит, поэтому близнец отличается от ветки ровно доказательством.
func TestIntegration_IC06_SecretFromCreatePassesTheExchangeThroughTheRoot(t *testing.T) {
	w := newCeremonyWorld(t, "IC-SECRET-06", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()
	k := w.createClient("ic-secret-06")

	ic := w.issueCode(k, icSecretR)
	form := exchangeForm(ic)
	if form.Get("client_id") != k.rec.ClientID {
		w.fixture("форма обмена называет клиента %q, а не его clientId %q", form.Get("client_id"), k.rec.ClientID)
	}

	requireInvalidClient(t, w.id, "(а) доказательство не предъявлено, клиент назван полем формы",
		w.post(clienttokenhttp.TokenPath, form, nil))
	requireInvalidClient(t, w.id, "(б) секрет искажён в одном знаке",
		w.post(clienttokenhttp.TokenPath, form, []string{k.rec.ClientID, mangleSecret(k.secret)}))

	tr := w.redeem(ic)
	claims := w.bearerClaims(tr.AccessToken)
	if sub, _ := claims["sub"].(string); sub != string(w.user) {
		t.Errorf("%s: предъявитель обмена несёт sub=%q, ожидался субъект сессии %q", w.id, sub, w.user)
	}

	w.requireOutcomeJournaled(k, ceremonyhttp.OutcomeExchangeCodeExchanged, "обмен секретом из ответа Create")
	w.requireOutcomeJournaled(k, ceremonyhttp.OutcomeExchangeClientRefused, "отказ веткам (а) и (б)")
	w.requireJournalCarriesNoSecret(k)
}

// TestIntegration_IC07_SecretIsBoundToItsClientThroughTheRoot — IC-SECRET-07
// сквозь корень: два заведения выдают разные секреты, и секрет второго
// клиента, предъявленный с `clientId` первого, получает ПОБАЙТОВО тот же
// отказ, что неверный секрет. Близнец — пара первого клиента со своим
// секретом на том же коде: 200; отличие в одном факте — чей секрет предъявлен.
func TestIntegration_IC07_SecretIsBoundToItsClientThroughTheRoot(t *testing.T) {
	w := newCeremonyWorld(t, "IC-SECRET-07", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()
	k1 := w.createClient("ic-secret-07-first")
	k2 := w.createClient("ic-secret-07-second")
	if k1.secret == k2.secret {
		t.Fatalf("%s: два заведения выдали один секрет", w.id)
	}

	ic := w.issueCode(k1, icSecretR)
	foreign := w.post(clienttokenhttp.TokenPath, exchangeForm(ic), []string{k1.rec.ClientID, k2.secret})
	wrong := w.post(clienttokenhttp.TokenPath, exchangeForm(ic), []string{k1.rec.ClientID, mangleSecret(k1.secret)})
	requireInvalidClient(t, w.id, "секрет второго клиента с clientId первого", foreign)
	requireInvalidClient(t, w.id, "неверный секрет (эталон отказа LINE-A-1-12)", wrong)
	if foreign.Code != wrong.Code || foreign.Body.String() != wrong.Body.String() ||
		foreign.Header().Get("WWW-Authenticate") != wrong.Header().Get("WWW-Authenticate") {
		t.Errorf("%s: чужой секрет отличим от неверного: %d %q %q против %d %q %q", w.id,
			foreign.Code, foreign.Header().Get("WWW-Authenticate"), foreign.Body.String(),
			wrong.Code, wrong.Header().Get("WWW-Authenticate"), wrong.Body.String())
	}

	w.redeem(ic)

	w.requireOutcomeJournaled(k1, ceremonyhttp.OutcomeExchangeCodeExchanged, "обмен своим секретом")
	w.requireOutcomeJournaled(k1, ceremonyhttp.OutcomeExchangeClientRefused, "отказ чужому секрету")
	w.requireJournalCarriesNoSecret(k1)
	w.requireJournalCarriesNoSecret(k2)
}
