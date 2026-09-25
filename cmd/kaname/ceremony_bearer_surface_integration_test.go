// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_bearer_surface_integration_test.go — группы F, C, H, D приёмки
// LINE-A-1: 01, 18, 19 (предъявитель A-1 у НАШИХ читателей на предъявлении и у
// функции пола), 22 (метаданные обнаружения), 23 (монтаж и метод), 25 (ни
// секретов, ни личных данных, ни инфра-данных в ответах и журнале).
//
// Уровень здесь I: предъявление спрашивается у тех читателей службы, которых
// спрашивает край. Сквозная половина через край (E) — следующий шаг полосы на
// стенде; этим файлом она не заменяется.
//
// Мир, ступени пробы и слова исхода — `ceremony_world_integration_test.go`.
package main

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestLINEA1_01_BearerIsRevocableAtPresentation — LINE-A-1-01: предъявитель
// A-1 после отсечки субъекта (механизм отсечки переиспользуется) отвергается
// на предъявлении. Близнец — тот же предъявитель без отсечки принимается;
// отличие — записана отсечка. Вопрос сквозь обе стороны одной пробой.
func TestLINEA1_01_BearerIsRevocableAtPresentation(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-01", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	tr := w.redeem(w.issueCode(w.ic1, lineA1R))
	if refused, why := w.presentation(tr.AccessToken); refused {
		t.Fatalf("%s: близнец: предъявитель отвергнут без отсечки: %s", w.id, why)
	}
	if err := kanamepg.NewUserTokenRevocationRepo(w.pool).UpsertRevokeAll(w.ctx, domain.UserTokenRevocation{
		UserID: w.user, RevokeBefore: time.Now().UTC(), Reason: "line-a-1-probe cutoff", RevokedBy: w.user,
	}, w.user); err != nil {
		w.fixture("запись отсечки субъекта: %v", err)
	}
	if refused, _ := w.presentation(tr.AccessToken); !refused {
		t.Errorf("%s: после отсечки субъекта предъявитель A-1 принимается на предъявлении — контроль на выдаче без энфорсмента", w.id)
	}
}

// TestLINEA1_18_BearerIsFitForTheEdge — LINE-A-1-18: предъявитель церемонии
// пригоден, а не только подписан: проверяется нашим ключом и издателем, не
// истёк, принимается нашими читателями на предъявлении, несёт вид принципала
// и уровень, достаточный рутинному глаголу (пол "1").
func TestLINEA1_18_BearerIsFitForTheEdge(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-18", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	tr := w.redeem(w.issueCode(w.ic1, lineA1R))
	claims := w.bearerClaims(tr.AccessToken)
	if exp, err := claims.GetExpirationTime(); err != nil || exp == nil || !exp.After(time.Now()) {
		t.Errorf("%s: срок предъявителя не в будущем: %v (%v)", w.id, exp, err)
	}
	if refused, why := w.presentation(tr.AccessToken); refused {
		t.Errorf("%s: наши читатели на предъявлении отвергают свежий предъявитель: %s", w.id, why)
	}
	if acr := claimACR(claims); acr < "1" {
		t.Errorf("%s: уровень %q ниже пола рутинного глагола", w.id, acr)
	}
	w.requireSessionFacts("предъявитель для края", claims)
}

// TestLINEA1_19_CarriedLevelIsJudgedByThePlatformFloor — LINE-A-1-19:
// предъявитель от сессии уровня "1" на чувствительном глаголе (пол "2")
// отвергается единственной функцией пола платформы. Близнец — предъявитель от
// сессии уровня "2" проходит тот же глагол: уровень перенесён фактом сессии.
func TestLINEA1_19_CarriedLevelIsJudgedByThePlatformFloor(t *testing.T) {
	for _, tc := range []struct {
		level  string
		passes bool
	}{{"1", false}, {"2", true}} {
		w := newCeremonyWorld(t, "LINE-A-1-19", tc.level)
		w.requireGrant(grantAuthorizationCode)
		w.requireAuthorizeEndpoint()

		acr := claimACR(w.bearerClaims(w.redeem(w.issueCode(w.ic1, lineA1R)).AccessToken))
		stub := &reachedClusterServer{}
		conn := serveACRChain(t, stub, acrTestGatewaySAN, acr)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := iamv1.NewInternalClusterServiceClient(conn).GrantAdmin(ctx, &iamv1.GrantClusterAdminRequest{SubjectId: string(w.user)})
		cancel()
		if tc.passes && (err != nil || !stub.grantReached) {
			t.Errorf("%s: сессия уровня %s: чувствительный глагол не пройден (%v) — уровень не перенесён фактом сессии", w.id, tc.level, err)
		}
		if !tc.passes && (status.Code(err) != codes.PermissionDenied || stub.grantReached) {
			t.Errorf("%s: сессия уровня %s: пол \"2\" не отказал (код %v, обработчик достигнут %v)", w.id, tc.level, status.Code(err), stub.grantReached)
		}
	}
}

// TestLINEA1_22_DiscoveryPublishesOurCeremonyCoordinates — LINE-A-1-22:
// `GET .well-known/oauth-authorization-server` без аутентификации → 200 и наши
// координаты церемонии; на проводе только публичный материал; иной метод →
// 405 с перечнем допустимых.
func TestLINEA1_22_DiscoveryPublishesOurCeremonyCoordinates(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-22", "1")
	w.requireDiscoveryEndpoint()

	rec := w.get(lineA1DiscoveryPath, nil, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: обнаружение ответило %d, ожидалось 200; тело %q", w.id, rec.Code, rec.Body.String())
	}
	var md struct {
		Issuer                 string   `json:"issuer"`
		AuthorizationEndpoint  string   `json:"authorization_endpoint"`
		TokenEndpoint          string   `json:"token_endpoint"`
		CodeChallengeMethods   []string `json:"code_challenge_methods_supported"`
		GrantTypesSupported    []string `json:"grant_types_supported"`
		ResponseTypesSupported []string `json:"response_types_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &md); err != nil {
		t.Fatalf("%s: метаданные неразбираемы: %v; тело %q", w.id, err, rec.Body.String())
	}
	if md.Issuer != lineA1Issuer {
		t.Errorf("%s: издатель %q, ожидался наш %q", w.id, md.Issuer, lineA1Issuer)
	}
	if !strings.HasSuffix(md.AuthorizationEndpoint, lineA1AuthorizePath) || !strings.HasSuffix(md.TokenEndpoint, clienttokenhttp.TokenPath) {
		t.Errorf("%s: координаты церемонии не наши: %q, %q", w.id, md.AuthorizationEndpoint, md.TokenEndpoint)
	}
	if !reflect.DeepEqual(md.CodeChallengeMethods, []string{"S256"}) || !reflect.DeepEqual(md.ResponseTypesSupported, []string{"code"}) {
		t.Errorf("%s: методы PKCE %v, виды ответа %v — ожидалось [S256] и [code]", w.id, md.CodeChallengeMethods, md.ResponseTypesSupported)
	}
	for _, g := range []string{grantAuthorizationCode, grantRefreshToken} {
		if !lineA1Has(md.GrantTypesSupported, g) {
			t.Errorf("%s: вид выдачи %q не объявлен: %v", w.id, g, md.GrantTypesSupported)
		}
	}
	cfg := w.pool.Config().ConnConfig
	for _, leak := range []string{w.email, string(w.user), string(w.ic1.rec.ID), cfg.Host, cfg.Database, "postgres", "secret"} {
		if leak != "" && strings.Contains(rec.Body.String(), leak) {
			t.Errorf("%s: метаданные несут непубличное %q", w.id, leak)
		}
	}
	post := w.post(lineA1DiscoveryPath, nil, nil)
	if post.Code != http.StatusMethodNotAllowed || !strings.Contains(post.Header().Get("Allow"), http.MethodGet) {
		t.Errorf("%s: POST на обнаружение ответил %d, Allow %q — ожидалось 405 с GET", w.id, post.Code, post.Header().Get("Allow"))
	}
}

// lineA1InternalMounts — монтаж на ВНУТРЕННИХ HTTP-муксах корня сегодня.
// Новая строка здесь — предмет решения, а не молчаливое расширение: путь
// церемонии на внутреннем слушателе есть нарушение ban #6.
var lineA1InternalMounts = []string{
	`jwksMux.Handle(tokenintrospecthttp.IntrospectPath, introspect)`,
	`metricsMux.Handle("/metrics", metricsReg.Handler())`,
}

// rootInternalMounts — все вызовы `X.Handle(...)`/`X.HandleFunc(...)` корня
// (не-тестовые файлы пакета), чей получатель — не мукс поверхности выдачи.
func rootInternalMounts(dir string) ([]string, int, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, 0, err
	}
	var out []string
	read := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			return nil, read, err
		}
		read++
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			return nil, read, err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || recv.Name == "mux" && filepath.Base(f) == "serve.go" {
				return true
			}
			out = append(out, strings.Join(strings.Fields(string(src[fset.Position(call.Pos()).Offset:fset.Position(call.End()).Offset])), " "))
			return true
		})
	}
	sort.Strings(out)
	return out, read, nil
}

// TestLINEA1_23_CeremonyMountedOnTheIssuingSurfaceAndNowhereElse —
// LINE-A-1-23: пути церемонии резолвятся на внешней поверхности выдачи и
// отвечают церемонией; метод ограничен (405 с перечнем); соседняя координата
// с суффиксом действия здесь НЕ резолвится (заказ разбора классов о разводке
// координаты); на внутренних муксах корня путей церемонии нет.
func TestLINEA1_23_CeremonyMountedOnTheIssuingSurfaceAndNowhereElse(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-23", "1")
	w.requireAuthorizeEndpoint()
	w.requireDiscoveryEndpoint()

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		w.surface.ServeHTTP(rec, httptest.NewRequest(m, lineA1AuthorizePath, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") == "" {
			t.Errorf("%s: %s на эндпоинте авторизации ответил %d, Allow %q — ожидалось 405 с перечнем", w.id, m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	get := httptest.NewRecorder()
	w.surface.ServeHTTP(get, httptest.NewRequest(http.MethodGet, clienttokenhttp.TokenPath+"?grant_type="+grantAuthorizationCode, nil))
	if get.Code != http.StatusMethodNotAllowed || get.Header().Get("Allow") == "" {
		t.Errorf("%s: GET на полосе обмена ответил %d, Allow %q — ожидалось 405 с перечнем", w.id, get.Code, get.Header().Get("Allow"))
	}
	if rec := w.post(lineA1AuthorizePath+":check", nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("%s: координата с суффиксом действия %s:check резолвится на поверхности выдачи (код %d)", w.id, lineA1AuthorizePath, rec.Code)
	}

	got, read, err := rootInternalMounts(".")
	if err != nil || read == 0 {
		w.fixture("перепись монтажа корня: прочитано файлов %d, ошибка %v", read, err)
	}
	if !reflect.DeepEqual(got, lineA1InternalMounts) {
		t.Errorf("%s: монтаж на внутренних муксах корня %q, объявлено %q (прочитано файлов %d): путь церемонии — только на поверхности выдачи",
			w.id, got, lineA1InternalMounts, read)
	}
}

// TestLINEA1_25_NoSecretsPIIOrInfraInCeremonyResponsesAndLog — LINE-A-1-25:
// ответы и журнал церемонии, обмена и ротации не несут ни кода, ни
// удостоверений, ни секрета клиента, ни личных данных, ни инфра-данных;
// положительный контроль — не-PII идентификатор субъекта в журнале есть.
func TestLINEA1_25_NoSecretsPIIOrInfraInCeremonyResponsesAndLog(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-25", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireGrant(grantRefreshToken)
	w.requireAuthorizeEndpoint()

	ic := w.issueCode(w.ic1, lineA1R)
	tr := w.redeem(ic)
	next := decodeToken(t, w.id, w.refresh(w.ic1, tr.RefreshToken))

	bad := exchangeForm(w.issueCode(w.ic1, lineA1R))
	other, _ := pkcePair()
	bad.Set("code_verifier", other)
	_, challenge := pkcePair()
	refusals := []*httptest.ResponseRecorder{
		w.exchangeAs(w.ic1, bad),
		w.refresh(w.ic1, randomToken(32)),
		w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1Foreign, stateOfLen(lineA1StateFloor), challenge), true),
	}

	log := w.logs.String()
	secrets := map[string]string{
		"код": ic.code, "verifier": ic.verifier, "предъявитель": tr.AccessToken, "refresh_token": tr.RefreshToken,
		"ротированный refresh_token": next.RefreshToken, "секрет клиента": w.ic1.secret,
		"носитель сессии": w.session.bearer.CookieValue(), "адрес почты": w.email,
	}
	for what, v := range secrets {
		if v != "" && strings.Contains(log, v) {
			t.Errorf("%s: журнал церемонии несёт %s", w.id, what)
		}
	}
	cfg := w.pool.Config().ConnConfig
	for i, rec := range refusals {
		for _, leak := range []string{"SQLSTATE", "pgx", "postgres", cfg.Host, cfg.Database, w.email} {
			if leak != "" && strings.Contains(rec.Body.String(), leak) {
				t.Errorf("%s: отказ %d несёт %q: %q", w.id, i, leak, rec.Body.String())
			}
		}
	}
	if !strings.Contains(log, string(w.user)) {
		t.Errorf("%s: в журнале нет не-PII идентификатора субъекта — «PII нет» неотличимо от «журнала нет»", w.id)
	}
}

func lineA1Has(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Самопроверка драйвера: перепись корня способна упасть (без базы)

// TestLINEA1Harness_RootCensusFollowsTheRoot — перепись употреблений муксом
// поверхности выдачи: контроль (дерево как есть) совпадает с перечнем сборки;
// инъекция нового монтажа в корень меняет перепись и называет его; корень без
// сборки поверхности — отказ, а не пустое «совпало».
func TestLINEA1Harness_RootCensusFollowsTheRoot(t *testing.T) {
	src := readFileT(t, "serve.go")

	got, err := rootIssuanceUses([]byte(src))
	if err != nil || !reflect.DeepEqual(got, lineA1IssuanceRootUses) {
		t.Fatalf("контроль: перепись корня %q (ошибка %v), перечень сборки %q", got, err, lineA1IssuanceRootUses)
	}

	const anchor = "mux.Handle(clienttokenhttp.TokenPath, clientTokenHandler)"
	if strings.Count(src, anchor) != 1 {
		t.Fatalf("предпосылка инъекции: якорь монтажа встречается %d раз(а), ожидался один", strings.Count(src, anchor))
	}
	injected := strings.Replace(src, anchor, anchor+"\n\t\t\tmux.Handle(\"/iam/v1/authorize\", clientTokenHandler)", 1)
	got, err = rootIssuanceUses([]byte(injected))
	if err != nil || reflect.DeepEqual(got, lineA1IssuanceRootUses) || !lineA1Has(got, `mux.Handle("/iam/v1/authorize", clientTokenHandler)`) {
		t.Errorf("инъекция: новый монтаж в корне не виден переписи: %q (ошибка %v)", got, err)
	}

	if _, err := rootIssuanceUses([]byte(strings.ReplaceAll(src, "registrytokenwire.Build(", "registrytokenwire.Other("))); err == nil {
		t.Error("корень без сборки поверхности выдачи дал перепись — пустой обход не может «совпасть»")
	}

	internal, read, err := rootInternalMounts(".")
	if err != nil || read == 0 || !reflect.DeepEqual(internal, lineA1InternalMounts) {
		t.Errorf("контроль: монтаж внутренних муксов %q (прочитано %d, ошибка %v), объявлено %q", internal, read, err, lineA1InternalMounts)
	}
	t.Logf("перепись: употреблений мукса выдачи %d · монтажей внутренних муксов %d · файлов корня прочитано %d",
		len(lineA1IssuanceRootUses), len(internal), read)
}
