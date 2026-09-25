// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremony_test

// usecase_test.go — вариант использования церемонии на портах-заглушках
// (приёмка LINE-A-1). Сквозные пробы сценариев — `cmd/kaname/ceremony_*`; здесь
// судится ПОРЯДОК решений и классификация исходов без базы.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/ceremony"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

const (
	clientID = domain.InteractiveClientID("ic-0123456789abcdefg")
	target   = "https://console.example.test/cb"
	subject  = domain.UserID("usr0123456789abcdefg")
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// ── заглушки портов ─────────────────────────────────────────────────────────

type clientsStub struct {
	client  domain.InteractiveClient
	found   bool
	err     error
	secret  ceremony.ClientSecret
	secretF bool
}

func (c clientsStub) InteractiveClient(context.Context, domain.InteractiveClientID) (domain.InteractiveClient, bool, error) {
	return c.client, c.found, c.err
}

func (c clientsStub) ClientSecret(context.Context, domain.InteractiveClientID) (ceremony.ClientSecret, bool, error) {
	return c.secret, c.secretF, c.err
}

type loginStub struct {
	who   ceremony.Authentication
	found bool
	err   error
	asked int
}

func (l *loginStub) Resolve(context.Context, domain.SessionBearer) (ceremony.Authentication, bool, error) {
	l.asked++
	return l.who, l.found, l.err
}

type storeStub struct {
	issued   []ceremony.CodeIssue
	issueOK  bool
	issueErr error
	classify ceremony.CodeRefusal
	w        *writerStub
}

func (s *storeStub) IssueCode(_ context.Context, in ceremony.CodeIssue) (bool, error) {
	if s.issueErr != nil {
		return false, s.issueErr
	}
	s.issued = append(s.issued, in)
	return s.issueOK, nil
}

func (s *storeStub) ClassifyCode(context.Context, ceremony.CodeRedemption) (ceremony.CodeRefusal, error) {
	return s.classify, nil
}

func (s *storeStub) Writer(context.Context) (ceremony.Writer, error) { return s.w, nil }

type writerStub struct {
	grant         ceremony.Grant
	redeem        bool
	revokedByCode bool
	state         ceremony.RefreshState
	rotate        bool
	revoked       []ceremony.FamilyRevocation
	codeRevokes   int
	inserted      []domain.CeremonySecretDigest
	audits        []outboxtypes.AuditEvent
	committed     bool
	redemptions   []ceremony.CodeRedemption
}

func (w *writerStub) RedeemCode(_ context.Context, in ceremony.CodeRedemption) (ceremony.Grant, bool, error) {
	w.redemptions = append(w.redemptions, in)
	g := w.grant
	g.ID = in.Grant
	return g, w.redeem, nil
}

func (w *writerStub) RevokeFamilyOfCode(context.Context, domain.CeremonySecretDigest, time.Time) (ceremony.Grant, bool, error) {
	w.codeRevokes++
	return w.grant, w.revokedByCode, nil
}

func (w *writerStub) LockRefresh(context.Context, domain.CeremonySecretDigest) (ceremony.RefreshState, error) {
	return w.state, nil
}

func (w *writerStub) RotateRefresh(_ context.Context, _, next domain.CeremonySecretDigest, _ domain.AuthorizationGrantID) (bool, error) {
	if w.rotate {
		w.inserted = append(w.inserted, next)
	}
	return w.rotate, nil
}

func (w *writerStub) InsertRefresh(_ context.Context, d domain.CeremonySecretDigest, _ domain.AuthorizationGrantID) error {
	w.inserted = append(w.inserted, d)
	return nil
}

func (w *writerStub) RevokeFamily(_ context.Context, in ceremony.FamilyRevocation) (bool, error) {
	w.revoked = append(w.revoked, in)
	return true, nil
}

func (w *writerStub) EmitAudit(_ context.Context, ev outboxtypes.AuditEvent) error {
	w.audits = append(w.audits, ev)
	return nil
}

func (w *writerStub) Commit(context.Context) error   { w.committed = true; return nil }
func (w *writerStub) Rollback(context.Context) error { return nil }

type signerStub struct{ req tokensigner.Request }

func (s *signerStub) Sign(_ context.Context, req tokensigner.Request) (tokensigner.Token, error) {
	s.req = req
	now := time.Unix(1_900_000_000, 0)
	return tokensigner.Token{Token: "signed", JTI: "tok1", IssuedAt: now, ExpiresAt: now.Add(req.TTL)}, nil
}

func (s *signerStub) Issuer() string { return "https://issuer.example.test" }

type usersStub struct{ status domain.InviteStatus }

func (u usersStub) GetByID(_ context.Context, id domain.UserID) (domain.User, error) {
	return domain.User{ID: id, ExternalID: "ext-1", InviteStatus: u.status}, nil
}

type claimsStub struct{ hook service.TokenHookContext }

func (c *claimsStub) UserClaims(_ domain.User, _ string, h service.TokenHookContext) map[string]any {
	c.hook = h
	return map[string]any{domain.ClaimPrincipalType: "user"}
}

type verifierStub struct{ outcome passwordverify.Outcome }

func (v verifierStub) Verify(domain.LoginVerifier, string) passwordverify.Result {
	return passwordverify.Result{Outcome: v.outcome}
}

// ── эндпоинт авторизации ────────────────────────────────────────────────────

func activeClient() domain.InteractiveClient {
	return domain.InteractiveClient{
		ID: clientID, Status: domain.InteractiveClientActive,
		RedirectURIs: []string{target}, Audiences: []string{"https://api.example.test"},
	}
}

func validParams() ceremony.AuthorizeParams {
	return ceremony.AuthorizeParams{
		ClientID: string(clientID), RedirectURI: target, ResponseType: "code", Scope: "openid",
		State: strings.Repeat("s", domain.AuthorizationStateFloor), CodeChallenge: domain.PKCEChallengeS256(strings.Repeat("v", 43)),
		CodeChallengeMethod: "S256",
	}
}

func authorizeWorld(t *testing.T, login *loginStub, store *storeStub, clients clientsStub) (*ceremony.AuthorizeUseCase, *ceremony.Census) {
	t.Helper()
	census := ceremony.NewCensus()
	uc, err := ceremony.NewAuthorizeUseCase(clients, login, store, census, quiet)
	if err != nil {
		t.Fatalf("построение: %v", err)
	}
	return uc, census
}

func authenticated(level string) *loginStub {
	return &loginStub{found: true, who: ceremony.Authentication{
		Subject: subject, Session: "hss-0123456789abcdefg", AuthenticatedAt: time.Unix(1_800_000_000, 0), Level: level,
	}}
}

// TestAuthorize_UntrustedTargetRefusalsAreOneKindAndNeverAskTheSeam — до
// доверия цели отказ один (без перенаправления), и шов входа не спрашивается:
// неизвестный клиент, снятый клиент, незарегистрированная цель, хвостовой
// слэш, повторённый client_id, незаконная форма id.
func TestAuthorize_UntrustedTargetRefusalsAreOneKindAndNeverAskTheSeam(t *testing.T) {
	gone := activeClient()
	gone.Status = domain.InteractiveClientDeleting
	cases := map[string]struct {
		clients clientsStub
		mutate  func(*ceremony.AuthorizeParams)
		outcome ceremony.Outcome
	}{
		"клиента нет":             {clientsStub{}, nil, ceremony.AuthorizeClientUnknown},
		"клиент снят":             {clientsStub{client: gone, found: true}, nil, ceremony.AuthorizeClientNotActive},
		"цель не та":              {clientsStub{client: activeClient(), found: true}, func(p *ceremony.AuthorizeParams) { p.RedirectURI = "https://elsewhere.test/cb" }, ceremony.AuthorizeRedirectUnregistered},
		"хвостовой слэш":          {clientsStub{client: activeClient(), found: true}, func(p *ceremony.AuthorizeParams) { p.RedirectURI = target + "/" }, ceremony.AuthorizeRedirectUnregistered},
		"повтор client_id":        {clientsStub{client: activeClient(), found: true}, func(p *ceremony.AuthorizeParams) { p.Repeated = []string{"client_id"} }, ceremony.AuthorizeTargetParamInvalid},
		"незаконная форма id":     {clientsStub{client: activeClient(), found: true}, func(p *ceremony.AuthorizeParams) { p.ClientID = "IC-nope" }, ceremony.AuthorizeTargetParamInvalid},
		"redirect_uri не прислан": {clientsStub{client: activeClient(), found: true}, func(p *ceremony.AuthorizeParams) { p.RedirectURI = "" }, ceremony.AuthorizeTargetParamInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			login := authenticated("1")
			store := &storeStub{issueOK: true}
			uc, census := authorizeWorld(t, login, store, tc.clients)
			p := validParams()
			if tc.mutate != nil {
				tc.mutate(&p)
			}
			d := uc.Execute(context.Background(), p)
			if d.Kind != ceremony.DecisionRefuseWithoutRedirect || d.Target != "" || !d.Code.IsZero() {
				t.Fatalf("решение %+v, ожидался отказ без перенаправления", d)
			}
			if d.Outcome != tc.outcome || census.Snapshot()[string(tc.outcome)] != 1 {
				t.Fatalf("исход %q, ожидался %q (перепись %v)", d.Outcome, tc.outcome, census.Snapshot()[string(tc.outcome)])
			}
			if login.asked != 0 || len(store.issued) != 0 {
				t.Fatalf("до доверия цели спрошен шов (%d) либо заведена запись (%d)", login.asked, len(store.issued))
			}
		})
	}
}

// TestAuthorize_RedirectRefusalsCarryOnlyTheErrorCode — после доверия цели
// отказы перенаправляемы, несут код ошибки и не несут state.
func TestAuthorize_RedirectRefusalsCarryOnlyTheErrorCode(t *testing.T) {
	cases := map[string]struct {
		mutate  func(*ceremony.AuthorizeParams)
		code    string
		outcome ceremony.Outcome
	}{
		"response_type=token":       {func(p *ceremony.AuthorizeParams) { p.ResponseType = "token" }, ceremony.ErrUnsupportedResponseType, ceremony.AuthorizeResponseTypeRefused},
		"response_type нет":         {func(p *ceremony.AuthorizeParams) { p.ResponseType = "" }, ceremony.ErrInvalidRequest, ceremony.AuthorizeResponseTypeMissing},
		"state на знак короче пола": {func(p *ceremony.AuthorizeParams) { p.State = p.State[1:] }, ceremony.ErrInvalidRequest, ceremony.AuthorizeStateRefused},
		"state не прислан":          {func(p *ceremony.AuthorizeParams) { p.State = "" }, ceremony.ErrInvalidRequest, ceremony.AuthorizeStateAbsent},
		"state вне VSCHAR":          {func(p *ceremony.AuthorizeParams) { p.State = strings.Repeat("ж", 22) }, ceremony.ErrInvalidRequest, ceremony.AuthorizeStateRefused},
		"PKCE нет":                  {func(p *ceremony.AuthorizeParams) { p.CodeChallenge, p.CodeChallengeMethod = "", "" }, ceremony.ErrInvalidRequest, ceremony.AuthorizePKCERefused},
		"PKCE plain":                {func(p *ceremony.AuthorizeParams) { p.CodeChallengeMethod = "plain" }, ceremony.ErrInvalidRequest, ceremony.AuthorizePKCERefused},
		"область с двумя пробелами": {func(p *ceremony.AuthorizeParams) { p.Scope = "a  b" }, ceremony.ErrInvalidScope, ceremony.AuthorizeScopeRefused},
		"acr_values вне оси":        {func(p *ceremony.AuthorizeParams) { p.ACRValues = "urn:x" }, ceremony.ErrInvalidRequest, ceremony.AuthorizeACRValuesRefused},
		"повтор state":              {func(p *ceremony.AuthorizeParams) { p.Repeated = []string{"state"} }, ceremony.ErrInvalidRequest, ceremony.AuthorizeParamRepeated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			login := authenticated("1")
			store := &storeStub{issueOK: true}
			uc, _ := authorizeWorld(t, login, store, clientsStub{client: activeClient(), found: true})
			p := validParams()
			tc.mutate(&p)
			d := uc.Execute(context.Background(), p)
			if d.Kind != ceremony.DecisionRedirectError || d.Target != target || d.Error != tc.code || d.Outcome != tc.outcome {
				t.Fatalf("решение %+v, ожидался перенаправляемый %s (%s)", d, tc.code, tc.outcome)
			}
			if d.State != "" || !d.Code.IsZero() || len(store.issued) != 0 {
				t.Fatalf("перенаправляемый отказ несёт state/код либо завёл запись: %+v", d)
			}
		})
	}
}

// TestAuthorize_StateFloorIsInclusiveAndNotAnEquality — ровно на полу и выше
// пола код выдаётся (граница «не ниже», а не «ровно»).
func TestAuthorize_StateFloorIsInclusiveAndNotAnEquality(t *testing.T) {
	for _, n := range []int{domain.AuthorizationStateFloor, domain.AuthorizationStateFloor + 21} {
		store := &storeStub{issueOK: true}
		uc, _ := authorizeWorld(t, authenticated("1"), store, clientsStub{client: activeClient(), found: true})
		p := validParams()
		p.State = strings.Repeat("s", n)
		if d := uc.Execute(context.Background(), p); d.Kind != ceremony.DecisionDeliverCode || d.State != p.State {
			t.Fatalf("state длиной %d: решение %+v", n, d)
		}
	}
}

// TestAuthorize_SeamDecidesAndIssuanceBindsTheSeamAnswer — «не
// аутентифицирован» не выдаёт кода; ответ шва — единственный источник
// субъекта и сессии записи кода; сбой шва — третий исход.
func TestAuthorize_SeamDecidesAndIssuanceBindsTheSeamAnswer(t *testing.T) {
	t.Run("не аутентифицирован", func(t *testing.T) {
		store := &storeStub{issueOK: true}
		uc, _ := authorizeWorld(t, &loginStub{}, store, clientsStub{client: activeClient(), found: true})
		if d := uc.Execute(context.Background(), validParams()); d.Kind != ceremony.DecisionAuthenticate || len(store.issued) != 0 {
			t.Fatalf("решение %+v, записей %d", d, len(store.issued))
		}
	})
	t.Run("шов не ответил", func(t *testing.T) {
		store := &storeStub{issueOK: true}
		uc, _ := authorizeWorld(t, &loginStub{err: errors.New("down")}, store, clientsStub{client: activeClient(), found: true})
		d := uc.Execute(context.Background(), validParams())
		if d.Kind != ceremony.DecisionRedirectError || d.Error != ceremony.ErrTemporarilyUnavailable || len(store.issued) != 0 {
			t.Fatalf("решение %+v", d)
		}
	})
	t.Run("выдача", func(t *testing.T) {
		login := authenticated("1")
		store := &storeStub{issueOK: true}
		uc, _ := authorizeWorld(t, login, store, clientsStub{client: activeClient(), found: true})
		d := uc.Execute(context.Background(), validParams())
		if d.Kind != ceremony.DecisionDeliverCode || d.Code.IsZero() || d.Target != target {
			t.Fatalf("решение %+v", d)
		}
		if len(store.issued) != 1 {
			t.Fatalf("записей %d", len(store.issued))
		}
		rec := store.issued[0]
		if rec.Subject != login.who.Subject || rec.Session != login.who.Session || rec.Digest != d.Code.Digest() ||
			rec.TTL != domain.AuthorizationCodeTTL || rec.RedirectURI != target {
			t.Fatalf("запись связывает не то: %+v", rec)
		}
	})
	t.Run("условие вставки проиграло гонку — отказ без перенаправления", func(t *testing.T) {
		store := &storeStub{issueOK: false}
		uc, _ := authorizeWorld(t, authenticated("1"), store, clientsStub{client: activeClient(), found: true})
		if d := uc.Execute(context.Background(), validParams()); d.Kind != ceremony.DecisionRefuseWithoutRedirect || d.Outcome != ceremony.AuthorizeIssueRaced {
			t.Fatalf("решение %+v", d)
		}
	})
	t.Run("хранилище клиентов не ответило — перенаправлять некуда", func(t *testing.T) {
		uc, _ := authorizeWorld(t, authenticated("1"), &storeStub{}, clientsStub{err: errors.New("down")})
		if d := uc.Execute(context.Background(), validParams()); d.Kind != ceremony.DecisionUnavailable || d.Target != "" {
			t.Fatalf("решение %+v", d)
		}
	})
}

// TestAuthorize_StepUpIsServedByThePlatformRanking — уровень ниже
// запрошенного не выдаёт кода; достаточный — выдаёт; из перечня берётся
// наименьший.
func TestAuthorize_StepUpIsServedByThePlatformRanking(t *testing.T) {
	cases := []struct {
		session, acr string
		kind         ceremony.DecisionKind
	}{
		{"1", "2", ceremony.DecisionStepUp},
		{"2", "2", ceremony.DecisionDeliverCode},
		{"1", "1", ceremony.DecisionDeliverCode},
		{"1", "3 1", ceremony.DecisionDeliverCode},
		{"2", "3", ceremony.DecisionStepUp},
	}
	for _, tc := range cases {
		store := &storeStub{issueOK: true}
		uc, _ := authorizeWorld(t, authenticated(tc.session), store, clientsStub{client: activeClient(), found: true})
		p := validParams()
		p.ACRValues = tc.acr
		d := uc.Execute(context.Background(), p)
		if d.Kind != tc.kind {
			t.Errorf("сессия %s, acr_values %q: решение %+v, ожидался вид %d", tc.session, tc.acr, d, tc.kind)
		}
		if tc.kind == ceremony.DecisionStepUp && (len(store.issued) != 0 || d.RequiredLevel == "") {
			t.Errorf("шаг вверх завёл запись либо не назвал уровень: %+v", d)
		}
	}
}

// ── обмен кода ──────────────────────────────────────────────────────────────

func exchangeWorld(t *testing.T, store *storeStub, clients clientsStub, verify passwordverify.Outcome,
	status domain.InviteStatus) (*ceremony.ExchangeUseCase, *signerStub, *claimsStub, *ceremony.Census) {
	t.Helper()
	signer, claims, census := &signerStub{}, &claimsStub{}, ceremony.NewCensus()
	uc, err := ceremony.NewExchangeUseCase(ceremony.ExchangeConfig{
		AllowedAudiences: []string{"https://api.example.test"}, DefaultAudience: "https://api.example.test",
		TokenTTL: 15 * time.Minute, Clock: func() time.Time { return time.Unix(1_800_000_100, 0) },
	}, ceremony.ExchangeDeps{Clients: clients, Secrets: verifierStub{verify}, Store: store, Signer: signer,
		Users: usersStub{status}, Claims: claims, Census: census, Logger: quiet})
	if err != nil {
		t.Fatalf("построение: %v", err)
	}
	return uc, signer, claims, census
}

func confidential() clientsStub {
	v, _ := domain.NewLoginVerifier("$argon2id$v=19$m=8,t=1,p=1$c2FsdA$Ym9keQ")
	return clientsStub{client: activeClient(), found: true, secret: ceremony.ClientSecret{Active: true, Verifier: v}, secretF: true}
}

func grantOfSession(level string) ceremony.Grant {
	return ceremony.Grant{Client: clientID, Subject: subject, Session: "hss-0123456789abcdefg", Scope: "openid",
		AuthenticatedAt: time.Unix(1_800_000_000, 0), Level: level, SessionExpiresAt: time.Unix(1_800_043_200, 0)}
}

func basic() ceremony.ClientPresentation {
	return ceremony.ClientPresentation{Presented: true, ID: string(clientID), Secret: "s"}
}

func codeInput() ceremony.CodeExchangeInput {
	return ceremony.CodeExchangeInput{Client: basic(), Code: "code-value", RedirectURI: target, Verifier: strings.Repeat("v", 43)}
}

// TestExchange_ClientIsAuthenticatedBeforeTheCodeIsNamed — отказы
// аутентификации клиента — `invalid_client` и до всякого обращения к коду.
func TestExchange_ClientIsAuthenticatedBeforeTheCodeIsNamed(t *testing.T) {
	inactive := confidential()
	inactive.secret.Active = false
	cases := map[string]struct {
		clients clientsStub
		pres    ceremony.ClientPresentation
		verify  passwordverify.Outcome
		code    string
		outcome ceremony.Outcome
	}{
		"нет заголовка":         {confidential(), ceremony.ClientPresentation{}, passwordverify.OutcomeMatched, ceremony.TokenErrInvalidClient, ceremony.ExchangeClientMissing},
		"client_id тела другой": {confidential(), ceremony.ClientPresentation{Presented: true, ID: string(clientID), FormClientID: "ic-zzzzzzzzzzzzzzzzz"}, passwordverify.OutcomeMatched, ceremony.TokenErrInvalidClient, ceremony.ExchangeClientMissing},
		"клиента нет":           {clientsStub{}, basic(), passwordverify.OutcomeMatched, ceremony.TokenErrInvalidClient, ceremony.ExchangeClientUnknown},
		"клиент снят":           {inactive, basic(), passwordverify.OutcomeMatched, ceremony.TokenErrInvalidClient, ceremony.ExchangeClientNotActive},
		"секрет не тот":         {confidential(), basic(), passwordverify.OutcomeMismatched, ceremony.TokenErrInvalidClient, ceremony.ExchangeClientSecretWrong},
		"секрета нет":           {confidential(), basic(), passwordverify.OutcomeMaterialMissing, ceremony.TokenErrInvalidClient, ceremony.ExchangeClientNoSecret},
		"значение не читается":  {confidential(), basic(), passwordverify.OutcomeBodyNotParsable, ceremony.TokenErrInvalidClient, ceremony.ExchangeClientSecretBroken},
		"ёмкость исчерпана":     {confidential(), basic(), passwordverify.OutcomeCapacityExhausted, ceremony.TokenErrUnavailable, ceremony.ExchangeVerifierBusy},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := &writerStub{redeem: true, grant: grantOfSession("1")}
			uc, _, _, _ := exchangeWorld(t, &storeStub{w: w}, tc.clients, tc.verify, domain.InviteStatusActive)
			in := codeInput()
			in.Client = tc.pres
			_, err := uc.ExchangeCode(context.Background(), in)
			r, ok := ceremony.IsRefusal(err)
			if !ok || r.Code != tc.code || r.Outcome != tc.outcome {
				t.Fatalf("отказ %+v (%v), ожидался %s/%s", r, err, tc.code, tc.outcome)
			}
			if len(w.redemptions) != 0 {
				t.Fatalf("код назван до аутентификации клиента")
			}
		})
	}
}

// TestExchange_AcceptedCodeCarriesTheSessionFacts — предъявитель несёт
// субъекта, уровень и момент авторизации (то есть сессии) и ключ семейства;
// вызов PKCE вычислен из verifier; аудит — той же транзакцией.
func TestExchange_AcceptedCodeCarriesTheSessionFacts(t *testing.T) {
	w := &writerStub{redeem: true, grant: grantOfSession("2")}
	uc, signer, claims, census := exchangeWorld(t, &storeStub{w: w}, confidential(), passwordverify.OutcomeMatched, domain.InviteStatusActive)
	pair, err := uc.ExchangeCode(context.Background(), codeInput())
	if err != nil {
		t.Fatalf("обмен: %v", err)
	}
	if pair.AccessToken != "signed" || pair.Refresh.IsZero() || pair.TokenType != "Bearer" || pair.ExpiresIn <= 0 {
		t.Fatalf("пара %+v", pair)
	}
	if got := w.redemptions[0].Challenge; got != domain.PKCEChallengeS256(strings.Repeat("v", 43)) {
		t.Fatalf("вызов обмена %q не вычислен из verifier", got)
	}
	c := jwt.MapClaims(signer.req.Claims)
	if signer.req.Subject != string(subject) || c["acr"] != "2" || c["auth_time"] != int64(1_800_000_000) ||
		c[domain.ClaimAuthorizationID] != string(w.redemptions[0].Grant) || claims.hook.ACR != "2" {
		t.Fatalf("предъявитель несёт не факты сессии: субъект %q, утверждения %v", signer.req.Subject, c)
	}
	if len(w.inserted) != 1 || w.inserted[0] != pair.Refresh.Digest() || !w.committed {
		t.Fatalf("удостоверение семейства не заведено той же транзакцией: %v", w.inserted)
	}
	if len(w.audits) != 1 || w.audits[0].EventType != ceremony.AuditAuthorizationGranted {
		t.Fatalf("аудит %v", w.audits)
	}
	if census.Snapshot()[string(ceremony.ExchangeCodeAccepted)] != 1 {
		t.Fatalf("перепись не сосчитала приём")
	}
}

// TestExchange_RefusedCodeIsOneAnswerAndAReplayRevokes — непотреблённый код:
// один ответ `invalid_grant` на все причины; повтор потреблённого — отзыв
// семейства и аудит.
func TestExchange_RefusedCodeIsOneAnswerAndAReplayRevokes(t *testing.T) {
	for reason, want := range map[ceremony.CodeRefusal]ceremony.Outcome{
		ceremony.CodeUnknown: ceremony.ExchangeCodeUnknown, ceremony.CodeExpired: ceremony.ExchangeCodeExpired,
		ceremony.CodeVerifierMismatch: ceremony.ExchangeCodeVerifierMismatch, ceremony.CodeClientMismatch: ceremony.ExchangeCodeClientMismatch,
		ceremony.CodeRedirectMismatch: ceremony.ExchangeCodeRedirectMismatch, ceremony.CodeSessionEnded: ceremony.ExchangeCodeSessionEnded,
	} {
		w := &writerStub{}
		uc, _, _, _ := exchangeWorld(t, &storeStub{w: w, classify: reason}, confidential(), passwordverify.OutcomeMatched, domain.InviteStatusActive)
		_, err := uc.ExchangeCode(context.Background(), codeInput())
		if r, ok := ceremony.IsRefusal(err); !ok || r.Code != ceremony.TokenErrInvalidGrant || r.Outcome != want {
			t.Errorf("%s: отказ %+v, ожидался invalid_grant/%s", reason, r, want)
		}
		if w.codeRevokes != 1 || len(w.audits) != 0 {
			t.Errorf("%s: отзыв спрошен %d раз, аудитов %d", reason, w.codeRevokes, len(w.audits))
		}
	}

	w := &writerStub{revokedByCode: true, grant: grantOfSession("1")}
	uc, _, _, _ := exchangeWorld(t, &storeStub{w: w}, confidential(), passwordverify.OutcomeMatched, domain.InviteStatusActive)
	_, err := uc.ExchangeCode(context.Background(), codeInput())
	if r, ok := ceremony.IsRefusal(err); !ok || r.Code != ceremony.TokenErrInvalidGrant || r.Outcome != ceremony.ExchangeCodeReplayed {
		t.Fatalf("повтор: отказ %+v", r)
	}
	if len(w.audits) != 1 || w.audits[0].EventType != ceremony.AuditAuthorizationRevoked || !w.committed {
		t.Fatalf("повтор не записал отзыв той же транзакцией: %v", w.audits)
	}
}

// TestExchange_FormAndIneligibleSubject — отказ формы различим; человек,
// которому выдача больше не положена, — `invalid_grant`, а не наш сбой.
func TestExchange_FormAndIneligibleSubject(t *testing.T) {
	uc, _, _, _ := exchangeWorld(t, &storeStub{w: &writerStub{}}, confidential(), passwordverify.OutcomeMatched, domain.InviteStatusActive)
	in := codeInput()
	in.Verifier = ""
	if _, err := uc.ExchangeCode(context.Background(), in); err == nil {
		t.Fatal("обмен без verifier принят")
	} else if r, _ := ceremony.IsRefusal(err); r.Code != ceremony.TokenErrInvalidRequest {
		t.Fatalf("отказ формы %+v", r)
	}
	in = codeInput()
	in.Repeated = true
	if _, err := uc.ExchangeCode(context.Background(), in); err == nil {
		t.Fatal("повторённый параметр принят")
	}

	w := &writerStub{redeem: true, grant: grantOfSession("1")}
	uc, _, _, _ = exchangeWorld(t, &storeStub{w: w}, confidential(), passwordverify.OutcomeMatched, domain.InviteStatusBlocked)
	_, err := uc.ExchangeCode(context.Background(), codeInput())
	if r, ok := ceremony.IsRefusal(err); !ok || r.Code != ceremony.TokenErrInvalidGrant || w.committed {
		t.Fatalf("заблокированному выдано либо отказ не тот: %+v, фиксация %v", r, w.committed)
	}
}

// ── ротация ─────────────────────────────────────────────────────────────────

func refreshInput() ceremony.RefreshInput {
	return ceremony.RefreshInput{Client: basic(), Refresh: "rt-value"}
}

// TestRefresh_StateUnderTheFamilyLockDecides — каждое состояние, прочитанное
// под замком семейства, даёт свой исход; повтор отзывает семейство.
func TestRefresh_StateUnderTheFamilyLockDecides(t *testing.T) {
	live := ceremony.RefreshState{Found: true, Grant: grantOfSession("1"), SessionLive: true}
	other := live
	other.Grant.Client = "ic-zzzzzzzzzzzzzzzzz"
	revoked := live
	revoked.Revoked = true
	rotated := live
	rotated.Rotated = true
	ended := live
	ended.SessionLive = false
	cut := live
	cut.CutOff = true
	cases := map[string]struct {
		st      ceremony.RefreshState
		rotate  bool
		outcome ceremony.Outcome
		revokes int
	}{
		"неизвестно":            {ceremony.RefreshState{}, true, ceremony.ExchangeRefreshUnknown, 0},
		"чужой клиент":          {other, true, ceremony.ExchangeRefreshClientMismatch, 0},
		"семейство отозвано":    {revoked, true, ceremony.ExchangeRefreshRevoked, 0},
		"повтор ротированного":  {rotated, true, ceremony.ExchangeRefreshReplayed, 1},
		"сессия снята":          {ended, true, ceremony.ExchangeRefreshSessionEnded, 0},
		"отсечка субъекта":      {cut, true, ceremony.ExchangeRefreshSessionEnded, 0},
		"CAS проиграл — повтор": {live, false, ceremony.ExchangeRefreshReplayed, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := &writerStub{state: tc.st, rotate: tc.rotate}
			uc, _, _, _ := exchangeWorld(t, &storeStub{w: w}, confidential(), passwordverify.OutcomeMatched, domain.InviteStatusActive)
			_, err := uc.Refresh(context.Background(), refreshInput())
			r, ok := ceremony.IsRefusal(err)
			if !ok || r.Code != ceremony.TokenErrInvalidGrant || r.Outcome != tc.outcome {
				t.Fatalf("отказ %+v, ожидался invalid_grant/%s", r, tc.outcome)
			}
			if len(w.revoked) != tc.revokes {
				t.Fatalf("отзывов семейства %d, ожидалось %d", len(w.revoked), tc.revokes)
			}
			if tc.revokes == 1 && (w.revoked[0].Reason != ceremony.RevokedRefreshReplay || !w.committed) {
				t.Fatalf("отзыв %+v не зафиксирован", w.revoked[0])
			}
		})
	}

	t.Run("ротация", func(t *testing.T) {
		w := &writerStub{state: live, rotate: true}
		uc, signer, _, _ := exchangeWorld(t, &storeStub{w: w}, confidential(), passwordverify.OutcomeMatched, domain.InviteStatusActive)
		pair, err := uc.Refresh(context.Background(), refreshInput())
		if err != nil || pair.Refresh.IsZero() || len(w.inserted) != 1 || w.inserted[0] != pair.Refresh.Digest() || !w.committed {
			t.Fatalf("ротация: %v, пара %+v, заведено %v", err, pair, w.inserted)
		}
		if signer.req.Claims["acr"] != "1" {
			t.Fatalf("ротация несёт не уровень авторизации: %v", signer.req.Claims)
		}
	})
	t.Run("сужение области", func(t *testing.T) {
		w := &writerStub{state: live, rotate: true}
		uc, _, _, _ := exchangeWorld(t, &storeStub{w: w}, confidential(), passwordverify.OutcomeMatched, domain.InviteStatusActive)
		in := refreshInput()
		in.Scope = "email"
		if _, err := uc.Refresh(context.Background(), in); err == nil {
			t.Fatal("область шире авторизации принята")
		} else if r, _ := ceremony.IsRefusal(err); r.Code != ceremony.TokenErrInvalidScope {
			t.Fatalf("отказ %+v", r)
		}
	})
}

// TestCensusIsSeededWithEveryDeclaredOutcome — перепись заводится целиком.
func TestCensusIsSeededWithEveryDeclaredOutcome(t *testing.T) {
	snap := ceremony.NewCensus().Snapshot()
	if len(snap) != len(ceremony.Outcomes()) || len(snap) == 0 {
		t.Fatalf("клеток %d, объявлено %d", len(snap), len(ceremony.Outcomes()))
	}
	for _, o := range ceremony.OutcomeNames() {
		if v, ok := snap[o]; !ok || v != 0 {
			t.Fatalf("клетка %q не засеяна нулём", o)
		}
	}
}
