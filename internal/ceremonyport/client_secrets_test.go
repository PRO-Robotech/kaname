// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_secrets_test.go — порт сверки секрета клиента
// (`oauthceremony.ClientSecretVerifier`, задача PRO-Robotech/kaname#410).
//
// Проверяющий в пробах НАСТОЯЩИЙ (`passwordverify`) и выровнен так же, как его
// выравнивает полоса входа; значение секрета чеканит тот же хешер, что пишет
// колонку `interactive_clients.secret_verifier`. Подставлен только справочник
// проверочных значений — и он держит контракт хранилища службы: клиента нет →
// признак `ErrNotFound`, секрета нет → «нет» без ошибки.
package ceremonyport_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const (
	rightClientSecret = "client-secret-the-client-was-issued"
	wrongClientSecret = "client-secret-somebody-guessed"
	publicClientID    = "svc-public"
	unknownClientID   = "svc-nobody-registered"
)

// ── Подставки ───────────────────────────────────────────────────────────────

// secretStore — справочник проверочных значений с контрактом хранилища службы
// (`(*pg.OAuthCeremonyRepo).ClientSecretVerifier`).
type secretStore struct {
	mu        sync.Mutex
	verifiers map[string]domain.LoginVerifier
	fail      error
	asked     []string
}

func (s *secretStore) ClientSecretVerifier(_ context.Context, clientID string) (domain.LoginVerifier, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked = append(s.asked, clientID)
	if clientID == "" {
		return domain.LoginVerifier{}, false, errors.New("Illegal argument interactive_client.client_id: required")
	}
	if s.fail != nil {
		return domain.LoginVerifier{}, false, s.fail
	}
	v, ok := s.verifiers[clientID]
	if !ok {
		return domain.LoginVerifier{}, false, iamerr.Wrapf(iamerr.ErrNotFound, "interactive client %s: not found", clientID)
	}
	if v.IsZero() {
		return domain.LoginVerifier{}, false, nil
	}
	return v, true, nil
}

func (s *secretStore) askedFor() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

// outcomeCounter — приёмник исходов проверяющего.
type outcomeCounter struct {
	mu    sync.Mutex
	cells map[passwordverify.Outcome]int
}

func (o *outcomeCounter) VerificationObserved(outcome passwordverify.Outcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cells[outcome]++
}

func (o *outcomeCounter) count(outcome passwordverify.Outcome) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cells[outcome]
}

func (o *outcomeCounter) total() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, c := range o.cells {
		n += c
	}
	return n
}

// floorHasher — хешер пола записи argon2id: тот же производитель, что у колонки
// проверочного значения клиента.
func floorHasher(t *testing.T) *passwordverify.Hasher {
	t.Helper()
	h, err := passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}})
	require.NoError(t, err)
	return h
}

// alignedVerifier — проверяющий, выровненный так, как его выравнивает полоса
// входа: значение того же класса от секрета, которого не знает никто.
func alignedVerifier(t *testing.T, hasher *passwordverify.Hasher, obs passwordverify.Observer) *passwordverify.Verifier {
	t.Helper()
	v, err := passwordverify.New(2, obs)
	require.NoError(t, err)
	decoy, err := hasher.Hash("decoy value nobody presents " + t.Name())
	require.NoError(t, err)
	require.NoError(t, v.SetDecoy(decoy))
	return v
}

// secretsRig — адаптер над справочником, где у testClientID есть секрет, а у
// publicClientID его нет.
type secretsRig struct {
	store    *secretStore
	outcomes *outcomeCounter
	port     *ceremonyport.ClientSecrets
}

func newSecretsRig(t *testing.T) *secretsRig {
	t.Helper()
	hasher := floorHasher(t)
	stored, err := hasher.Hash(rightClientSecret)
	require.NoError(t, err)
	store := &secretStore{verifiers: map[string]domain.LoginVerifier{
		testClientID:   stored,
		publicClientID: {},
	}}
	outcomes := &outcomeCounter{cells: map[passwordverify.Outcome]int{}}
	port, err := ceremonyport.NewClientSecrets(store, alignedVerifier(t, hasher, outcomes))
	require.NoError(t, err)
	return &secretsRig{store: store, outcomes: outcomes, port: port}
}

// ── Два вердикта ────────────────────────────────────────────────────────────

// Совпадение и несовпадение — два РАЗНЫХ вердикта, оба без ошибки: неверный
// секрет — вход клиента, а не отказ операции.
func TestClientSecrets_MatchAndMismatchAreTwoVerdicts(t *testing.T) {
	rig := newSecretsRig(t)
	ctx := context.Background()

	verdict, err := rig.port.VerifyClientSecret(ctx, testClientID, oauthceremony.NewPresentedSecret(rightClientSecret))
	require.NoError(t, err)
	require.Equal(t, oauthceremony.SecretMatched, verdict, "выданный клиенту секрет не совпал")

	verdict, err = rig.port.VerifyClientSecret(ctx, testClientID, oauthceremony.NewPresentedSecret(wrongClientSecret))
	require.NoError(t, err)
	require.Equal(t, oauthceremony.SecretMismatched, verdict, "чужой секрет совпал")

	verdict, err = rig.port.VerifyClientSecret(ctx, testClientID, oauthceremony.PresentedSecret{})
	require.NoError(t, err)
	require.Equal(t, oauthceremony.SecretMismatched, verdict, "непредъявленный секрет не назван несовпадением")

	require.Equal(t, 1, rig.outcomes.count(passwordverify.OutcomeMatched))
	require.Equal(t, 2, rig.outcomes.count(passwordverify.OutcomeMismatched))
}

// ── Неизвестный клиент стоит столько же ─────────────────────────────────────

// Клиент, которого у службы нет, и клиент без секрета получают тот же вердикт,
// что неверный секрет, — и за ту же цену: проверяющий ВЫЧИСЛЯЕТ сверку против
// выравнивающего значения (исход «материала нет»), а не отвечает мгновенно.
// Иначе время отказа — прибор перебора зарегистрированных клиентов.
func TestClientSecrets_UnknownAndPublicClientsCostAVerification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		clientID string
		asked    []string
	}{
		{"клиента нет", unknownClientID, []string{unknownClientID}},
		{"у клиента нет секрета", publicClientID, []string{publicClientID}},
		{"клиент не назван", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newSecretsRig(t)
			verdict, err := rig.port.VerifyClientSecret(context.Background(), tc.clientID,
				oauthceremony.NewPresentedSecret(rightClientSecret))
			require.NoError(t, err, "клиент без проверочного значения — несовпадение, а не отказ операции")
			require.Equal(t, oauthceremony.SecretMismatched, verdict)
			require.Equal(t, 1, rig.outcomes.count(passwordverify.OutcomeMaterialMissing),
				"сверка против выравнивающего значения не вычислена — отказ дешевле настоящего")
			require.Equal(t, 1, rig.outcomes.total(), "сверка на один вызов порта — ровно одна")
			require.Equal(t, tc.asked, rig.store.askedFor())
		})
	}

	t.Run("близнец: известный клиент с неверным секретом сверяется со своим значением", func(t *testing.T) {
		rig := newSecretsRig(t)
		verdict, err := rig.port.VerifyClientSecret(context.Background(), testClientID,
			oauthceremony.NewPresentedSecret(wrongClientSecret))
		require.NoError(t, err)
		require.Equal(t, oauthceremony.SecretMismatched, verdict)
		require.Equal(t, 1, rig.outcomes.count(passwordverify.OutcomeMismatched))
		require.Zero(t, rig.outcomes.count(passwordverify.OutcomeMaterialMissing))
	})
}

// ── Несостоявшаяся сверка — отказ операции ──────────────────────────────────

// Отказ справочника — не «клиент не доказан»: несостоявшаяся сверка не вправе
// стать ни одним из вердиктов. Отказ не несёт ни случая фундамента (его
// церемония прочла бы как нарушение контракта порта), ни предъявленного
// секрета; срок и отмена вызова узнаются своими часовыми.
func TestClientSecrets_StoreFailureIsAnOperationFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail error
	}{
		{"справочник недоступен", errors.New("connection refused")},
		{"срок вызова вышел", context.DeadlineExceeded},
		{"вызов отменён", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newSecretsRig(t)
			rig.store.fail = tc.fail
			verdict, err := rig.port.VerifyClientSecret(context.Background(), testClientID,
				oauthceremony.NewPresentedSecret(rightClientSecret))
			require.Error(t, err, "отказ справочника стал вердиктом")
			require.ErrorIs(t, err, tc.fail, "причина отказа справочника потеряна")
			require.Equal(t, oauthceremony.SecretVerdictUnspecified, verdict)
			require.Equal(t, oauthceremony.CodeUnspecified, oauthceremony.CodeOf(err),
				"отказ операции несёт случай фундамента — церемония прочла бы его нарушением контракта")
			require.NotContains(t, err.Error(), rightClientSecret, "предъявленный секрет в тексте отказа")
			require.Zero(t, rig.outcomes.total(), "сверка вычислена без проверочного значения")
		})
	}

	t.Run("близнец: тот же вызов при ответившем справочнике — вердикт", func(t *testing.T) {
		rig := newSecretsRig(t)
		verdict, err := rig.port.VerifyClientSecret(context.Background(), testClientID,
			oauthceremony.NewPresentedSecret(rightClientSecret))
		require.NoError(t, err)
		require.Equal(t, oauthceremony.SecretMatched, verdict)
	})
}

// ── Каждый исход проверяющего — свой ответ ──────────────────────────────────

// stubChecker — проверяющий, отвечающий названным исходом.
type stubChecker struct{ outcome passwordverify.Outcome }

func (s stubChecker) VerifyPresented(domain.LoginVerifier, passwordverify.Presented) passwordverify.Result {
	return passwordverify.Result{Outcome: s.outcome}
}

func (stubChecker) Aligned() bool { return true }

// Словарь исходов проверяющего ЗАКРЫТ, и у каждого исхода — свой ответ порта:
// совпал · не совпал · сверка не состоялась. Исход, которого эта таблица не
// знает, — находка: словарь вырос, и решение о новом исходе не принято.
func TestClientSecrets_EveryVerifierOutcomeHasAnAnswer(t *testing.T) {
	type answer struct {
		verdict oauthceremony.SecretVerdict
		refused bool
	}
	want := map[passwordverify.Outcome]answer{
		passwordverify.OutcomeMatched:             {verdict: oauthceremony.SecretMatched},
		passwordverify.OutcomeMismatched:          {verdict: oauthceremony.SecretMismatched},
		passwordverify.OutcomeMaterialMissing:     {verdict: oauthceremony.SecretMismatched},
		passwordverify.OutcomeCapacityExhausted:   {refused: true},
		passwordverify.OutcomeFormatNotInRegistry: {refused: true},
		passwordverify.OutcomeBodyNotParsable:     {refused: true},
		passwordverify.OutcomeParamsAboveCeiling:  {refused: true},
	}
	outcomes := passwordverify.Outcomes()
	require.NotEmpty(t, outcomes, "НЕ ВЫПОЛНИЛОСЬ: словарь исходов пуст")
	hasher := floorHasher(t)
	stored, err := hasher.Hash(rightClientSecret)
	require.NoError(t, err)

	for _, outcome := range outcomes {
		t.Run(string(outcome), func(t *testing.T) {
			expected, known := want[outcome]
			require.Truef(t, known, "у исхода %q нет ответа порта — словарь проверяющего вырос", outcome)
			store := &secretStore{verifiers: map[string]domain.LoginVerifier{testClientID: stored}}
			port, err := ceremonyport.NewClientSecrets(store, stubChecker{outcome: outcome})
			require.NoError(t, err)

			verdict, err := port.VerifyClientSecret(context.Background(), testClientID,
				oauthceremony.NewPresentedSecret(rightClientSecret))
			if !expected.refused {
				require.NoError(t, err)
				require.Equal(t, expected.verdict, verdict)
				return
			}
			require.Error(t, err, "несостоявшаяся сверка стала вердиктом")
			require.Equal(t, oauthceremony.SecretVerdictUnspecified, verdict)
			require.Contains(t, err.Error(), string(outcome), "отказ не называет исход проверяющего")
			require.Contains(t, err.Error(), testClientID, "отказ не называет клиента")
			require.NotContains(t, err.Error(), rightClientSecret, "предъявленный секрет в тексте отказа")
			require.Equal(t, oauthceremony.CodeUnspecified, oauthceremony.CodeOf(err))
		})
	}
	require.Len(t, want, len(outcomes), "таблица ответов знает исход, которого в словаре нет")
}

// ── Сборка ──────────────────────────────────────────────────────────────────

// Сборка отказывает в том, чем порт не сможет исполнить контракт, а не отвечает
// на первом запросе: без справочника сверять не с чем, без проверяющего нечем, а
// проверяющий без выравнивающего значения отвечал бы неизвестному клиенту
// мгновенно.
func TestNewClientSecrets_RefusesWhatCannotHonourTheContract(t *testing.T) {
	hasher := floorHasher(t)
	aligned := alignedVerifier(t, hasher, &outcomeCounter{cells: map[passwordverify.Outcome]int{}})
	bare, err := passwordverify.New(1, &outcomeCounter{cells: map[passwordverify.Outcome]int{}})
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		store   ceremonyport.SecretVerifierStore
		checker ceremonyport.SecretChecker
		says    string
	}{
		{"справочника нет", nil, aligned, "store"},
		{"проверяющего нет", &secretStore{}, nil, "checker"},
		{"проверяющий не выровнен", &secretStore{}, bare, "decoy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, err := ceremonyport.NewClientSecrets(tc.store, tc.checker)
			require.Error(t, err)
			require.Nil(t, port)
			require.True(t, strings.Contains(err.Error(), tc.says), "отказ сборки не называет причину: %v", err)
		})
	}

	t.Run("близнец: справочник и выровненный проверяющий собираются", func(t *testing.T) {
		port, err := ceremonyport.NewClientSecrets(&secretStore{}, aligned)
		require.NoError(t, err)
		require.NotNil(t, port)
	})
}
