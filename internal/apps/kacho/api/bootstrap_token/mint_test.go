// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

type fakeTx struct{ committed, rolledback bool }

func (t *fakeTx) Commit(context.Context) error   { t.committed = true; return nil }
func (t *fakeTx) Rollback(context.Context) error { t.rolledback = true; return nil }

type fakeTxBeginner struct{ last *fakeTx }

func (b *fakeTxBeginner) Begin(context.Context) (service.Tx, error) {
	b.last = &fakeTx{}
	return b.last, nil
}

type fakeStore struct {
	existing  *domain.ServiceAccountOAuthClient
	inserted  *domain.ServiceAccountOAuthClient
	insertErr error
	lockCalls int
}

func (s *fakeStore) LockAndGet(context.Context, service.Tx) (domain.ServiceAccountOAuthClient, bool, error) {
	s.lockCalls++
	if s.existing != nil {
		return *s.existing, true, nil
	}
	return domain.ServiceAccountOAuthClient{}, false, nil
}

func (s *fakeStore) InsertMapping(_ context.Context, _ service.Tx, c domain.ServiceAccountOAuthClient) error {
	if s.insertErr != nil {
		return s.insertErr
	}
	cp := c
	s.inserted = &cp
	return nil
}

// fakeMinter — НАШ подписант с точки зрения пробы.
//
// Записывает ВЕСЬ вход, потому что предмет проверок ниже — что именно контур
// просит выпустить: принципала, адресата и срок он не берёт из запроса, и
// доказывается это значением, а не фактом вызова.
type fakeMinter struct {
	calls int
	last  MintInput
	out   MintOutput
	err   error
}

// MintToken отдаёт объявленный пробой исход ДОСЛОВНО.
//
// Ни одного «если пусто — подставим»: дублёр, снисходительнее продукта, делает
// невидимым ровно тот дефект, ради которого его подставляют. Пустой токен —
// законный вход этой пробы, и он обязан дойти до use-case пустым.
func (m *fakeMinter) MintToken(_ context.Context, in MintInput) (MintOutput, error) {
	m.calls++
	m.last = in
	if m.err != nil {
		return MintOutput{}, m.err
	}
	out := m.out
	if out.IssuedAt.IsZero() {
		out.IssuedAt = fixedNow
	}
	if out.ExpiresAt.IsZero() {
		out.ExpiresAt = out.IssuedAt.Add(in.TTL)
	}
	return out, nil
}

// okMinter — подписант, выпускающий токен. Отдельный построитель, потому что
// «выпустил» и «выпустил пустоту» суть разные входы, и различать их обязана
// проба, а не дублёр.
func okMinter() *fakeMinter { return &fakeMinter{out: MintOutput{AccessToken: "signed.by.us"}} }

var fixedNow = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

// ── helpers ───────────────────────────────────────────────────────────────────

func genES256PEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newUseCase(t *testing.T, store BootstrapStore, minter LocalMinter, cfg Config) *MintUseCase {
	t.Helper()
	if cfg.SigningKeyPEM == "" {
		cfg.SigningKeyPEM = genES256PEM(t)
	}
	if cfg.GatewayAudience == "" {
		cfg.GatewayAudience = "https://api.kacho.cloud"
	}
	return NewMintUseCase(store, &fakeTxBeginner{}, minter, cfg)
}

// ── чеканка идёт БЕЗ внешней стороны (задача #1119, предикат снятия п.2) ───────

// TestMintBootstrapToken_MintsWithNoProviderAnywhere — удостоверение выпускается
// на контуре, у которого внешнего поставщика нет ВОВСЕ.
//
// Утверждается НАБЛЮДАЕМОЕ — токен на руках у вызывающего, — а не «функция не
// позвана»: последнее зеленело бы и на реализации, которая зовёт поставщика и
// молча продолжает при его отказе. Дороги к поставщику у этого use-case нет by
// construction: у него нет ни одного порта, которым её можно было бы подать, и
// свойство дерева закреплено разбором в bootstraptokenwire/provider_absent_test.go.
func TestMintBootstrapToken_MintsWithNoProviderAnywhere(t *testing.T) {
	minter := okMinter()
	uc := newUseCase(t, &fakeStore{}, minter, Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	require.Equal(t, "signed.by.us", res.AccessToken)
	require.Equal(t, "Bearer", res.TokenType)
	require.Equal(t, 1, minter.calls)
	// Наш подписант получил ИМЕННО бутстрап-принципала и адресата края — ни то,
	// ни другое не приходит запросом.
	require.Equal(t, DeriveIdentity().SvaID, minter.last.PrincipalID)
	require.Equal(t, DeriveIdentity().SocID, minter.last.SAKeyID)
	require.Equal(t, "https://api.kacho.cloud", minter.last.Audience)
	require.Equal(t, MaxTTL, minter.last.TTL)
}

// ── чеканка нечем → fail-closed, без утечки причины ──────────────────────────

func TestMintBootstrapToken_MinterUnavailable_FailClosed(t *testing.T) {
	rawLeak := "dial tcp 10.1.2.3:5432: connection refused"
	minter := &fakeMinter{err: errors.Join(ErrMintingUnavailable, errors.New(rawLeak))}
	uc := newUseCase(t, &fakeStore{}, minter, Config{})

	res, err := uc.Execute(context.Background())
	require.Nil(t, res)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code(), "нечем выпустить ⇒ fail-closed UNAVAILABLE")
	// Никакого оракула и никакой инфра-утечки: фиксированный текст, не причина.
	require.Equal(t, "bootstrap token minting is unavailable", st.Message())
	require.NotContains(t, st.Message(), "10.1.2.3")
	require.NotContains(t, st.Message(), "connection refused")
}

// TestMintBootstrapToken_MintFailureOfAnotherKind_IsNotUnavailability — отказ,
// который повтором не лечится, не выдаётся за недоступность.
//
// Положительный контроль к пробе выше: без него «fail-closed» зеленело бы и на
// реализации, объявляющей недоступность на любом отказе, — то есть обещающей
// вызывающему повтор там, где он не пройдёт никогда.
func TestMintBootstrapToken_MintFailureOfAnotherKind_IsNotUnavailability(t *testing.T) {
	minter := &fakeMinter{err: errors.New("bootstrap token: sign: unsupported algorithm")}
	uc := newUseCase(t, &fakeStore{}, minter, Config{})

	_, err := uc.Execute(context.Background())
	require.Equal(t, codes.Internal, status.Code(err))
	require.Equal(t, "internal error", status.Convert(err).Message())
}

// TestMintBootstrapToken_EmptyTokenNeverPassesAsSuccess — «выпустили ничто» это
// дефект нашей провязки, а не недоступность.
func TestMintBootstrapToken_EmptyTokenNeverPassesAsSuccess(t *testing.T) {
	minter := &fakeMinter{out: MintOutput{AccessToken: "", IssuedAt: fixedNow, ExpiresAt: fixedNow.Add(time.Minute)}}
	uc := newUseCase(t, &fakeStore{}, minter, Config{})

	res, err := uc.Execute(context.Background())
	require.Nil(t, res)
	require.Equal(t, codes.Internal, status.Code(err))
}

// ── IBT-11: only-bootstrap — no arbitrary principal ─────────────────────────────

func TestMintBootstrapToken_NoArbitraryPrincipal(t *testing.T) {
	minter := okMinter()
	uc := newUseCase(t, &fakeStore{}, minter, Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	// The minted principal is ALWAYS the deterministic bootstrap SA — there is no
	// request field to name any other subject (skeleton-key rejected by construction).
	require.Equal(t, DeriveIdentity().SvaID, res.PrincipalID)
	require.Equal(t, "Bearer", res.TokenType)
	require.Equal(t, "https://api.kacho.cloud", minter.last.Audience)
}

// ── provisioning wiring (supports IBT-01/02/03 at the unit boundary) ────────────

func TestMintBootstrapToken_FirstCall_RecordsOurClientRow(t *testing.T) {
	store := &fakeStore{}
	uc := newUseCase(t, store, okMinter(), Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	require.NotNil(t, store.inserted, "строка соответствия записана")
	require.Equal(t, DeriveIdentity().SvaID, string(store.inserted.SvaID))
	require.Equal(t, DeriveIdentity().SocID, string(store.inserted.ID))
	require.Equal(t, "ES256", store.inserted.KeyAlgorithm)
	// Открытая половина — НАША запись о ключе бутстрап-клиента; приватная не
	// покидает окружения и в строку не попадает.
	require.NotEmpty(t, store.inserted.PublicKeyPEM)
	require.Contains(t, store.inserted.PublicKeyPEM, "BEGIN PUBLIC KEY")
	require.NotContains(t, store.inserted.PublicKeyPEM, "PRIVATE KEY")
	require.Equal(t, res.PrincipalID, string(store.inserted.SvaID))
}

func TestMintBootstrapToken_Idempotent_ReusesExistingMapping(t *testing.T) {
	existing := domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind: domain.CredentialKindKeypair,
		ID:             domain.SAOAuthClientID(DeriveIdentity().SocID),
		SvaID:          domain.ServiceAccountID(DeriveIdentity().SvaID),
		OAuthClientID:  domain.OAuthClientID(DeriveIdentity().ClientID),
	}
	store := &fakeStore{existing: &existing}
	uc := newUseCase(t, store, okMinter(), Config{})

	res, err := uc.Execute(context.Background())
	require.NoError(t, err)
	require.Nil(t, store.inserted, "новая строка соответствия не заводится")
	require.Equal(t, DeriveIdentity().SvaID, res.PrincipalID)
}

// ── signing-key-not-configured → fail-closed ────────────────────────────────────

func TestMintBootstrapToken_NoSigningKey_FailClosed(t *testing.T) {
	uc := NewMintUseCase(&fakeStore{}, &fakeTxBeginner{}, okMinter(), Config{
		GatewayAudience: "https://api.kacho.cloud",
		// SigningKeyPEM deliberately empty.
	})
	_, err := uc.Execute(context.Background())
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, "bootstrap token minting is not configured", status.Convert(err).Message())
}

// TestMintBootstrapToken_NoMinter_FailClosed — полусобранный контур отвечает
// отказом, а не паникует и не выдаёт токен.
func TestMintBootstrapToken_NoMinter_FailClosed(t *testing.T) {
	uc := NewMintUseCase(&fakeStore{}, &fakeTxBeginner{}, nil, Config{
		SigningKeyPEM:   genES256PEM(t),
		GatewayAudience: "https://api.kacho.cloud",
	})
	_, err := uc.Execute(context.Background())
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// ── ids are byte-identical to migration 0058 seed ───────────────────────────────

func TestDeriveIdentity_MatchesMigrationSeed(t *testing.T) {
	id := DeriveIdentity()
	require.Equal(t, "svab91854890de887e6d", id.SvaID)
	require.Equal(t, "soc_db27d17291ff453b6", id.SocID)
	require.Equal(t, "kacho-bootstrap-admin", id.ClientID)
	require.Equal(t, "usr1a18042d81fb438d6", id.CreatedByUserID)
	require.True(t, strings.HasPrefix(id.SvaID, "sva"))
}
