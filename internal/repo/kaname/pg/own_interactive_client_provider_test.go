// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// own_interactive_client_provider_test.go — СПОСОБ аутентификации клиента,
// которого заводит собственный реестр посадки без внешнего поставщика, судится
// решением Р3 одобренной приёмки LINE-A-1 (kacho-workspace,
// docs/specs/sub-phase-LINE-A-1-own-authorization-endpoint-and-code-acceptance.md,
// строка 3 таблицы решений; сценарии LINE-A-1-10 и LINE-A-1-12): интерактивный
// клиент КОНФИДЕНЦИАЛЬНЫЙ и аутентифицируется на обмене секретом (задача
// PRO-Robotech/kaname#405, приёмка
// docs/engineering/acceptance/confidential-interactive-client-secret-shown-once.md).
//
// Судится выход исполнителя заведения, а не строка базы: способ, секрет и его
// проверочное значение производит он, а схема только принимает любой способ
// своего закрытого словаря (`interactive_clients_auth_method_ck`, kaname#317).
// Поэтому пробы не поднимают базы — хранилище заведению не нужно.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// confidentialAuthMethods — способы словаря схемы, у которых клиент предъявляет
// секрет. Способ `none` (публичный клиент) в перечень не входит, и это предмет
// пробы, а не умолчание.
var confidentialAuthMethods = []string{"client_secret_basic", "client_secret_post"}

// clientStoreDouble — снятие проверочного значения: заведению не нужно, но
// исполнитель без реестра не строится.
type clientStoreDouble struct{}

func (clientStoreDouble) ClearClientSecretVerifier(context.Context, string) error { return nil }

// floorDeclared — объявленный класс записи на полу перечня argon2id: тот же
// производитель и тот же класс, что пишет пароли и приманку проверяющего.
func floorDeclared(t *testing.T) passwordverify.Declared {
	t.Helper()
	record, ok := domain.PasswordHashFormatByMarker(string(domain.PasswordHashFormatArgon2id))
	require.True(t, ok, "формат argon2id обязан стоять в перечне")
	return passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id, Params: record.Floor}
}

func floorHasher(t *testing.T) *passwordverify.Hasher {
	t.Helper()
	h, err := passwordverify.NewHasher(floorDeclared(t))
	require.NoError(t, err, "хешер объявленного формата")
	return h
}

func ownProvider(t *testing.T) *kanamepg.OwnInteractiveClientProvider {
	t.Helper()
	p, err := kanamepg.NewOwnInteractiveClientProvider(clientStoreDouble{}, floorHasher(t))
	require.NoError(t, err, "исполнитель над реестром и хешером")
	return p
}

func ownSpec() interactiveclient.ProviderClientSpec {
	return interactiveclient.ProviderClientSpec{
		Name:                   "console",
		RedirectURIs:           []string{"https://console.example.test/cb"},
		PostLogoutRedirectURIs: []string{"https://console.example.test/"},
		Audiences:              []string{"https://api.example.test"},
		GrantTypes:             []string{"authorization_code", "refresh_token"},
	}
}

// shownSecret — значение секрета единственным его выходом: полем ответа.
func shownSecret(pc interactiveclient.ProviderClient) string {
	var resp iamv1.CreateInteractiveClientResponse
	pc.Secret.IntoResponse(&resp)
	return resp.GetClientSecret()
}

// TestOwnInteractiveClientRegistrationDeclaresAConfidentialClient — собственный
// реестр заводит клиента, который аутентифицируется на обмене (Р3).
func TestOwnInteractiveClientRegistrationDeclaresAConfidentialClient(t *testing.T) {
	provider := ownProvider(t)
	spec := ownSpec()

	pc, err := provider.Register(context.Background(), spec)
	require.NoError(t, err, "заведение на годном входе")

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же вызов, та же форма ответа — имя клиента
	// отчеканено своей приставкой, виды выдачи и получатели возвращены дословно.
	// Без него красное ниже читалось бы и как «заведение не состоялось вовсе».
	require.True(t, strings.HasPrefix(pc.ClientID, "oic-"),
		"имя клиента не отчеканено собственной приставкой: %q", pc.ClientID)
	require.Equal(t, spec.GrantTypes, pc.GrantTypes, "виды выдачи решает вызывающий")
	require.Equal(t, spec.Audiences, pc.Audiences, "получателей решает вызывающий")

	// ПРЕДМЕТ: способ — секретом. Отличие от близнеца ровно в одном факте.
	require.Contains(t, confidentialAuthMethods, pc.TokenEndpointAuthMethod,
		"собственный реестр завёл клиента со способом %q, а Р3 одобренной приёмки "+
			"LINE-A-1 требует конфиденциального клиента, аутентифицируемого на обмене",
		pc.TokenEndpointAuthMethod)
	require.Equal(t, "client_secret_basic", pc.TokenEndpointAuthMethod,
		"Р1 приёмки #405: способ — client_secret_basic (RFC 6749 §2.3.1 обязывает его всякий сервер)")
}

// unreserved — незарезервированные знаки RFC 3986 §2.3. Движок церемонии
// снимает процентное кодирование с обеих половин Basic, и `+` стал бы пробелом у
// клиента, не кодирующего пару; знаки этого множества кодированию не подлежат.
var unreserved = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// countingReader — источник, считающий потреблённые байты; значения берёт у
// обёрнутого.
type countingReader struct {
	src  io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	c.read += n
	return n, err
}

// TestOwnInteractiveClientSecretIsStrongAndUnreserved — условие поверхности
// п.5 (Р2 приёмки): секрет — не меньше 128 бит из источника случайности, в
// алфавите незарезервированных знаков, и зависит от КАЖДОГО потреблённого байта.
func TestOwnInteractiveClientSecretIsStrongAndUnreserved(t *testing.T) {
	ctx := context.Background()

	pc, err := ownProvider(t).Register(ctx, ownSpec())
	require.NoError(t, err)
	s := shownSecret(pc)
	require.NotEmpty(t, s, "заведение секрета не выдало")
	require.Regexp(t, unreserved, s, "секрет несёт знаки вне незарезервированных RFC 3986")

	again, err := ownProvider(t).Register(ctx, ownSpec())
	require.NoError(t, err)
	require.NotEqual(t, s, shownSecret(again), "два заведения выдали один секрет")

	// Сколько случайности потреблено — считает источник, а не длина строки:
	// длина говорит об алфавите, а не о случайности за ним.
	zeros := &countingReader{src: bytes.NewReader(make([]byte, 4096))}
	first, err := ownProvider(t).WithClientSecretEntropy(zeros).Register(ctx, ownSpec())
	require.NoError(t, err)
	require.GreaterOrEqual(t, zeros.read*8, 128, "секрет потребил %d бит случайности, пол — 128", zeros.read*8)

	// Каждый потреблённый байт меняет секрет: иначе часть случайности
	// выбрасывается, и «потреблено 128 бит» не значит «несёт 128 бит».
	for i := 0; i < zeros.read; i++ {
		buf := make([]byte, 4096)
		buf[i] = 0x80
		pcI, err := ownProvider(t).WithClientSecretEntropy(bytes.NewReader(buf)).Register(ctx, ownSpec())
		require.NoError(t, err)
		require.NotEqualf(t, shownSecret(first), shownSecret(pcI),
			"байт %d источника на секрет не повлиял — случайность выброшена", i)
	}
}

// TestOwnInteractiveClientSecretVerifierIsOfThatSecretAndOfTheLaneClass —
// условие поверхности п.6: проверочное значение — ЭТОГО секрета и ТОГО ЖЕ
// класса, что приманка проверяющего; иначе отказ незаведённому клиенту стоил
// бы иначе, чем заведённому, и время ответа перечисляло бы клиентов.
func TestOwnInteractiveClientSecretVerifierIsOfThatSecretAndOfTheLaneClass(t *testing.T) {
	declared := floorDeclared(t)
	pc, err := ownProvider(t).Register(context.Background(), ownSpec())
	require.NoError(t, err)
	require.False(t, pc.SecretVerifier.IsZero(), "проверочного значения нет — клиенту нечего будет предъявить")

	checker, err := passwordverify.New(1, nopObserver{})
	require.NoError(t, err)

	s := shownSecret(pc)
	got := checker.Verify(pc.SecretVerifier, s)
	require.Equal(t, passwordverify.OutcomeMatched, got.Outcome, "проверочное значение не этого секрета")
	mangled := "X" + s[1:]
	if mangled == s {
		mangled = "Y" + s[1:]
	}
	require.Equal(t, passwordverify.OutcomeMismatched, checker.Verify(pc.SecretVerifier, mangled).Outcome,
		"секрет с одним изменённым знаком прошёл сверку")

	meets, err := checker.MeetsDeclared(pc.SecretVerifier, declared)
	require.NoError(t, err)
	require.True(t, meets, "проверочное значение не отвечает объявленному классу записи")

	decoy, err := floorHasher(t).Hash("decoy-of-the-lane")
	require.NoError(t, err)
	dres := checker.Verify(decoy, "x")
	require.Equal(t, dres.Format, got.Format, "формат проверочного значения не тот, что у приманки")
	require.Equal(t, dres.Params, got.Params, "параметры проверочного значения не те, что у приманки")
}

// nopObserver — приёмник исходов проверяющего без счёта.
type nopObserver struct{}

func (nopObserver) VerificationObserved(passwordverify.Outcome) {}

// failingEntropy — источник случайности, который не отвечает.
type failingEntropy struct{}

func (failingEntropy) Read([]byte) (int, error) { return 0, errors.New("entropy source unavailable") }

// TestOwnInteractiveClientRegistrationRefusesWithoutEntropy — условие
// поверхности п.5: сорванный источник случайности даёт ОТКАЗ фиксированным
// текстом, а не секрет предсказуемого вида.
func TestOwnInteractiveClientRegistrationRefusesWithoutEntropy(t *testing.T) {
	pc, err := ownProvider(t).WithClientSecretEntropy(failingEntropy{}).Register(context.Background(), ownSpec())
	require.Error(t, err, "секрет выдан при сорванном источнике случайности")
	require.True(t, pc.Secret.IsZero(), "при отказе исполнитель вернул секрет")
	require.True(t, pc.SecretVerifier.IsZero(), "при отказе исполнитель вернул проверочное значение")
	require.Empty(t, pc.ClientID, "при отказе исполнитель вернул клиента")

	st, _ := status.FromError(shared.MapRepoErr(err))
	require.Equal(t, codes.Internal, st.Code())
	require.Equal(t, "internal error", st.Message(), "текст отказа обязан быть фиксированным")
}

// TestOwnInteractiveClientProviderRefusesToBeBuiltIncomplete — условие
// поверхности п.9 на уровне исполнителя: без хешера нечем положить
// проверочное значение, без реестра — нечем его снять; сборка отказывает, а не
// заводит клиента без материала.
func TestOwnInteractiveClientProviderRefusesToBeBuiltIncomplete(t *testing.T) {
	_, err := kanamepg.NewOwnInteractiveClientProvider(clientStoreDouble{}, nil)
	require.Error(t, err, "исполнитель собран без хешера")
	require.Contains(t, err.Error(), "hasher")

	_, err = kanamepg.NewOwnInteractiveClientProvider(nil, floorHasher(t))
	require.Error(t, err, "исполнитель собран без реестра")
	require.Contains(t, err.Error(), "registry")

	_, err = kanamepg.NewOwnInteractiveClientProvider(clientStoreDouble{}, floorHasher(t))
	require.NoError(t, err, "ЗАКОННЫЙ БЛИЗНЕЦ: реестр и хешер — сборка проходит")
}
