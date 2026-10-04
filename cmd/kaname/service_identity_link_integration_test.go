// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_identity_link_integration_test.go — звено Р2 на внутреннем
// слушателе kaname (полоса K5; приёмка NTF-1 NTF1-M07, NTF1-M09; замысел З13
// «Ручка kaname», «Звено наблюдаемо на голове K5»; CX1-105, CX1-107, CX1-110).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	(а) цепочка внутреннего слушателя собирается ОДНОЙ функцией корня
//	    `internalUnaryChain(deps)`: её зовут и `runServe`, и эта проба; состав и
//	    порядок перехватчиков здесь не перечисляются. `deps` без зависимости
//	    звена личности — ошибка сборки с именем звена (`identityUnary`);
//	    близнец — полный `deps` — цепочка собрана;
//	(б) заглушка `ResolveSend` (интерфейс K3c) первым стейтментом спрашивает
//	    `authz.CallerSubject` и отвечает `UNIMPLEMENTED`: сертификат notify,
//	    ключа `authn.service-identity` нет → записано `(—, false)`; согласный
//	    ключ → `service:notify`, `true`; код в обоих — `UNIMPLEMENTED`;
//	(в) инъекция одна — вход «звено без таблицы при согласном ключе» даёт
//	    `(—, false)`, и утверждение (б) на нём краснеет;
//	(г) стражи старта корня по ручке — по случаю на отказ, с именем ручки и
//	    значением (NTF1-M09 (а), (б), (в) и формы таблицы);
//	(д) самоотчёт несёт звено: `n/a` без ключа, перечень и строки таблицы — с
//	    ключом (Р2 п.7);
//	(е) NTF1-M07: ответы корпуса внутренних вызовов модулей с ключом и без
//	    побайтово равны, служебного субъекта у них нет, а
//	    `authzguard.PrincipalSubject` второго носителя не читает (УК3).
//
// Боевая пара на настоящем обработчике — не здесь, а в K3 (УК101).
//
// ─────────────────────────────────────────────────────────────────────────────
// КОНТРАКТ, КОТОРЫЙ ЗАДАЁТ ЭТА ПРОБА (полоса RED, до реализации)
//
//	type internalChainDeps struct {
//	    logger            *slog.Logger
//	    permRegistry      *seed.PermissionRegistry
//	    authn             *config.AuthNConfig        // звено личности (identityUnary + Р2)
//	    callerPolicy      *authzguard.CallerPolicy
//	    addressGate       *authzguard.AddressGate
//	    systemViewerFloor *authzguard.SystemViewerFloor
//	    acrFloor          *authzguard.ACRFloor
//	}
//	func internalUnaryChain(deps internalChainDeps) ([]grpc.UnaryServerInterceptor, error)
//
// Ключ файла `authn.service-identity` (`methods`, `services[{san, name}]`) —
// форма замысла З13; поле `AuthNConfig.ServiceIdentity`.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/corelib/authz"
	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ntfChainDeps — боевой `deps`: каждое существующее звено построено своим
// конструктором так же, как в `runServe` (боевой режим), звено личности —
// из настройки пробы.
func ntfChainDeps(t *testing.T, cfg *config.Config, db *ntfDB) internalChainDeps {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg, err := seed.LoadPermissionRegistry(context.Background(), logger)
	require.NoError(t, err, "фикстура: реестр прав не прочитан")
	_, relations := ntfDoor(db)
	return internalChainDeps{
		logger:            logger,
		permRegistry:      reg,
		authn:             &cfg.AuthN,
		callerPolicy:      authzguard.NewCallerPolicy(true, authzguard.GatewayFrontedInternalRPCs()),
		addressGate:       authzguard.NewAddressGate(personmarks.New(db.pool)),
		systemViewerFloor: authzguard.NewSystemViewerFloor(relations, authzguard.ReadFloorRPCs()).WithProductionMode(true),
		acrFloor:          authzguard.NewACRFloor(reg, authzguard.GatewayFrontedInternalRPCs()).WithProductionMode(true),
	}
}

// ntfSeen — что увидел обработчик: субъект `authz.CallerSubject` и признак.
type ntfSeen struct {
	subject string
	ok      bool
}

func (s ntfSeen) String() string {
	if s.subject == "" {
		return fmt.Sprintf("(—, %v)", s.ok)
	}
	return fmt.Sprintf("(%s, %v)", s.subject, s.ok)
}

// ntfResolveSendStub — заглушка сгенерированного K3c интерфейса: первым
// стейтментом зовёт ту же функцию, что обработчик K3 (З18), записывает
// исход и отвечает `UNIMPLEMENTED`.
type ntfResolveSendStub struct {
	iamv1.UnimplementedInternalNotificationGrantServiceServer
	mu   sync.Mutex
	seen []ntfSeen
}

func (s *ntfResolveSendStub) ResolveSend(ctx context.Context, _ *iamv1.ResolveSendRequest) (*iamv1.ResolveSendResponse, error) {
	c, ok := authz.CallerSubject(ctx)
	s.mu.Lock()
	s.seen = append(s.seen, ntfSeen{subject: c.Subject(), ok: ok})
	s.mu.Unlock()
	return nil, status.Error(codes.Unimplemented, "заглушка K5: обработчика нет")
}

func (s *ntfResolveSendStub) last(t *testing.T) ntfSeen {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.seen, "обработчик заглушки не вызван — звено не дошло до обработчика, вердикта о субъекте нет")
	return s.seen[len(s.seen)-1]
}

// ntfRecognitionFinding — утверждение (б) о положительном случае, вынесенное
// функцией, чтобы инъекция (в) судила ТО ЖЕ утверждение, а не своё.
func ntfRecognitionFinding(seen ntfSeen) string {
	if !seen.ok || seen.subject != "service:notify" {
		return "обработчик видит " + seen.String() + ", а не (service:notify, true): звено Р2 не опознало notify"
	}
	return ""
}

func ntfResolveSendRequest() *iamv1.ResolveSendRequest {
	return &iamv1.ResolveSendRequest{Namespace: "probe", Template: "probe-hello", EnqueuedAt: timestamppb.Now()}
}

// ntfStubPair — один случай пары (б): цепочка корня по настройке, заглушка,
// вызов с сертификатом notify. Возвращает код и записанное.
func ntfStubPair(t *testing.T, yaml string) (codes.Code, ntfSeen) {
	t.Helper()
	db := newNTFDB(t)
	cfg, err := ntfConfig(t, yaml)
	require.NoError(t, err, "настройка не загрузилась: %v", err)
	chain, err := internalUnaryChain(ntfChainDeps(t, &cfg, db))
	require.NoError(t, err, "цепочка внутреннего слушателя не собрана")
	stub := &ntfResolveSendStub{}
	lis := ntfServe(t, newNTFPKI(t), chain, func(s grpc.ServiceRegistrar) {
		iamv1.RegisterInternalNotificationGrantServiceServer(s, stub)
	})
	_, err = iamv1.NewInternalNotificationGrantServiceClient(lis.dial(t, ntfNotifySAN)).
		ResolveSend(context.Background(), ntfResolveSendRequest())
	return status.Code(err), stub.last(t)
}

// (а)
func TestNTF1K5_InternalChainIsBuiltByOneRootConstructor(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: адресный гейт цепочки строится над базой")
	}
	db := newNTFDB(t)
	cfg, err := ntfConfig(t, ntfAgreedIdentityYAML())
	require.NoError(t, err)

	t.Run("близнец: полный deps — цепочка собрана", func(t *testing.T) {
		chain, err := internalUnaryChain(ntfChainDeps(t, &cfg, db))
		require.NoError(t, err)
		require.NotEmpty(t, chain)
	})
	t.Run("deps без звена личности — ошибка сборки с именем звена", func(t *testing.T) {
		deps := ntfChainDeps(t, &cfg, db)
		deps.authn = nil
		chain, err := internalUnaryChain(deps)
		require.Error(t, err, "цепочка собрана без звена личности: сервер без извлечения служебного субъекта поднялся бы")
		require.Nil(t, chain)
		require.Contains(t, err.Error(), "identityUnary", "отказ обязан назвать звено")
	})
}

// (б), (в)
func TestNTF1K5_ResolveSendSeesTheServiceSubjectOnlyWithTheAgreedKey(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	absentCode, absent := ntfStubPair(t, "")
	agreedCode, agreed := ntfStubPair(t, ntfAgreedIdentityYAML())
	t.Logf("ключа нет: записано %s, код %s; согласный ключ: записано %s, код %s", absent, absentCode, agreed, agreedCode)

	t.Run("ключа нет — субъекта нет", func(t *testing.T) {
		require.Equal(t, ntfSeen{}, absent)
		require.Equal(t, codes.Unimplemented, absentCode)
	})
	t.Run("согласный ключ — service:notify", func(t *testing.T) {
		require.Empty(t, ntfRecognitionFinding(agreed))
		require.Equal(t, codes.Unimplemented, agreedCode)
	})
	t.Run("инъекция: звено без таблицы при согласном ключе — утверждение краснеет", func(t *testing.T) {
		// Вход инъекции — то, что видит обработчик, когда звено Р2 не опознало
		// пира: ровно запись случая «ключа нет», полученная прогоном выше.
		require.NotEmpty(t, ntfRecognitionFinding(absent),
			"утверждение о положительном случае зеленеет на записи (—, false) — оно не способно упасть")
	})
}

// (г)
func TestNTF1M09_RootRefusesAnInconsistentServiceIdentityKnob(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	db := newNTFDB(t)
	const (
		methodsKey  = "authn.service-identity.methods"
		servicesKey = "authn.service-identity.services"
	)
	nonCanonical := strings.Replace(ntfNotifySAN, "kacho.cloud", "KACHO.cloud", 1)
	cases := []struct {
		name, yaml string
		mustName   []string
	}{
		{"(а) перечень непуст, таблица пуста",
			ntfServiceIdentityYAML([]string{ntfResolveSendKey}, nil), []string{servicesKey}},
		{"(б) таблица непуста, перечень пуст",
			ntfServiceIdentityYAML(nil, [][2]string{{ntfNotifySAN, "notify"}}), []string{methodsKey}},
		{"(в) метод вне {ResolveSend}, хотя он в реестре прав",
			ntfServiceIdentityYAML([]string{ntfResolveSendKey, ntfCheckKey}, [][2]string{{ntfNotifySAN, "notify"}}),
			[]string{methodsKey, ntfCheckKey}},
		{"(г) один SAN дважды",
			ntfServiceIdentityYAML([]string{ntfResolveSendKey}, [][2]string{{ntfNotifySAN, "notify"}, {ntfNotifySAN, "notify-b"}}),
			[]string{servicesKey, ntfNotifySAN}},
		{"(д) одно имя дважды",
			ntfServiceIdentityYAML([]string{ntfResolveSendKey}, [][2]string{{ntfNotifySAN, "notify"}, {ntfForeignNotifySAN, "notify"}}),
			[]string{servicesKey, "notify"}},
		{"(е) имя не DNS label",
			ntfServiceIdentityYAML([]string{ntfResolveSendKey}, [][2]string{{ntfNotifySAN, "Notify_1"}}),
			[]string{servicesKey, "Notify_1"}},
		{"SAN не в канонической форме",
			ntfServiceIdentityYAML([]string{ntfResolveSendKey}, [][2]string{{nonCanonical, "notify"}}),
			[]string{servicesKey, nonCanonical}},
	}

	t.Run("близнец: согласный ключ — цепочка собрана", func(t *testing.T) {
		cfg, err := ntfConfig(t, ntfAgreedIdentityYAML())
		require.NoError(t, err)
		_, err = internalUnaryChain(ntfChainDeps(t, &cfg, db))
		require.NoError(t, err)
	})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := ntfConfig(t, c.yaml)
			require.NoError(t, err, "файл формы ключа обязан загрузиться: суждение о ручке — у корня, а не у декодера")
			chain, err := internalUnaryChain(ntfChainDeps(t, &cfg, db))
			require.Error(t, err, "корень принял несогласную ручку — слушатели поднялись бы")
			require.Nil(t, chain)
			for _, want := range c.mustName {
				require.Contains(t, err.Error(), want, "отказ обязан назвать ручку и значение")
			}
		})
	}
}

// (д)
func TestNTF1M09_SelfReportCarriesTheServiceIdentityLink(t *testing.T) {
	want, err := grpcsrv.NewServiceIdentity([]string{"/" + ntfResolveSendKey},
		map[string]grpcsrv.ServiceName{ntfNotifySAN: "notify"})
	require.NoError(t, err, "фикстура: ожидаемый отчёт звена не построен фундаментом")

	report := func(t *testing.T, yaml string) any {
		t.Helper()
		cfg, err := ntfConfig(t, yaml)
		require.NoError(t, err)
		// Боевая посадка принимается дескриптором только с шифрованием до
		// базы: без него проба судила бы отказ посадки, а не звено.
		cfg.Repository.Postgres.URL = "postgres://u:p@pg-iam:5432/kaname"
		cfg.Repository.Postgres.SSLMode = "require"
		line := captureBootPosture(t, bootPosture(acceptedPosture(t, cfg), cfg, config.MTLSConfig{}, true, restFrontUp(), restFrontUp()))
		got, ok := line["service_identity"]
		require.True(t, ok, "самоотчёт без поля service_identity: %v", line)
		return got
	}
	t.Run("ключа нет — звено NotApplicable", func(t *testing.T) {
		got := report(t, "")
		s, _ := got.(string)
		require.True(t, strings.HasPrefix(s, grpcsrv.ServiceIdentityNotApplicable),
			"service_identity = %q, ждали %q с причиной", s, grpcsrv.ServiceIdentityNotApplicable)
	})
	t.Run("согласный ключ — перечень и строки таблицы из файла", func(t *testing.T) {
		require.Equal(t, want.Report(), report(t, ntfAgreedIdentityYAML()))
	})
}

// ntfModuleCorpus — заглушка внутренней службы модулей: ответ кодирует то,
// что увидел обработчик, поэтому «ответы побайтово равны» включает и «субъект
// тот же».
type ntfModuleCorpus struct {
	iamv1.UnimplementedInternalIAMServiceServer
}

func ntfSaw(ctx context.Context) string {
	principal, pok := authzguard.PrincipalSubject(ctx)
	caller, cok := authz.CallerSubject(ctx)
	return fmt.Sprintf("principal=%s,%v|caller=%s,%v", principal, pok, caller.Subject(), cok)
}

func (ntfModuleCorpus) Check(ctx context.Context, _ *iamv1.CheckRequest) (*iamv1.CheckResponse, error) {
	return &iamv1.CheckResponse{Allowed: true, Reason: ntfSaw(ctx)}, nil
}

func (ntfModuleCorpus) RegisterResource(ctx context.Context, _ *iamv1.RegisterResourceRequest) (*iamv1.RegisterResourceResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, ntfSaw(ctx))
}

// (е) NTF1-M07
func TestNTF1M07_ModuleCallsAreUnchangedByTheServiceIdentityLink(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	type answer struct {
		code  codes.Code
		bytes string
	}
	corpus := func(t *testing.T, yaml, san string) map[string]answer {
		t.Helper()
		db := newNTFDB(t)
		cfg, err := ntfConfig(t, yaml)
		require.NoError(t, err)
		chain, err := internalUnaryChain(ntfChainDeps(t, &cfg, db))
		require.NoError(t, err)
		lis := ntfServe(t, newNTFPKI(t), chain, func(s grpc.ServiceRegistrar) {
			iamv1.RegisterInternalIAMServiceServer(s, ntfModuleCorpus{})
		})
		client := iamv1.NewInternalIAMServiceClient(lis.dial(t, san))
		out := map[string]answer{}
		check, err := client.Check(context.Background(), &iamv1.CheckRequest{
			SubjectId: "user:usr0000000000000m0701", Relation: "viewer", Object: "project:prj0000000000000m0701",
		})
		b, _ := proto.Marshal(check)
		out["Check"] = answer{code: status.Code(err), bytes: string(b) + status.Convert(err).Message()}
		_, err = client.RegisterResource(context.Background(), &iamv1.RegisterResourceRequest{})
		out["RegisterResource"] = answer{code: status.Code(err), bytes: status.Convert(err).Message()}
		return out
	}

	for _, san := range []string{ntfVPCSAN, ntfNotifySAN} {
		t.Run(san, func(t *testing.T) {
			before := corpus(t, "", san)
			after := corpus(t, ntfAgreedIdentityYAML(), san)
			t.Logf("до Р2: %v; после Р2: %v", before, after)
			require.Equal(t, before, after, "ответ внутреннего вызова модуля изменился со звеном Р2")
			for method, a := range after {
				require.NotContains(t, a.bytes, "service:", "у %s появился служебный субъект: перечень Р2 открыт шире {ResolveSend}", method)
			}
		})
	}
}
