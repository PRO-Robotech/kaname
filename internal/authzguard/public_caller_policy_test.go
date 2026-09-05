// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// public_caller_policy_test.go — кто вправе ВЫЗЫВАТЬ публичный листенер iam.
//
// Предмет. Внутренний листенер уже несёт пер-RPC политику вызывающего
// (caller_policy.go): пол из проверенного сертификата модуля плюс закрепление
// привилегированных RPC за одним отправителем. У публичного (:9090) политики не
// было НИКАКОЙ — и это не мелочь, потому что iam на :9090 сознательно НЕ
// перепроверяет права конечного пользователя (единственная парадная дверь —
// api-gateway). То есть любой сосед с законным сертификатом внутреннего центра
// присылал заголовки личности жертвы и получал её полномочия на всей
// тенантской поверхности: аккаунты, проекты, группы, роли, выдачи — и чеканку
// личных токенов и ключей служебных учёток.
//
// Список отправителей (grpcsrv.WithTrustedForwarders) сужает круг до «наши
// модули», но НЕ до «нужный модуль на нужном RPC»: сосед из списка всё ещё мог бы
// чеканить токены от чужого имени. Эта политика и есть то сужение.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

const (
	// storageSAN — сосед с законным сертификатом внутреннего центра: storage
	// ходит на :9090 за ProjectService.Get.
	//
	// Строка взята из чарта, который этот сертификат выдаёт, а не написана по
	// образцу: сегмент пространства имён у storage СВОЙ. Здесь это не влияет на
	// исход — политика читает только сегмент учётной записи, — но списку
	// отправителей (точное совпадение) такая описка стоила бы молчаливого отказа
	// рабочему пути, поэтому привычка брать строку из чарта заводится сразу.
	storageSAN = "spiffe://kacho.cloud/ns/kacho-storage/sa/kacho-storage"

	// operatorSAN — сертификат СНЯТОГО сетевого оператора. Чарта, который его
	// выпускал бы, в дереве нет, каталога модуля нет, репозитория нет — строка
	// живёт здесь ровно как вход отрицания
	// (TestPublicCallerPolicy_RetiredOperatorFanoutIsNotCallable): предъявитель
	// такого сертификата обязан быть отвергнут на всём публичном листенере.
	operatorSAN = "spiffe://kacho.cloud/ns/kacho-vpc-operator/sa/kacho-vpc-operator"

	// projectGetMethod — единственный публичный RPC, который зовут ВСЕ
	// consumer-модули (vpc/compute/nlb/storage/registry): существование проекта
	// и его аккаунт на пути запроса Create.
	projectGetMethod = "/kacho.cloud.iam.v1.ProjectService/Get"
	// projectListMethod / accountListMethod — два списочных RPC, которые прежде
	// стояли в таблице под веер снятого оператора. Соседо-вызываемыми они больше
	// не объявлены; остаются здесь как предмет отрицания и как часть поверхности,
	// доступной парадной двери.
	projectListMethod = "/kacho.cloud.iam.v1.ProjectService/List"
	accountListMethod = "/kacho.cloud.iam.v1.AccountService/List"

	// userTokenIssueMethod — представитель того, что ДОЛЖНО остаться только за
	// парадной дверью: чеканка личного токена пользователя. Ровно этот RPC
	// показывает цену дыры — сосед выпускал бы носитель прав от чужого имени.
	userTokenIssueMethod = "/kacho.cloud.iam.v1.UserTokenService/Issue"
	// accessBindingCreateMethod — второй представитель: выдача прав.
	accessBindingCreateMethod = "/kacho.cloud.iam.v1.AccessBindingService/Create"
	// projectDeleteMethod — третий: необратимая мутация тенантского ресурса.
	projectDeleteMethod = "/kacho.cloud.iam.v1.ProjectService/Delete"

	// batchCheckMethod — пер-страничный фильтр видимости List у vpc/compute/nlb/
	// storage (internal/authzfilter). Единственный метод AuthorizeService, который
	// кто-либо из них зовёт.
	batchCheckMethod = "/kacho.cloud.iam.v1.AuthorizeService/BatchCheck"

	// registrySAN — живой модуль, который вправе спросить ProjectService.Get и
	// НЕ вправе спросить BatchCheck (фильтра страницы у него нет). Пара
	// «допущен на своё ребро / отвергнут на чужое» на одном и том же
	// сертификате — то, чем проверяется пообъектность допуска.
	registrySAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-registry"
)

func newStorageCtx() context.Context {
	return grpcsrv.WithCertIdentity(context.Background(), storageSAN, true)
}

func newOperatorCtx() context.Context {
	return grpcsrv.WithCertIdentity(context.Background(), operatorSAN, true)
}

func testPublicPolicy(prod bool) *PublicCallerPolicy {
	return NewPublicCallerPolicy(prod, PublicPeerCallableRPCs())
}

// ── сердце правки: сосед не зовёт то, что за парадной дверью ────────────────

// TestPublicCallerPolicy_NeighbourDeniedOnGatewayOnlyRPC — главный замок.
//
// RED до правки: публичной политики нет вовсе, сосед доходит до обработчика.
func TestPublicCallerPolicy_NeighbourDeniedOnGatewayOnlyRPC(t *testing.T) {
	p := testPublicPolicy(true)
	for _, method := range []string{userTokenIssueMethod, accessBindingCreateMethod, projectDeleteMethod} {
		t.Run(method, func(t *testing.T) {
			for name, ctx := range map[string]context.Context{
				"storage":  newStorageCtx(),
				"vpc":      newVPCCtx(),
				"registry": grpcsrv.WithCertIdentity(context.Background(), registrySAN, true),
			} {
				err := p.allow(ctx, method)
				if err == nil {
					t.Fatalf("%s reached %s on the public listener: iam does NOT re-ReBAC the end user "+
						"there, so with a forwarded identity this neighbour acts with the victim's "+
						"authority", name, method)
				}
				if status.Code(err) != codes.PermissionDenied {
					t.Fatalf("%s: code = %v, want PermissionDenied", name, status.Code(err))
				}
				if msg := status.Convert(err).Message(); msg != "permission denied" {
					t.Fatalf("%s: message = %q, want the verbatim non-leaking %q", name, msg, "permission denied")
				}
			}
		})
	}
}

// TestPublicCallerPolicy_GatewayMayCallEverything — парадная дверь не сужена: за
// ней стоит проверка прав пользователя, ради которой всё и построено.
func TestPublicCallerPolicy_GatewayMayCallEverything(t *testing.T) {
	p := testPublicPolicy(true)
	for _, method := range []string{
		userTokenIssueMethod, accessBindingCreateMethod, projectDeleteMethod,
		projectGetMethod, projectListMethod, accountListMethod,
		"/kacho.cloud.operation.OperationService/Get",
	} {
		if err := p.allow(newGatewayCtx(), method); err != nil {
			t.Fatalf("api-gateway denied on %s: %v — the change denies service instead of narrowing it", method, err)
		}
	}
}

// TestPublicCallerPolicy_PeerReadEdgesKeepWorking — обратная ошибка: сузить так,
// что встанет рабочий путь. ProjectService.Get — путь запроса Create у ПЯТИ
// сервисов; BatchCheck — пер-страничный фильтр видимости у четырёх. Без них
// Create в vpc/compute/nlb/storage/registry отвечал бы отказом, а List у тенанта
// возвращал бы пустоту при живых ресурсах.
func TestPublicCallerPolicy_PeerReadEdgesKeepWorking(t *testing.T) {
	p := testPublicPolicy(true)

	for _, san := range []string{
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-compute",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-nlb",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-storage",
		registrySAN,
	} {
		ctx := grpcsrv.WithCertIdentity(context.Background(), san, true)
		if err := p.allow(ctx, projectGetMethod); err != nil {
			t.Fatalf("%s denied on %s: %v — this is the request-path project validation of Create", san, projectGetMethod, err)
		}
	}
	// Пер-страничный фильтр видимости: без него List у тенанта отвечает пустотой
	// (фильтр падает закрыто), хотя ресурсы у него есть.
	for _, san := range []string{
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-compute",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-nlb",
		storageSAN,
	} {
		ctx := grpcsrv.WithCertIdentity(context.Background(), san, true)
		if err := p.allow(ctx, batchCheckMethod); err != nil {
			t.Fatalf("%s denied on %s: %v — это пер-страничный фильтр видимости List", san, batchCheckMethod, err)
		}
	}
}

// TestPublicCallerPolicy_PeerReadEdgeIsPerRPCNotPerCaller — допуск выдан на
// конкретный RPC, а не «этому модулю на всё»: storage вправе спросить проект и
// не вправе его удалить.
func TestPublicCallerPolicy_PeerReadEdgeIsPerRPCNotPerCaller(t *testing.T) {
	p := testPublicPolicy(true)
	if err := p.allow(newStorageCtx(), projectGetMethod); err != nil {
		t.Fatalf("storage denied on its own read edge: %v", err)
	}
	if err := p.allow(newStorageCtx(), projectDeleteMethod); err == nil {
		t.Fatal("storage reached ProjectService/Delete — the allowance must be per-RPC, not per-caller")
	}
}

// TestPublicCallerPolicy_PeerReadEdgeIsPerCallerNotOpenToAll — и наоборот:
// разрешённый RPC открыт перечисленным вызывающим, а не любому модулю. registry
// вправе спросить проект и НЕ вправе спросить фильтр видимости страницы:
// пообъектного фильтра у него нет, и допуск об этом знает.
func TestPublicCallerPolicy_PeerReadEdgeIsPerCallerNotOpenToAll(t *testing.T) {
	p := testPublicPolicy(true)
	registryCtx := grpcsrv.WithCertIdentity(context.Background(), registrySAN, true)
	if err := p.allow(registryCtx, projectGetMethod); err != nil {
		t.Fatalf("контроль: registry отвергнут на своём ребре %s: %v", projectGetMethod, err)
	}
	if err := p.allow(registryCtx, batchCheckMethod); err == nil {
		t.Fatalf("registry дошёл до %s — допуск на этот RPC назван четырём модулям с "+
			"пообъектным фильтром, а не всякому, кто уже допущен куда-то ещё", batchCheckMethod)
	}
}

// ── пол: без проверенного сертификата модуля ────────────────────────────────

// TestPublicCallerPolicy_NoVerifiedCert_Prod — боевой режим fail-closed.
func TestPublicCallerPolicy_NoVerifiedCert_Prod(t *testing.T) {
	p := testPublicPolicy(true)
	for _, ctx := range []context.Context{
		context.Background(),
		grpcsrv.WithCertIdentity(context.Background(), gatewaySAN, false), // предъявлен, но не проверен
		grpcsrv.WithCertIdentity(context.Background(), "spiffe://kacho.cloud/ns/kacho/sa/hydra", true),
	} {
		if err := p.allow(ctx, projectGetMethod); err == nil {
			t.Fatal("a caller without a verified kacho module certificate passed the public floor")
		}
	}
}

// TestPublicCallerPolicy_Dev_NoOp — dev остаётся сквозным (in-process фикстуры,
// newman-стенд без mTLS). На РАЗВЁРНУТОМ стенде dev-посадка запрещена отдельным
// правилом.
func TestPublicCallerPolicy_Dev_NoOp(t *testing.T) {
	p := testPublicPolicy(false)
	for _, ctx := range []context.Context{context.Background(), newStorageCtx()} {
		if err := p.allow(ctx, userTokenIssueMethod); err != nil {
			t.Fatalf("dev must be a pass-through, got: %v", err)
		}
	}
}

// ── интерсепторы ───────────────────────────────────────────────────────────

// TestPublicCallerPolicy_Unary_Denies — политика обязана быть смонтирована как
// интерсептор, а не просто существовать функцией.
func TestPublicCallerPolicy_Unary_Denies(t *testing.T) {
	p := testPublicPolicy(true)
	_, err := p.Unary()(newStorageCtx(), nil,
		&grpc.UnaryServerInfo{FullMethod: userTokenIssueMethod}, okHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unary interceptor: code = %v, want PermissionDenied", status.Code(err))
	}
}

// TestPublicCallerPolicy_Stream_Denies — тот же контракт для потоковых RPC.
func TestPublicCallerPolicy_Stream_Denies(t *testing.T) {
	p := testPublicPolicy(true)
	err := p.Stream()(nil, fakeStream{ctx: newStorageCtx()},
		&grpc.StreamServerInfo{FullMethod: userTokenIssueMethod}, okStreamHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stream interceptor: code = %v, want PermissionDenied", status.Code(err))
	}
}

// ── состав таблицы ─────────────────────────────────────────────────────────

// TestPublicPeerCallableRPCs_CarryNoMutation — таблица допусков соседям обязана
// оставаться ЗАПРАШИВАЮЩЕЙ. Мутация, попавшая сюда, отдала бы соседу право менять
// тенантские данные от чужого имени — то самое, что правка закрывает.
//
// Проверяем по КОНТРАКТУ, а не по привычке именования: в Kachō мутация — это в
// точности RPC, возвращающий Operation. Суффиксный список («только Get и List»)
// был бы формой без содержания — он развалился бы на первом же законном
// запрашивающем методе с другим именем (BatchCheck) и при этом пропустил бы
// мутацию, названную, скажем, `ApplyList`.
func TestPublicPeerCallableRPCs_CarryNoMutation(t *testing.T) {
	returns := protoReturnTypes(t)
	for method := range PublicPeerCallableRPCs() {
		ret, ok := returns[method]
		if !ok {
			t.Fatalf("%s отсутствует в proto — таблица допусков разошлась с контрактом", method)
		}
		if strings.Contains(ret, "Operation") {
			t.Fatalf("%s возвращает %s, то есть МУТИРУЕТ: сосед менял бы тенантские данные от "+
				"имени переданного пользователя — ровно та дыра, которую политика закрывает", method, ret)
		}
	}
}

// protoReturnTypes читает `Service/Method → тип ответа` прямо из .proto — из
// источника истины контракта, а не из копии, которую пришлось бы поддерживать.
func protoReturnTypes(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "..", "proto", "kacho", "cloud", "iam", "v1")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read proto dir %s: %v", dir, err)
	}
	svcRe := regexp.MustCompile(`^service\s+(\w+)`)
	rpcRe := regexp.MustCompile(`^\s*rpc\s+(\w+)\s*\([^)]*\)\s*returns\s*\(\s*([\w.]+)`)
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".proto" {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		svc := ""
		for _, ln := range strings.Split(string(b), "\n") {
			if m := svcRe.FindStringSubmatch(ln); m != nil {
				svc = m[1]
				continue
			}
			if m := rpcRe.FindStringSubmatch(ln); m != nil && svc != "" {
				out["/kacho.cloud.iam.v1."+svc+"/"+m[1]] = m[2]
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("не разобрано ни одного rpc из %s — страж потерял источник истины", dir)
	}
	return out
}

// TestPublicPeerCallableRPCs_NamesNoGateway — gateway разрешён отдельной ветвью;
// дублировать его в таблице значит завести второй источник истины, который
// разъедется.
func TestPublicPeerCallableRPCs_NamesNoGateway(t *testing.T) {
	for method, svcs := range PublicPeerCallableRPCs() {
		for _, svc := range svcs {
			if svc == "api-gateway" {
				t.Fatalf("%s lists the api-gateway explicitly — it is already allowed everywhere by "+
					"its own arm; two sources of truth drift", method)
			}
		}
	}
}

// TestPublicPeerCallableRPCs_EveryCallerHasAModuleInTheTree — допуск в таблице
// обязан называть модуль, который в дереве ЕСТЬ.
//
// Это гейт на КЛАСС, а не на один случай. Запись под вызывающего, которого нет,
// невозможно отличить от записи под вызывающего, который есть: она той же формы
// в таблице, той же формы в ревью, той же формы в отказе. Разница только в том,
// что первая ничего не разрешает сегодня — и разрешит всё, что в ней написано,
// в тот день, когда кто-нибудь выпустит сертификат с таким именем. Тот же класс
// уже находился в кругах доверенных отправителей (ebedae53), и там он держался
// проверкой, которая лишнюю запись ТРЕБОВАЛА.
//
// Предикат — каталог `services/<имя>/`. Он самоистекает: заведут модуль со своим
// каталогом — гейт пройдёт сам, без чьей-либо памяти. api-gateway в таблице не
// значится по построению (у него своя ветвь, это держит
// TestPublicPeerCallableRPCs_NamesNoGateway), поэтому отсутствие у него каталога
// в `services/` предмета здесь не составляет.
func TestPublicPeerCallableRPCs_EveryCallerHasAModuleInTheTree(t *testing.T) {
	modules := serviceModulesInTree(t)
	seen := 0
	for method, svcs := range PublicPeerCallableRPCs() {
		for _, svc := range svcs {
			seen++
			if _, ok := modules[svc]; !ok {
				t.Fatalf("%s допускает %q, а каталога services/%s в дереве нет: допуск выдан "+
					"предъявителю сертификата, которого мы не выпускаем и не контролируем",
					method, svc, svc)
			}
		}
	}
	// Объём осмотренного: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	t.Logf("осмотрено: допусков в таблице=%d, модулей в дереве=%d", seen, len(modules))
	if seen == 0 {
		t.Fatal("предпосылка гейта нарушена: таблица допусков пуста — проверять нечего")
	}
	if len(modules) == 0 {
		t.Fatal("предпосылка гейта нарушена: в дереве не найдено ни одного модуля — " +
			"любой допуск прошёл бы даром")
	}
}

// serviceModulesInTree возвращает короткие имена модулей продукта — по каталогам
// `services/*`, а не по списку в коде: список разошёлся бы с деревом молча.
func serviceModulesInTree(t *testing.T) map[string]struct{} {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "..", "services")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read services dir %s: %v", dir, err)
	}
	out := map[string]struct{}{}
	for _, e := range entries {
		if e.IsDir() {
			out[e.Name()] = struct{}{}
		}
	}
	return out
}

// ── снятый сетевой оператор ────────────────────────────────────────────────

// TestPublicCallerPolicy_RetiredOperatorFanoutIsNotCallable — веер снятого
// сетевого оператора (AccountService.List → ProjectService.List) публичным
// листенером больше не обслуживается.
//
// Предмет. Компонента нет: ни каталога в дереве, ни репозитория, ни чарта,
// который выпускал бы ему сертификат, — поэтому оба допуска не описывали
// действующее ребро, а держали открытой поверхность под имя. Пока имя стоит в
// таблице, любой, кто когда-нибудь получит сертификат с этим SAN, читает два
// списочных RPC iam ЗА пользователя, чью личность он передаст.
//
// Утверждается ДВА разных свойства, и одного не хватило бы:
//   - таблица не несёт эти методы КЛЮЧАМИ (запись — это объявление ребра; ребра
//     нет, значит не должно быть и объявления);
//   - вызов с сертификатом оператора отвергается в боевом режиме — то есть
//     проверяется ИСХОД, а не только состав таблицы.
//
// Форма снятия — ОТСУТСТВИЕ ключа, а не ключ с пустым списком. По исходу они
// неразличимы, и это здесь же доказано положительным контролём ниже: индексация
// отсутствующего ключа даёт nil-карту, индексация nil-карты законна и даёт
// «не найдено», поэтому отвергают обе формы одинаково. Различие — в том, что
// ключ с пустым списком ОБЪЯВЛЯЕТ метод соседо-вызываемым (его читают
// TestPublicPeerCallableRPCs_CarryNoMutation и человек в ревью) и приглашает
// вписать вызывающего в уже готовую строку.
//
// RED до правки: таблица несёт оба метода, оператор на них проходит.
func TestPublicCallerPolicy_RetiredOperatorFanoutIsNotCallable(t *testing.T) {
	retired := []string{accountListMethod, projectListMethod}

	table := PublicPeerCallableRPCs()
	if len(table) == 0 {
		t.Fatal("предпосылка нарушена: таблица допусков пуста — отрицание прошло бы даром")
	}
	for _, method := range retired {
		if callers, present := table[method]; present {
			t.Fatalf("%s всё ещё объявлен соседо-вызываемым (вызывающие: %v): компонента, ради "+
				"которого допуск заводился, в дереве нет — снимается ЗАПИСЬ, а не её содержимое",
				method, callers)
		}
	}

	p := testPublicPolicy(true)
	for _, method := range retired {
		err := p.allow(newOperatorCtx(), method)
		if err == nil {
			t.Fatalf("сертификат снятого оператора прошёл на %s: iam на публичном листенере НЕ "+
				"перепроверяет права конечного пользователя, поэтому предъявитель действует с "+
				"полномочиями того, чью личность он передал", method)
		}
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: код = %v, ожидался PermissionDenied", method, status.Code(err))
		}
		if msg := status.Convert(err).Message(); msg != "permission denied" {
			t.Fatalf("%s: сообщение = %q, ожидалось невыдающее %q", method, msg, "permission denied")
		}
	}

	// Положительный контроль тем же путём: живое ребро на месте. Без него
	// отрицание зеленело бы и на политике, отвергающей вообще всех.
	if err := p.allow(newStorageCtx(), projectGetMethod); err != nil {
		t.Fatalf("контроль: storage отвергнут на своём живом ребре %s: %v — отрицание выше "+
			"получено бы даром", projectGetMethod, err)
	}

	// Контроль формы: ключ с ПУСТЫМ списком отвергает ровно так же. Значит выбор
	// «снять запись» сделан не ради исхода, а ради правдивости таблицы, — и
	// «починка» дописыванием пустой строки этот гейт не обойдёт.
	empty := NewPublicCallerPolicy(true, map[string][]string{accountListMethod: {}})
	if err := empty.allow(newOperatorCtx(), accountListMethod); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("контроль формы: пустой список вызывающих дал код %v, ожидался PermissionDenied — "+
			"объяснение в шапке о неразличимости исходов неверно и его надо переписать",
			status.Code(err))
	}
}
