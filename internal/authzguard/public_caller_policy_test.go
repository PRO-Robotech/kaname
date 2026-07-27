// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
	// storageSAN / operatorSAN — соседи с законным сертификатом внутреннего
	// центра. storage ходит на :9090 за ProjectService.Get; оператор — за
	// AccountService.List → ProjectService.List (SEC-G).
	//
	// Обе строки взяты из чартов, которые эти сертификаты выдают, а не написаны по
	// образцу: сегмент пространства имён у них СВОЙ. Здесь это не влияет на исход —
	// политика читает только сегмент учётной записи, — но списку отправителей
	// (точное совпадение) такая описка стоила бы молчаливого отказа рабочему пути,
	// поэтому привычка брать строку из чарта заводится сразу.
	storageSAN  = "spiffe://kacho.cloud/ns/kacho-storage/sa/kacho-storage"
	operatorSAN = "spiffe://kacho.cloud/ns/kacho-vpc-operator/sa/kacho-vpc-operator"

	// projectGetMethod — единственный публичный RPC, который зовут ВСЕ
	// consumer-модули (vpc/compute/nlb/storage/registry): существование проекта
	// и его аккаунт на пути запроса Create.
	projectGetMethod = "/kacho.cloud.iam.v1.ProjectService/Get"
	// projectListMethod / accountListMethod — ребро SEC-G оператора пространств
	// имён: он веером читает аккаунты, затем проекты.
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
				"operator": newOperatorCtx(),
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
// сервисов; ProjectService.List / AccountService.List — веер оператора (SEC-G).
// Без них Create в vpc/compute/nlb/storage/registry отвечал бы отказом, а
// оператор перестал бы видеть проекты.
func TestPublicCallerPolicy_PeerReadEdgesKeepWorking(t *testing.T) {
	p := testPublicPolicy(true)

	for _, san := range []string{
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-compute",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-nlb",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-storage",
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-registry",
	} {
		ctx := grpcsrv.WithCertIdentity(context.Background(), san, true)
		if err := p.allow(ctx, projectGetMethod); err != nil {
			t.Fatalf("%s denied on %s: %v — this is the request-path project validation of Create", san, projectGetMethod, err)
		}
	}
	for _, method := range []string{accountListMethod, projectListMethod} {
		if err := p.allow(newOperatorCtx(), method); err != nil {
			t.Fatalf("the namespace operator was denied on %s: %v — SEC-G fan-out read", method, err)
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
// разрешённый RPC открыт перечисленным вызывающим, а не любому модулю. Веер
// оператора не должен становиться общедоступным списком аккаунтов.
func TestPublicCallerPolicy_PeerReadEdgeIsPerCallerNotOpenToAll(t *testing.T) {
	p := testPublicPolicy(true)
	if err := p.allow(newStorageCtx(), accountListMethod); err == nil {
		t.Fatal("storage reached AccountService/List — the allowance names the operator, not every module")
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
