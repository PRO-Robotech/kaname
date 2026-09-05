// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics_test

// authz_lanes_test.go — счётчик решений видит ВСЕ полосы, которыми у владельца
// прав спрашивают доступ.
//
// # Предмет
//
// Полос три, и они принадлежат разным вызывающим:
//
//   - `Check` — КРАЙ, по одному вопросу на входящий запрос арендатора;
//   - `BatchCheck` — сужатель списочной выдачи модулей, по вопросу на КАЖДЫЙ
//     объект страницы (страница контрактно бывает до тысячи);
//   - `CheckRelation` — пообъектное звено решения модулей, по вопросу на RPC.
//
// Счётчик видел ОДНУ из трёх. Следствие прямое: всякое «проверок в секунду»,
// снятое с владельца прав, занижено — на пути чтения по идентификатору ровно
// вдвое, потому что там проверок две (край и сервис), а видна была вторая.
//
// # Почему пробы утверждают РОСТ, а не наличие серии
//
// «Метрика зарегистрирована» этого класса не ловит: серия с меткой, у которой
// нет производителя, присутствует, отдаёт ноль и выглядит исправным
// наблюдением. Ровно так полоса края и прожила своё время — объявленная в
// комментарии типа наблюдения и не эмитируемая ни одним прод-местом.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-iam/internal/observability/metrics"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// fakeSubjectAuthorizer — решатель полос края и сужателя.
type fakeSubjectAuthorizer struct {
	allowed bool
	err     error
	batch   []*service.CheckResult
}

func (f fakeSubjectAuthorizer) Check(_ context.Context, _ service.CheckRequest) (*service.CheckResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &service.CheckResult{Allowed: f.allowed}, nil
}

func (f fakeSubjectAuthorizer) BatchCheck(_ context.Context, reqs []service.CheckRequest) ([]*service.CheckResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.batch != nil {
		return f.batch, nil
	}
	out := make([]*service.CheckResult, 0, len(reqs))
	for range reqs {
		out = append(out, &service.CheckResult{Allowed: f.allowed})
	}
	return out, nil
}

func (f fakeSubjectAuthorizer) ListSubjects(context.Context, service.ListSubjectsRequest) (*service.ListSubjectsResult, error) {
	return nil, nil
}

func (f fakeSubjectAuthorizer) ExpandRelations(context.Context, service.ExpandRequest) (*service.ExpandResult, error) {
	return nil, nil
}

// TestEdgeLaneCheckIsObserved — полоса КРАЯ растёт, и растёт независимо от
// полосы модулей.
//
// Независимость утверждается прямо: пока полосы не было, её ноль был неотличим
// от «краю не задавали вопросов», и обе прочитались бы как одна.
func TestEdgeLaneCheckIsObserved(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	dec := metrics.NewInstrumentedSubjectAuthorizer(fakeSubjectAuthorizer{allowed: true}, reg)

	const calls = 3
	for i := 0; i < calls; i++ {
		res, err := dec.Check(context.Background(), service.CheckRequest{
			Subject: "user:usr_x", Action: "vpc.networks.get",
		})
		if err != nil {
			t.Fatalf("Check err: %v", err)
		}
		if res == nil || !res.Allowed {
			t.Fatal("решение изменено декоратором — он обязан быть сквозным")
		}
	}

	dump := dumpMetrics(t, reg)
	if got := counterValue(t, dump, `kacho_iam_authz_check_decisions_total{decision="allow",rpc="Check"}`); got != calls {
		t.Fatalf("полоса края = %v, ждали %d.\n\nСчётчик, не видящий полосу края, занижает "+
			"«проверок в секунду» вдвое на пути чтения по идентификатору.\n%s", got, calls, dump)
	}
	if got := counterValue(t, dump, `kacho_iam_authz_check_duration_seconds_count{allowed="true",rpc="Check"}`); got != calls {
		t.Fatalf("длительность полосы края = %v, ждали %d", got, calls)
	}
	// Полоса модулей не тронута: полосы обязаны быть РАЗНЫМИ сериями.
	if strings.Contains(dump, `rpc="CheckRelation"} `+fmt.Sprint(calls)) {
		t.Fatalf("вопросы края попали в полосу модулей — полосы не различаются:\n%s", dump)
	}
}

// TestEdgeLaneCountsADenyAndAnError — три исхода полосы края различимы.
//
// Без этого счётчик отвечал бы на «сколько спросили», но не на «чем кончилось»,
// а решение о ёмкости принимается по второму: отказ владельца прав стоит ему
// столько же, сколько разрешение.
func TestEdgeLaneCountsADenyAndAnError(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	deny := metrics.NewInstrumentedSubjectAuthorizer(fakeSubjectAuthorizer{allowed: false}, reg)
	if _, err := deny.Check(context.Background(), service.CheckRequest{Subject: "user:usr_x"}); err != nil {
		t.Fatalf("Check err: %v", err)
	}
	boom := metrics.NewInstrumentedSubjectAuthorizer(fakeSubjectAuthorizer{err: errors.New("store down")}, reg)
	if _, err := boom.Check(context.Background(), service.CheckRequest{Subject: "user:usr_x"}); err == nil {
		t.Fatal("ошибка проглочена декоратором — он обязан быть сквозным")
	}

	dump := dumpMetrics(t, reg)
	if got := counterValue(t, dump, `kacho_iam_authz_check_decisions_total{decision="deny",rpc="Check"}`); got != 1 {
		t.Fatalf("отказ полосы края = %v, ждали 1:\n%s", got, dump)
	}
	if got := counterValue(t, dump, `kacho_iam_authz_check_decisions_total{decision="error",rpc="Check"}`); got != 1 {
		t.Fatalf("сбой полосы края = %v, ждали 1:\n%s", got, dump)
	}
}

// TestBatchLaneCountsEveryQuestion — полоса сужателя считает ВОПРОСЫ, а не
// вызовы.
//
// Разница не бухгалтерская: страница контрактно бывает до тысячи объектов, и
// счёт по вызовам занизил бы нагрузку от списочной выдачи в тысячу раз — то
// есть сделал бы её невидимой ровно там, где она наибольшая.
func TestBatchLaneCountsEveryQuestion(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	dec := metrics.NewInstrumentedSubjectAuthorizer(fakeSubjectAuthorizer{
		batch: []*service.CheckResult{{Allowed: true}, {Allowed: false}, {Allowed: true}},
	}, reg)

	reqs := []service.CheckRequest{{Subject: "user:usr_x"}, {Subject: "user:usr_x"}, {Subject: "user:usr_x"}}
	if _, err := dec.BatchCheck(context.Background(), reqs); err != nil {
		t.Fatalf("BatchCheck err: %v", err)
	}

	dump := dumpMetrics(t, reg)
	if got := counterValue(t, dump, `kacho_iam_authz_check_decisions_total{decision="allow",rpc="BatchCheck"}`); got != 2 {
		t.Fatalf("разрешений полосы сужателя = %v, ждали 2 (вопросов в пачке три):\n%s", got, dump)
	}
	if got := counterValue(t, dump, `kacho_iam_authz_check_decisions_total{decision="deny",rpc="BatchCheck"}`); got != 1 {
		t.Fatalf("отказов полосы сужателя = %v, ждали 1:\n%s", got, dump)
	}
	// Длительность принадлежит ВЫЗОВУ, а не вопросу: делить её на вопросы значило
	// бы утверждать про каждый то, чего никто не измерял.
	if got := counterValue(t, dump, `kacho_iam_authz_check_duration_seconds_count{allowed="true",rpc="BatchCheck"}`); got != 1 {
		t.Fatalf("наблюдений длительности пачки = %v, ждали 1 (одно на вызов):\n%s", got, dump)
	}
}

// TestEveryDeclaredLaneHasAProducer — словарь полос и производители СХОДЯТСЯ.
//
// Гейт против того самого класса, из которого выросла задача: полоса, названная
// в словаре и не эмитируемая ничем, присутствует нулём и выглядит исправным
// наблюдением. Проба гоняет ВСЕ декораторы и сверяет множество увиденных меток
// с объявленным — поэтому четвёртая полоса без производителя краснеет, а
// производитель без объявления краснеет тоже.
func TestEveryDeclaredLaneHasAProducer(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	subject := metrics.NewInstrumentedSubjectAuthorizer(fakeSubjectAuthorizer{allowed: true}, reg)
	if _, err := subject.Check(context.Background(), service.CheckRequest{Subject: "user:usr_x"}); err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if _, err := subject.BatchCheck(context.Background(), []service.CheckRequest{{Subject: "user:usr_x"}}); err != nil {
		t.Fatalf("BatchCheck err: %v", err)
	}
	relation := metrics.NewInstrumentedAuthorizer(fakeAuthorizer{allowed: true}, reg)
	if _, err := relation.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: "user:usr_x", Relation: "viewer", Object: "vpc_network:vpcn_y",
	}); err != nil {
		t.Fatalf("CheckRelation err: %v", err)
	}

	produced := lanesInDump(dumpMetrics(t, reg))
	declared := append([]string(nil), metrics.DeclaredAuthzLanes()...)
	sort.Strings(declared)
	sort.Strings(produced)
	if strings.Join(declared, ",") != strings.Join(produced, ",") {
		t.Fatalf("объявлено полос %v, произведено %v.\n\nПолоса без производителя присутствует "+
			"нулём и выглядит исправным наблюдением; производитель без объявления делает словарь "+
			"меток открытым, и число серий начинает расти с данными запроса.", declared, produced)
	}
	t.Logf("перепись: полос объявлено %d, произведено %d: %v", len(declared), len(produced), produced)
}

// TestServedCheckCountsAgreeWithTheAuthzCounter — сверка ДВУХ независимых
// счётчиков одного предмета.
//
// Это вторая половина предиката снятия задачи: число проверок обязано сходиться
// с числом, снятым независимым способом. Способы здесь и правда независимы —
// один считает транспорт (звено сервера, метка метода), другой решатель
// (декоратор, метка полосы), и разъехаться они могут молча.
func TestServedCheckCountsAgreeWithTheAuthzCounter(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	dec := metrics.NewInstrumentedSubjectAuthorizer(fakeSubjectAuthorizer{allowed: true}, reg)
	// Счётчик транспорта — платформенный, заведённый сквозь окно регистрации: тот
	// же измеритель, что провязывает композиционный корень. Независимость двух
	// способов от этого не страдает — считают по-прежнему разные механизмы.
	lat, lerr := grpcsrv.NewServerLatency(reg.Registerer())
	if lerr != nil {
		t.Fatalf("измеритель задержки: %v", lerr)
	}
	intr := lat.UnaryServerInterceptor(grpcsrv.ListenerPublic)

	const calls = 5
	for i := 0; i < calls; i++ {
		_, err := intr(context.Background(), nil,
			&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AuthorizeService/Check"},
			func(ctx context.Context, _ any) (any, error) {
				return dec.Check(ctx, service.CheckRequest{Subject: "user:usr_x"})
			})
		if err != nil {
			t.Fatalf("вызов %d: %v", i, err)
		}
	}

	dump := dumpMetrics(t, reg)
	served := counterValue(t, dump,
		`kacho_grpc_server_handled_total{grpc_code="OK",grpc_method="Check",`+
			`grpc_service="kacho.cloud.iam.v1.AuthorizeService",listener="public"}`)
	decided := counterValue(t, dump, `kacho_iam_authz_check_decisions_total{decision="allow",rpc="Check"}`)
	if served != calls || decided != calls {
		t.Fatalf("обслужено %v, решений %v, вызовов %d — счётчики разошлись:\n%s",
			served, decided, calls, dump)
	}
}

// counterValue достаёт значение серии из выгрузки. Отсутствие серии — ОТКАЗ, а
// не ноль: «серии нет» и «серия равна нулю» суть разные факты, и путать их —
// ровно тот класс, ради которого эти пробы написаны.
func counterValue(t *testing.T, dump, series string) float64 {
	t.Helper()
	for _, ln := range strings.Split(dump, "\n") {
		if !strings.HasPrefix(ln, series+" ") {
			continue
		}
		var v float64
		if _, err := fmt.Sscanf(strings.TrimPrefix(ln, series+" "), "%g", &v); err != nil {
			t.Fatalf("значение серии %s не читается из %q: %v", series, ln, err)
		}
		return v
	}
	t.Fatalf("серии %s в выгрузке нет вовсе — это не ноль, а отсутствие производителя:\n%s",
		series, dump)
	return 0
}

var laneLabel = regexp.MustCompile(`kacho_iam_authz_check_decisions_total\{[^}]*rpc="([^"]+)"`)

// lanesInDump — множество полос, ФАКТИЧЕСКИ появившихся в выгрузке.
func lanesInDump(dump string) []string {
	seen := map[string]bool{}
	for _, m := range laneLabel.FindAllStringSubmatch(dump, -1) {
		seen[m[1]] = true
	}
	out := make([]string, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	return out
}
