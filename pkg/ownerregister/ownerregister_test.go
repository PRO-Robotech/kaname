// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package ownerregister_test

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kaname/pkg/ownerregister"
)

// recordingRPC — дублёр владельца прав. Он ЗАПИСЫВАЕТ то, что получил, и
// отвечает по заранее заданному плану; ничего не смягчает и ничего не
// додумывает. Дублёр, принимающий больше настоящего, сделал бы невидимым именно
// тот дефект, ради которого его подставляют.
type recordingRPC struct {
	got  []*iamv1.RegisterResourceRequest
	errs []error // ответ на i-й вызов; короче набора ⇒ дальше nil
}

func (r *recordingRPC) RegisterResource(ctx context.Context, in *iamv1.RegisterResourceRequest, _ ...grpc.CallOption) (*iamv1.RegisterResourceResponse, error) {
	r.got = append(r.got, in)
	if _, ok := ctx.Deadline(); !ok {
		// Срок вызова — часть контракта, а не украшение: доставка идёт из
		// воркера на detached-контексте, и без срока неотвечающий владелец
		// вешает горутину навсегда.
		return nil, errors.New("вызов пришёл БЕЗ предельного срока")
	}
	i := len(r.got) - 1
	if i < len(r.errs) {
		return nil, r.errs[i]
	}
	return &iamv1.RegisterResourceResponse{}, nil
}

func reg(object string, g int64) ownerregister.Registration {
	return ownerregister.Registration{
		Object: object,
		Tuples: []ownerregister.Tuple{
			{SubjectID: "project:prj-1", Relation: "project"},
			{SubjectID: "user:usr-1", Relation: "owner"},
		},
		TraceID:         "res-1",
		Labels:          map[string]string{"env": "prod"},
		ParentProjectID: "prj-1",
		ParentAccountID: "acc-1",
		Generation:      g,
	}
}

// TestGenerationFromWriterTxIsForwardedVerbatim — поколение, проставленное в
// writer-транзакции, доезжает до владельца прав БЕЗ ИЗМЕНЕНИЙ.
//
// Обе доставки одной строки обязаны нести одно значение — иначе гашение
// редоставки у принимающей стороны зависит от того, кто выиграл гонку.
// Утверждается РАВЕНСТВО отправленного исходному, а не «поколение не пусто».
func TestGenerationFromWriterTxIsForwardedVerbatim(t *testing.T) {
	const stamp int64 = 41
	rpc := &recordingRPC{}
	r, err := ownerregister.New(rpc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Register(context.Background(), []ownerregister.Registration{reg("vpc_network:net-1", stamp)}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(rpc.got) != 1 {
		t.Fatalf("доставок %d, ждали 1", len(rpc.got))
	}
	if gotG := rpc.got[0].GetGeneration(); gotG != stamp {
		t.Fatalf("поколение изменилось в пути: отправлено %d, проставлено writer-транзакцией %d", gotG, stamp)
	}
}

// TestEveryFieldOfTheMirrorFeedIsForwarded — форвардится ВЕСЬ набор полей
// зеркала, включая TraceID и ParentAccountID, и ВЕСЬ набор кортежей события —
// одним вызовом (приёмка NTF-3, Р30 «Единица поколения — событие»).
//
// Их недосылали три регистратора из пяти. Недосланное поле не роняет ничего
// сразу — оно молча обедняет зеркало владельца прав, а по зеркалу резолвится
// принадлежность объекта проекту (анти-BOLA) и матчатся селекторы меток.
func TestEveryFieldOfTheMirrorFeedIsForwarded(t *testing.T) {
	rpc := &recordingRPC{}
	r, _ := ownerregister.New(rpc)
	in := reg("nlb_load_balancer:lb-1", 1)
	if err := r.Register(context.Background(), []ownerregister.Registration{in}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(rpc.got) != 1 {
		t.Fatalf("событие ушло %d вызовами, ждали один — кортежи одного поколения по отдельности теряются", len(rpc.got))
	}
	got := rpc.got[0]
	if len(got.GetTuples()) != len(in.Tuples) {
		t.Fatalf("кортежей события в пути %d, отправлено %d", len(got.GetTuples()), len(in.Tuples))
	}
	for i, tp := range in.Tuples {
		if g := got.GetTuples()[i]; g.GetSubjectId() != tp.SubjectID || g.GetRelation() != tp.Relation {
			t.Fatalf("кортеж %d события изменился в пути: %s#%s, ждали %s#%s", i, g.GetSubjectId(), g.GetRelation(), tp.SubjectID, tp.Relation)
		}
	}
	for _, c := range []struct{ name, want, have string }{
		{"Object", in.Object, got.GetObject()},
		{"TraceId", in.TraceID, got.GetTraceId()},
		{"ParentProjectId", in.ParentProjectID, got.GetParentProjectId()},
		{"ParentAccountId", in.ParentAccountID, got.GetParentAccountId()},
	} {
		if c.want != c.have {
			t.Fatalf("%s потеряно в пути: отправлено %q, ждали %q", c.name, c.have, c.want)
		}
	}
	if got.GetLabels()["env"] != "prod" {
		t.Fatalf("метки потеряны в пути: %v", got.GetLabels())
	}
}

// TestUnversionedRegistrationIsRefusedAndNotSent — регистрация без поколения НЕ
// отправляется и отказ называет объект.
//
// Принимающая сторона приёма без поколения не имеет и ответила бы отказом,
// который дренаж повторял бы вечно. Непротащенное поколение есть ошибка
// программиста, и она обязана быть слышна здесь, до провода.
func TestUnversionedRegistrationIsRefusedAndNotSent(t *testing.T) {
	rpc := &recordingRPC{}
	r, _ := ownerregister.New(rpc)
	err := r.Register(context.Background(), []ownerregister.Registration{reg("storage_volume:vol-1", 0)})
	if !errors.Is(err, ownerregister.ErrUnversioned) {
		t.Fatalf("регистрация без версии принята: %v", err)
	}
	if len(rpc.got) != 0 {
		t.Fatalf("регистрация без версии всё-таки ушла на провод: %+v", rpc.got)
	}
}

// TestNilClientRefusesInsteadOfSilentlyDoingNothing — несконфигурированный
// клиент есть ОТКАЗ, а не пустая операция.
//
// Пустая операция неотличима от исправной работы: ни отказа, ни строки в логе,
// ни одного срабатывания за всю жизнь. Ровно тот класс, который мы ловим в
// коде («ноль отказов за всю жизнь контроля» обязано быть заметно).
func TestNilClientRefusesInsteadOfSilentlyDoingNothing(t *testing.T) {
	if _, err := ownerregister.New(nil); !errors.Is(err, ownerregister.ErrNoClient) {
		t.Fatalf("нулевой клиент принят конструктором: %v", err)
	}
}

// TestFailureOnOneTupleDoesNotAbandonTheRest — отказ на одном событии НЕ
// прекращает набор событий: пробуются все, отказы объединяются.
//
// Положительная половина утверждения обязательна: без неё «все отвергнуты»
// зеленело бы на полностью мёртвом регистраторе. Поэтому здесь сразу два факта
// — сосед по набору ДОЕХАЛ, и отказ первого при этом НЕ потерян.
func TestFailureOnOneTupleDoesNotAbandonTheRest(t *testing.T) {
	boom := status.Error(codes.Unavailable, "владелец прав недоступен")
	rpc := &recordingRPC{errs: []error{boom}}
	r, _ := ownerregister.New(rpc)

	err := r.Register(context.Background(), []ownerregister.Registration{
		reg("registry_registry:reg-1", 2),
		reg("registry_repository:reg-1/app", 2),
	})

	if len(rpc.got) != 2 {
		t.Fatalf("после отказа на первой строке набор прекращён: доставок %d, ждали 2", len(rpc.got))
	}
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("отказ первой строки потерян: %v", err)
	}
}

// TestErrorIsSurfacedNotClassifiedAway — отказ владельца прав возвращается как
// есть; корзины «это ожидаемо» у регистратора нет.
//
// У одного из прежних регистраторов такая корзина была: `AlreadyExists`
// считался успехом. Производителя у этого входа нет — контракт RegisterResource
// идемпотентен и такого кода не отдаёт, — то есть ветка молчала на том, ради
// чего написана, и однажды проглотила бы настоящий отказ.
func TestErrorIsSurfacedNotClassifiedAway(t *testing.T) {
	denied := status.Error(codes.PermissionDenied, "least-priv отказал")
	rpc := &recordingRPC{errs: []error{denied}}
	r, _ := ownerregister.New(rpc)
	err := r.Register(context.Background(), []ownerregister.Registration{reg("compute_instance:ins-1", 3)})
	if err == nil {
		t.Fatal("терминальный отказ в правах проглочен — о нерегистрируемом ресурсе не узнает никто")
	}
	// Код обязан ДОСТАВАТЬСЯ вызывающим, а не только «ошибка не nil»: по коду
	// он отличает терминальный отказ (повтор не поможет) от временного.
	// errors.As идёт по дереву errors.Join, в отличие от errors.Unwrap.
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		t.Fatalf("из отказа не достать gRPC-статус — вызывающий не отличит терминальный от временного: %v", err)
	}
	if got := se.GRPCStatus().Code(); got != codes.PermissionDenied {
		t.Fatalf("код отказа подменён: %v", got)
	}
}

// TestEmptySetIsNotAnError — пустой набор не является отказом. Положительный
// контроль к отрицаниям выше: без него они зеленели бы на регистраторе,
// который отвергает всё подряд.
func TestEmptySetIsNotAnError(t *testing.T) {
	rpc := &recordingRPC{}
	r, _ := ownerregister.New(rpc)
	if err := r.Register(context.Background(), nil); err != nil {
		t.Fatalf("пустой набор объявлен отказом: %v", err)
	}
	if len(rpc.got) != 0 {
		t.Fatalf("пустой набор что-то отправил: %+v", rpc.got)
	}
}
