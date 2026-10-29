// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_form_test.go — звено формы идентификатора (`OwnDoor.FormUnary`,
// kaname#168) в одиночку: когда оно отвечает, когда молчит и когда не
// собирается. Класс целиком через цепочку корня держит проба
// `cmd/kaname` `TestIAM_PNE_1_21_A_FormIsAnsweredBeforeTheDoorOnEveryObjectScopedRPC`;
// здесь — ветви самого звена, которые та проба видит лишь вскользь.

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// formJudge — судья-подделка: знает виды из known, отвергает всякий
// идентификатор без приставки "prj"; вызовы записывает.
type formJudge struct {
	known  map[string]bool
	judged []string
}

func (j *formJudge) Judges(objectType string) bool { return j.known[objectType] }

func (j *formJudge) Check(objectType, objectID string) error {
	j.judged = append(j.judged, objectType+":"+objectID)
	if !strings.HasPrefix(objectID, "prj") {
		return status.Errorf(codes.InvalidArgument, "invalid %s id '%s'", objectType, objectID)
	}
	return nil
}

// allKinds — все виды объектов класса и якоря роли.
func allKinds() map[string]bool {
	known := map[string]bool{}
	for _, rpc := range authzguard.ObjectScopedRPCs() {
		known[rpc.ObjectType] = true
	}
	known["account"], known["project"] = true, true
	return known
}

func formLink(t *testing.T, judge authzguard.IDFormJudge) grpc.UnaryServerInterceptor {
	t.Helper()
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: &grantStore{}})
	if err != nil {
		t.Fatalf("дверь не собралась: %v", err)
	}
	link, err := door.FormUnary(judge)
	if err != nil {
		t.Fatalf("звено формы не собралось: %v", err)
	}
	return link
}

const projectGet = "/kaname.cloud.iam.v1.ProjectService/Get"

func TestFormUnary_NamedCallerMalformedIDIsRefusedBeforeTheHandler(t *testing.T) {
	judge := &formJudge{known: allKinds()}
	link := formLink(t, judge)
	hit := false
	_, err := link(tenantCtx("usr00000000000000001"), &iamv1.GetProjectRequest{ProjectId: "qqq-not-a-project"},
		&grpc.UnaryServerInfo{FullMethod: projectGet}, reached(&hit))
	if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "invalid project id 'qqq-not-a-project'" {
		t.Fatalf("ответ %v, ожидался InvalidArgument с текстом судьи", err)
	}
	if hit {
		t.Fatal("обработчик позван после отказа формы")
	}
	// Законный близнец — та же цепочка, правильная форма: проход.
	hit = false
	if _, err := link(tenantCtx("usr00000000000000001"), &iamv1.GetProjectRequest{ProjectId: "prj00000000000notfnd"},
		&grpc.UnaryServerInfo{FullMethod: projectGet}, reached(&hit)); err != nil || !hit {
		t.Fatalf("правильная форма не прошла: err=%v, обработчик позван=%v", err, hit)
	}
}

// Пустая строка — отсутствие поля, строка из пробелов — неверная форма:
// идентификатором она не бывает ни при каком состоянии базы. Близнец —
// пустая строка той же цепочки — молчит (кейс «пустое поле» ниже).
func TestFormUnary_BlankIDIsMalformedNotAbsent(t *testing.T) {
	judge := &formJudge{known: allKinds()}
	hit := false
	_, err := formLink(t, judge)(tenantCtx("usr00000000000000001"), &iamv1.GetProjectRequest{ProjectId: "  "},
		&grpc.UnaryServerInfo{FullMethod: projectGet}, reached(&hit))
	if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "invalid project id '  '" {
		t.Fatalf("ответ %v на пробельный идентификатор, ожидался InvalidArgument с текстом судьи", err)
	}
	if hit {
		t.Fatal("обработчик позван после отказа формы на пробельном идентификаторе")
	}
}

func TestFormUnary_SilentWhereTheDoorWouldNotAsk(t *testing.T) {
	for name, tc := range map[string]struct {
		ctx    context.Context
		method string
		req    any
	}{
		"безымянный вызывающий": {context.Background(), projectGet, &iamv1.GetProjectRequest{ProjectId: "qqq-not-a-project"}},
		"пустое поле":           {tenantCtx("usr00000000000000001"), projectGet, &iamv1.GetProjectRequest{ProjectId: ""}},
		"глагол вне класса": {tenantCtx("usr00000000000000001"), "/kaname.cloud.iam.v1.ProjectService/List",
			&iamv1.ListProjectsRequest{}},
		"вопрос о правах без области": {tenantCtx("usr00000000000000001"), "/kaname.cloud.iam.v1.AuthorizeService/BatchCheck",
			&iamv1.BatchAuthorizeCheckRequest{}},
	} {
		t.Run(name, func(t *testing.T) {
			judge := &formJudge{known: allKinds()}
			hit := false
			if _, err := formLink(t, judge)(tc.ctx, tc.req, &grpc.UnaryServerInfo{FullMethod: tc.method}, reached(&hit)); err != nil {
				t.Fatalf("звено ответило там, где молчит: %v", err)
			}
			if !hit {
				t.Fatalf("обработчик не позван (судья спрошен %v) — звено обязано пропустить запрос к двери", judge.judged)
			}
		})
	}
}

func TestFormUnary_RefusesToAssembleWithoutAJudgeForEveryKind(t *testing.T) {
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: &grantStore{}})
	if err != nil {
		t.Fatalf("дверь не собралась: %v", err)
	}
	if _, err := door.FormUnary(nil); err == nil {
		t.Fatal("звено собралось без судьи — оно не проверяло бы ничего, оставаясь на вид провязанным")
	}
	// Один факт против близнеца: судья не знает ровно одного вида класса.
	known := allKinds()
	delete(known, "iam_group")
	_, err = door.FormUnary(&formJudge{known: known})
	if err == nil || !strings.Contains(err.Error(), `"iam_group"`) {
		t.Fatalf("звено собралось при судье, не знающем вида iam_group, либо не назвало его: %v", err)
	}
	if _, err := door.FormUnary(&formJudge{known: allKinds()}); err != nil {
		t.Fatalf("близнец со всеми видами не собрался: %v", err)
	}
}

// Пробельная область у вопроса о правах — неверная форма, как у любого другого
// глагола класса: названный вызывающий получает отказ судьи, обработчик не
// позван. Близнец — пустая `scope_id` той же цепочки — молчит (кейс «вопрос о
// правах без области» выше): пустое поле есть отсутствие, и вопрос уходит
// своему решателю.
func TestFormUnary_BlankScopeOfABatchQuestionIsMalformedNotAbsent(t *testing.T) {
	judge := &formJudge{known: allKinds()}
	hit := false
	_, err := formLink(t, judge)(tenantCtx("usr00000000000000001"), &iamv1.BatchAuthorizeCheckRequest{ScopeId: "  "},
		&grpc.UnaryServerInfo{FullMethod: batchQuestion}, reached(&hit))
	if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "invalid project id '  '" {
		t.Fatalf("ответ %v на пробельную область вопроса о правах, ожидался InvalidArgument с текстом судьи "+
			"(судья спрошен %v)", err, judge.judged)
	}
	if hit {
		t.Fatal("обработчик позван после отказа формы на пробельной области")
	}
}

// Звено формы и дверь одного пакета понимают «значение отсутствует» ОДИНАКОВО.
//
// Проба судит РАЗНИЦУ двух потребителей, а не каждого порознь: на одном и том
// же входе звено считает идентификатор отсутствующим (пропускает, судью не
// спросив) ровно тогда, когда дверь отдаёт вопрос его решателю (обработчик
// достигнут при пустой модели прав). Законные близнецы — пустая строка (оба
// «отсутствует») и годная форма (оба «назван»); входы с пробелами — предмет.
func TestOwnDoor_FormLinkAndDoorShareOneDefinitionOfAbsence(t *testing.T) {
	inputs := []string{"", "  ", "\t", " prj00000000000notfnd", "prj00000000000notfnd"}
	for _, scope := range inputs {
		req := &iamv1.BatchAuthorizeCheckRequest{ScopeId: scope}

		judge := &formJudge{known: allKinds()}
		formHit := false
		_, _ = formLink(t, judge)(tenantCtx(ownerUser), req, &grpc.UnaryServerInfo{FullMethod: batchQuestion},
			reached(&formHit))
		formAbsent := formHit && len(judge.judged) == 0

		store := &grantStore{allow: map[string]bool{}}
		doorHit := false
		_, _ = doorUnder(t, store)(tenantCtx(ownerUser), req, &grpc.UnaryServerInfo{FullMethod: batchQuestion},
			reached(&doorHit))
		doorAbsent := doorHit && len(store.asked) == 0

		if formAbsent != doorAbsent {
			t.Errorf("scope_id %q: звено формы считает область отсутствующей=%v, дверь=%v — "+
				"два определения отсутствия в одном пакете (судья спрошен %v, модель спрошена %v)",
				scope, formAbsent, doorAbsent, judge.judged, store.asked)
		}
	}
	t.Logf("осмотрено входов: %d", len(inputs))
}
