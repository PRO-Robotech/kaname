// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// set_public_read_publication_integration_test.go — публикация для анонимного
// чтения: свой метод и своя версия, применение только к текущему воплощению
// объекта (приёмка NTF-3, kacho#2918, сценарии NTF3-186, NTF3-189 (сторона
// службы доступа); Р30 «Публикация для анонимного чтения», «Производитель
// поколения — счётчик объекта модуля», редакции 40–41).
//
// # Что судится
//
// Порядок публикации производит метод `InternalIAMService/SetPublicReadPublication`
// с версией публикации `publication_version`; регистрация и снятие объекта
// публикацию не несут. Публикация ложится только на текущее воплощение объекта:
// при голове-надгробии — если `object_generation` строго новее надгробия, при
// живой голове — если не старше поколения регистрации, начавшей воплощение,
// головы нет — применяется. Снятие объекта уносит кортеж публикации и строку
// `public_read_publication`; регистрация, начинающая воплощение, снимает
// публикацию прежнего воплощения.
//
// # Как проба зовёт метод
//
// Сообщение запроса берётся из реестра типов по полному имени, метод
// обработчика — по имени: проба собирается на дереве без метода и падает там
// текстом «метода нет», а не ошибкой компиляции.
//
// Пропускается под `go test -short`.
package internal_iam_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Версии публикации t1 < t2 < t3.
var (
	pubT1 = time.Date(2026, 10, 7, 10, 0, 1, 0, time.UTC)
	pubT2 = time.Date(2026, 10, 7, 10, 0, 2, 0, time.UTC)
	pubT3 = time.Date(2026, 10, 7, 10, 0, 3, 0, time.UTC)
)

// pubReq — запрос публикации по полным именам контракта. Нулевая версия и нулевое
// поколение — поле не задано.
func pubReq(t *testing.T, object string, published bool, version time.Time, objectGeneration int64) proto.Message {
	t.Helper()
	mt, err := protoregistry.GlobalTypes.FindMessageByName("kaname.cloud.iam.v1.SetPublicReadPublicationRequest")
	if err != nil {
		t.Fatalf("сообщения SetPublicReadPublicationRequest нет — порядок публикации производить нечем "+
			"(Р30 «Публикация для анонимного чтения», NTF3-186): %v", err)
	}
	m := mt.New()
	set := func(name protoreflect.Name, v protoreflect.Value) {
		fd := m.Descriptor().Fields().ByName(name)
		if fd == nil {
			t.Fatalf("SetPublicReadPublicationRequest: поля %q нет", name)
		}
		m.Set(fd, v)
	}
	set("object", protoreflect.ValueOfString(object))
	set("published", protoreflect.ValueOfBool(published))
	if !version.IsZero() {
		set("publication_version", protoreflect.ValueOfMessage(timestamppb.New(version).ProtoReflect()))
	}
	if objectGeneration != 0 {
		set("object_generation", protoreflect.ValueOfInt64(objectGeneration))
	}
	return m.Interface()
}

// publish зовёт метод публикации обработчика.
func (e *eventHarness) publish(t *testing.T, req proto.Message) error {
	t.Helper()
	meth := reflect.ValueOf(e.h).MethodByName("SetPublicReadPublication")
	if !meth.IsValid() {
		t.Fatal("у обработчика внутренней службы нет метода SetPublicReadPublication (NTF3-186)")
	}
	out := meth.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(req)})
	if errv := out[1]; !errv.IsNil() {
		return errv.Interface().(error)
	}
	return nil
}

// publication — строка публикации репозитория: открыт ли и версия.
func (e *eventHarness) publication(t *testing.T, name string) (published bool, version time.Time, present bool) {
	t.Helper()
	err := e.pool.QueryRow(context.Background(),
		`SELECT published, source_version FROM kaname.public_read_publication
		  WHERE object_type = $1 AND object_id = $2`, evRepoType, "reg-1/"+name).Scan(&published, &version)
	if err == pgx.ErrNoRows {
		return false, time.Time{}, false
	}
	require.NoError(t, err)
	return published, version.UTC(), true
}

// publicFact — версия кортежа `user:* v_get` на репозитории; ok=false — кортежа нет.
func (e *eventHarness) publicFact(t *testing.T, name string) (time.Time, bool) {
	t.Helper()
	var v time.Time
	err := e.pool.QueryRow(context.Background(),
		`SELECT source_version FROM kaname.relation_fact
		  WHERE object_type = $1 AND object_id = $2 AND relation = 'v_get' AND subject = 'user:*'`,
		evRepoType, "reg-1/"+name).Scan(&v)
	if err == pgx.ErrNoRows {
		return time.Time{}, false
	}
	require.NoError(t, err)
	return v.UTC(), true
}

func (e *eventHarness) requirePublished(t *testing.T, name string, wantPublished bool, wantVersion time.Time, why string) {
	t.Helper()
	published, version, ok := e.publication(t, name)
	require.True(t, ok, "%s: строки публикации reg-1/%s нет", why, name)
	require.Equal(t, wantPublished, published, "%s: published", why)
	require.True(t, wantVersion.Equal(version), "%s: версия публикации %s, ожидается %s", why, version, wantVersion)
	fv, fok := e.publicFact(t, name)
	require.Equal(t, wantPublished, fok, "%s: кортеж user:* v_get", why)
	if wantPublished {
		require.True(t, wantVersion.Equal(fv), "%s: версия кортежа %s, ожидается %s", why, fv, wantVersion)
	}
}

func (e *eventHarness) requireNoPublication(t *testing.T, name, why string) {
	t.Helper()
	_, _, ok := e.publication(t, name)
	require.False(t, ok, "%s: строка публикации reg-1/%s есть", why, name)
	_, fok := e.publicFact(t, name)
	require.False(t, fok, "%s: кортеж user:* v_get на reg-1/%s есть", why, name)
}

func repo(name string) string { return evRepoType + ":reg-1/" + name }

// pubState — состояние NTF3-186 «Дано»: репозиторий зарегистрирован поколением 1
// набором NTF3-185 (а).
func pubState(t *testing.T) *eventHarness {
	t.Helper()
	e := newEventHarness(t)
	require.NoError(t, e.register(t, evReg(t, "pub", []evTuple{evParent, evOwner}, 1)))
	return e
}

// TestSetPublicReadPublication_NTF3_186a_OpensWithItsVersion — публикация t1:
// кортеж `user:* v_get` с версией t1, строка публикации `true`, t1; голова не
// изменена.
func TestSetPublicReadPublication_NTF3_186a_OpensWithItsVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := pubState(t)
	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT1, 1)))
	e.requirePublished(t, "pub", true, pubT1, "публикация t1")
	e.requireHead(t, "pub", 1, false, "публикация головы не пишет")
}

// TestSetPublicReadPublication_NTF3_186b_LateOpenDoesNotOverturnTheClose —
// закрытие t2, затем запоздалое открытие t1: строка (false, t2), кортежа нет.
// Близнец по одному факту — открытие t3: кортеж есть с версией t3.
func TestSetPublicReadPublication_NTF3_186b_LateOpenDoesNotOverturnTheClose(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := pubState(t)
	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT1, 1)))
	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), false, pubT2, 1)))
	e.requirePublished(t, "pub", false, pubT2, "закрытие t2")
	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT1, 1)), "запоздалое открытие — успех вызова")
	e.requirePublished(t, "pub", false, pubT2, "открытие t1 не новее закрытия t2")

	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT3, 1)))
	e.requirePublished(t, "pub", true, pubT3, "близнец: открытие t3")
}

// TestSetPublicReadPublication_NTF3_186c_WithdrawnIncarnationIsNotPublished —
// снятие объекта поколением 2 уносит кортеж публикации и строку; публикация
// воплощения 1 после снятия — REJECTED_STALE, ответ успех. Близнец по одному
// факту — без снятия объекта: публикация t3 применена.
func TestSetPublicReadPublication_NTF3_186c_WithdrawnIncarnationIsNotPublished(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	t.Run("снятие", func(t *testing.T) {
		e := pubState(t)
		require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT1, 1)))
		require.NoError(t, e.unregister(t, evUnreg("pub", 2)))
		e.requireNoPublication(t, "pub", "снятие объекта уносит публикацию")
		require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT3, 1)), "устаревшая публикация — успех вызова")
		e.requireNoPublication(t, "pub", "воплощение 1 не новее надгробия 2")
		e.requireHead(t, "pub", 2, true, "надгробие не тронуто публикацией")
	})
	t.Run("близнец без снятия", func(t *testing.T) {
		e := pubState(t)
		require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT1, 1)))
		require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT3, 1)))
		e.requirePublished(t, "pub", true, pubT3, "близнец: без снятия объекта")
	})
}

// TestSetPublicReadPublication_NTF3_186d_RequestIsValidatedAndOwned — версия не
// задана, тип не допускает публикации, вызов от модуля storage, поколение
// воплощения не задано: отказ с полем и текстом, публикация не изменена.
// Близнец по одному факту — тот же вызов от модуля registry: применён.
func TestSetPublicReadPublication_NTF3_186d_RequestIsValidatedAndOwned(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := pubState(t)
	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT1, 1)))

	for _, c := range []struct {
		why    string
		domain string
		req    proto.Message
		code   codes.Code
		field  string
		desc   string
	}{
		{"версия не задана", "registry", pubReq(t, repo("pub"), false, time.Time{}, 1),
			codes.InvalidArgument, "publication_version", "required"},
		{"тип не допускает", "registry", pubReq(t, "storage_volume:vol-41", true, pubT2, 1),
			codes.InvalidArgument, "object", "type storage_volume does not admit public read"},
		{"чужой модуль", "storage", pubReq(t, repo("pub"), false, pubT2, 1),
			codes.PermissionDenied, "", ""},
		{"поколение не задано", "registry", pubReq(t, repo("pub"), false, pubT2, 0),
			codes.InvalidArgument, "object_generation", "required"},
	} {
		t.Run(c.why, func(t *testing.T) {
			e.gate.domain = c.domain
			defer func() { e.gate.domain = "registry" }()
			err := e.publish(t, c.req)
			require.Error(t, err, "%s: вызов принят", c.why)
			require.Equal(t, c.code, status.Code(err), "%s: %v", c.why, err)
			if c.code == codes.InvalidArgument {
				field, desc := badRequestField(err)
				require.Equal(t, c.field, field, "%s: поле отказа", c.why)
				require.Equal(t, c.desc, desc, "%s: описание отказа", c.why)
			} else {
				require.Equal(t, "permission denied", status.Convert(err).Message(), "%s: текст отказа", c.why)
				require.Equal(t, "AUTHZ_DENIED", errorInfoReason(err), "%s: машинный признак отказа", c.why)
			}
			e.requirePublished(t, "pub", true, pubT1, c.why+": публикация не изменена")
		})
	}

	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), false, pubT2, 1)))
	e.requirePublished(t, "pub", false, pubT2, "близнец: вызов от модуля registry")
}

// errorInfoReason — машинный признак отказа.
func errorInfoReason(err error) string {
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei.GetReason()
		}
	}
	return ""
}

// TestSetPublicReadPublication_NTF3_186e_PublicationBeforeItsRegistration —
// объекта в службе доступа нет: публикация применена; регистрация поколения 1
// публикацию с поколением воплощения 1 не снимает. Близнец по одному факту —
// объект прежде зарегистрирован поколением 1 и снят поколением 2: та же
// публикация — REJECTED_STALE.
func TestSetPublicReadPublication_NTF3_186e_PublicationBeforeItsRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	t.Run("головы нет", func(t *testing.T) {
		e := newEventHarness(t)
		require.NoError(t, e.publish(t, pubReq(t, repo("early"), true, pubT1, 1)))
		e.requirePublished(t, "early", true, pubT1, "публикация раньше регистрации")
		require.NoError(t, e.register(t, evReg(t, "early", []evTuple{evParent}, 1)))
		e.requireHead(t, "early", 1, false, "регистрация поколения 1")
		e.requirePublished(t, "early", true, pubT1, "CREATED поколения 1 не снимает публикацию воплощения 1")
	})
	t.Run("близнец: надгробие", func(t *testing.T) {
		e := newEventHarness(t)
		require.NoError(t, e.register(t, evReg(t, "early", []evTuple{evParent}, 1)))
		require.NoError(t, e.unregister(t, evUnreg("early", 2)))
		require.NoError(t, e.publish(t, pubReq(t, repo("early"), true, pubT1, 1)))
		e.requireNoPublication(t, "early", "публикация воплощения 1 при надгробии 2")
	})
}

// TestSetPublicReadPublication_NewIncarnationDoesNotInheritAnOlderPublication —
// публикация воплощения 1 применена при отсутствии головы; регистрация поколения
// 3 начинает воплощение и снимает публикацию с поколением воплощения меньше
// своего. Близнец по одному факту — регистрация поколения 1: публикация на месте
// (подсценарий «головы нет» NTF3-186 (д)).
func TestSetPublicReadPublication_NewIncarnationDoesNotInheritAnOlderPublication(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	require.NoError(t, e.publish(t, pubReq(t, repo("old"), true, pubT1, 1)))
	e.requirePublished(t, "old", true, pubT1, "публикация воплощения 1 без головы")
	require.NoError(t, e.register(t, evReg(t, "old", []evTuple{evParent}, 3)))
	e.requireHead(t, "old", 3, false, "регистрация поколения 3")
	e.requireNoPublication(t, "old", "воплощение 3 не наследует публикацию воплощения 1")
}

// TestRegisterResource_NTF3_189_ObjectRecreatedOverTheTombstone — сторона службы
// доступа: объект, созданный с id снятого, продолжает его поколения и ложится
// поверх надгробия; кортежей прежнего воплощения на нём нет; запоздалые
// регистрация и публикация прежнего воплощения — REJECTED_STALE. Близнец по
// одному факту — регистрация поколения gT+2: применена.
func TestRegisterResource_NTF3_189_ObjectRecreatedOverTheTombstone(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	e := newEventHarness(t)
	const g1, gT = 1, 2
	usrA := evTuple{"user:usr-A", "owner"}
	usrB := evTuple{"user:usr-B", "owner"}

	require.NoError(t, e.register(t, evReg(t, "pub", []evTuple{evParent, usrA}, g1)))
	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT1, g1)))
	require.NoError(t, e.unregister(t, evUnreg("pub", gT)))
	e.requireHead(t, "pub", gT, true, "надгробие gT")
	e.requireNoPublication(t, "pub", "снятие унесло публикацию")

	// (а) объект с тем же id — поколение gT+1.
	require.NoError(t, e.register(t, evReg(t, "pub", []evTuple{evParent, usrB}, gT+1)))
	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT2, gT+1)))
	e.requireHead(t, "pub", gT+1, false, "новое воплощение поверх надгробия")
	require.Equal(t, []string{keyOf(evParent), keyOf(usrB)}, factKeys(withoutPublic(e.facts(t, "pub"))),
		"кортежи нового воплощения: владение usr-B есть, usr-A нет")
	e.requirePublished(t, "pub", true, pubT2, "публикация нового воплощения")

	// (б) запоздалая доставка прежнего воплощения.
	require.NoError(t, e.register(t, evReg(t, "pub", []evTuple{evParent, usrA}, g1)))
	require.NoError(t, e.publish(t, pubReq(t, repo("pub"), true, pubT3, g1)))
	e.requireHead(t, "pub", gT+1, false, "запоздалая регистрация прежнего — REJECTED_STALE")
	require.Equal(t, []string{keyOf(evParent), keyOf(usrB)}, factKeys(withoutPublic(e.facts(t, "pub"))),
		"запоздалая регистрация прежнего: кортежа usr-A нет")
	e.requirePublished(t, "pub", true, pubT2, "запоздалая публикация прежнего воплощения не легла")

	require.NoError(t, e.register(t, evReg(t, "pub", []evTuple{evParent, usrB}, gT+2)))
	e.requireHead(t, "pub", gT+2, false, "близнец: поколение gT+2 применено")
}

// withoutPublic — кортежи без кортежа публикации.
func withoutPublic(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if k != "user:*#v_get" {
			out[k] = v
		}
	}
	return out
}
