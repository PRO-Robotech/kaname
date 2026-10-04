// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package servicemanifest

// seed_form_test.go — форму раздела `seed` манифеста СЛУЖБЫ судит тот же судья,
// что у модулей (приёмка MRW-1, сценарии MRW-06…MRW-10).
//
// Дом каждого сценария — ДОКУМЕНТ В ПАМЯТИ: встроенный манифест, у которого один
// названный факт изменён разбором YAML, а не второй файл в дереве. Каждое
// отрицание стоит рядом со своим положительным близнецом — иначе оно зеленело
// бы на судье, отвергающем всё.
//
// MRW-09 и MRW-10 держит ОСНАСТКА ДЕРЕВА, а не старт службы (Р3): без внесённого
// канона судья «о существовании отношения не утверждает ничего», и оракул здесь —
// факт дома, взятый у той же оснастки (`manifestoracle.Canon`).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifestoracle"
)

// seedDocument — встроенный манифест как дерево YAML, к которому проба
// применяет ОДНУ правку и отдаёт обратно байтами.
func seedDocument(t *testing.T, edit func(seed map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(Raw(), &doc); err != nil {
		t.Fatalf("встроенный манифест не разобран как YAML: %v", err)
	}
	seed, ok := doc["seed"].(map[string]any)
	if !ok {
		t.Fatalf("раздел `seed` у манифеста службы не объявлен — сценарии о его форме беспредметны (Р1)")
	}
	edit(seed)
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("документ пробы не собран: %v", err)
	}
	return out
}

func firstBinding(t *testing.T, seed map[string]any) map[string]any {
	t.Helper()
	bindings, ok := seed["accessBindings"].([]any)
	if !ok || len(bindings) == 0 {
		t.Fatal("манифест службы не объявляет ни одной выдачи — править нечего")
	}
	b, ok := bindings[0].(map[string]any)
	if !ok {
		t.Fatal("первая выдача не отображение")
	}
	return b
}

func canonOracle(t *testing.T) manifest.LoadOption {
	t.Helper()
	oracle, err := manifestoracle.Canon()
	if err != nil {
		t.Fatalf("канон модели прав не разобран: %v — проверка НЕ ИСПОЛНЯЛАСЬ", err)
	}
	return manifest.WithRelationOracle(oracle)
}

// TestMRW06_GroupWithoutAGrantIsRefusedByTheForm — группа без выдачи: находка
// `ErrGroupNeverGranted` с путём `seed.groups[0]` и номером строки.
func TestMRW06_GroupWithoutAGrantIsRefusedByTheForm(t *testing.T) {
	doc := seedDocument(t, func(seed map[string]any) { delete(seed, "accessBindings") })
	_, err := manifest.Load(doc)
	if !errors.Is(err, manifest.ErrGroupNeverGranted) {
		t.Fatalf("группа без выдачи принята судьёй формы: %v", err)
	}
	if want := "seed.groups[0]"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("находка не называет путь %q: %v", want, err)
	}
	if !strings.Contains(err.Error(), "line ") && !strings.Contains(err.Error(), "строк") {
		t.Fatalf("находка не называет номер строки документа: %v", err)
	}
	t.Logf("находка: %v", err)
}

// TestMRW07_GroupWithItsGrantIsAccepted — положительный близнец MRW-06: тот же
// документ с выдачей, находок ноль.
func TestMRW07_GroupWithItsGrantIsAccepted(t *testing.T) {
	m, err := manifest.Load(seedDocument(t, func(map[string]any) {}))
	if err != nil {
		t.Fatalf("манифест службы отвергнут судьёй формы: %v", err)
	}
	if m.Seed == nil || len(m.Seed.Groups) != 1 || len(m.Seed.AccessBindings) != 1 {
		t.Fatalf("манифест службы объявляет не одну группу и не одну выдачу (Р1): %+v", m.Seed)
	}
	if len(m.Seed.ServiceAccounts) != 0 || len(m.Seed.Joins) != 0 {
		t.Fatalf("манифест службы объявляет личности либо вступления — своей служебной записи у службы не бывает (Р1)")
	}
	t.Logf("перепись связности: %s", m.Linkage())
}

// TestMRW08_AnchorOutsideTheClusterSingletonIsRefused — обе стороны оси якоря.
func TestMRW08_AnchorOutsideTheClusterSingletonIsRefused(t *testing.T) {
	t.Run("iam.account — находка ErrBindingAnchor", func(t *testing.T) {
		doc := seedDocument(t, func(seed map[string]any) { firstBinding(t, seed)["scopeType"] = "iam.account" })
		_, err := manifest.Load(doc)
		if !errors.Is(err, manifest.ErrBindingAnchor) {
			t.Fatalf("якорь вне кластерного singleton'а принят: %v", err)
		}
		if !strings.Contains(err.Error(), "seed.accessBindings[0]") {
			t.Fatalf("находка не называет путь seed.accessBindings[0]: %v", err)
		}
	})
	t.Run("iam.cluster — находок нет", func(t *testing.T) {
		doc := seedDocument(t, func(seed map[string]any) { firstBinding(t, seed)["scopeType"] = "iam.cluster" })
		if _, err := manifest.Load(doc); err != nil {
			t.Fatalf("якорь кластера отвергнут: %v", err)
		}
	})
}

// TestMRW09_RelationOutsideTheCanonIsRefusedByTheTreeJudge — с внесённым каноном
// отношение вне канона даёт `ErrRelationNotDeclared`; `fga_writer` принимается;
// без оракула (путь старта) тот же документ отказа НЕ производит.
func TestMRW09_RelationOutsideTheCanonIsRefusedByTheTreeJudge(t *testing.T) {
	outside := seedDocument(t, func(seed map[string]any) { firstBinding(t, seed)["grantedRelation"] = "no_such_relation" })

	t.Run("вне канона, с оракулом — находка", func(t *testing.T) {
		_, err := manifest.Load(outside, canonOracle(t))
		if !errors.Is(err, manifest.ErrRelationNotDeclared) {
			t.Fatalf("отношение вне канона принято: %v", err)
		}
	})
	t.Run("fga_writer, с оракулом — находок нет", func(t *testing.T) {
		if _, err := manifest.Load(seedDocument(t, func(map[string]any) {}), canonOracle(t)); err != nil {
			t.Fatalf("объявленное отношение отвергнуто: %v", err)
		}
	})
	t.Run("вне канона, без оракула — отказ не производится (путь старта)", func(t *testing.T) {
		if _, err := manifest.Load(outside); err != nil {
			t.Fatalf("без оракула судья утверждает о существовании отношения: %v", err)
		}
	})
}

// TestMRW10_RecipientKindTheRelationDoesNotAdmitIsRefused — группа на
// `system_viewer` (канон принимает `user` и `service_account`) отвергается с
// перечнем принимаемых видов; та же группа на `fga_writer` принимается.
func TestMRW10_RecipientKindTheRelationDoesNotAdmitIsRefused(t *testing.T) {
	viewer := seedDocument(t, func(seed map[string]any) { firstBinding(t, seed)["grantedRelation"] = "system_viewer" })

	t.Run("system_viewer, с оракулом — ErrRelationRecipientKind", func(t *testing.T) {
		_, err := manifest.Load(viewer, canonOracle(t))
		if !errors.Is(err, manifest.ErrRelationRecipientKind) {
			t.Fatalf("получатель, которого отношение не принимает, принят: %v", err)
		}
		if !strings.Contains(err.Error(), "service_account") {
			t.Fatalf("находка не называет принимаемые виды: %v", err)
		}
	})
	t.Run("fga_writer, с оракулом — принимается", func(t *testing.T) {
		if _, err := manifest.Load(seedDocument(t, func(map[string]any) {}), canonOracle(t)); err != nil {
			t.Fatalf("группа на fga_writer отвергнута: %v", err)
		}
	})
	t.Run("system_viewer, без оракула — отказ не производится (путь старта)", func(t *testing.T) {
		if _, err := manifest.Load(viewer); err != nil {
			t.Fatalf("без оракула судья утверждает о виде получателя: %v", err)
		}
	})
}

// serviceDocument — встроенный манифест как дерево YAML с ОДНОЙ правкой
// верхнего уровня (раздел `notifications` лежит рядом с `seed`, а не внутри).
func serviceDocument(t *testing.T, edit func(doc map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(Raw(), &doc); err != nil {
		t.Fatalf("встроенный манифест не разобран как YAML: %v", err)
	}
	edit(doc)
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("документ пробы не собран: %v", err)
	}
	return out
}

// tupleCall — записанный вызов порта: служебный кортеж, который применитель
// отдал хранилищу.
type tupleCall struct{ user, relation, object string }

// tupleRecorder — порт хранилища, записывающий служебные кортежи и молча
// соглашающийся со всем остальным: предмет пробы — только строка
// `notifications`, посев группы в ней не участвует.
type tupleRecorder struct {
	tuples []tupleCall
	// grants — записи выдачи пространства, которые посев попросил завести.
	grants []string
}

func (r *tupleRecorder) UpsertServiceAccount(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (r *tupleRecorder) UpsertGroup(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (r *tupleRecorder) JoinGroup(context.Context, string, string, string, string) (bool, error) {
	return true, nil
}
func (r *tupleRecorder) GrantRelation(context.Context, moduleseed.Subject, string, string, string) (bool, error) {
	return true, nil
}
func (r *tupleRecorder) GrantRole(context.Context, moduleseed.Subject, string, string, string) (bool, error) {
	return true, nil
}
func (r *tupleRecorder) WriteServiceTuple(_ context.Context, tu moduleseed.ServiceTuple) (bool, error) {
	r.tuples = append(r.tuples, tupleCall{user: tu.User(), relation: tu.Relation(), object: tu.Object()})
	return true, nil
}

func (r *tupleRecorder) EnsureNotificationGrant(_ context.Context, namespace string) (bool, error) {
	r.grants = append(r.grants, namespace)
	return true, nil
}

type recorderTx struct{ w *tupleRecorder }

func (tx recorderTx) RunInWriteTx(ctx context.Context, fn func(context.Context, moduleseed.Writer) error) error {
	return fn(ctx, tx.w)
}

// TestNTF1F21_AccessServiceNotificationsLine — исключение службы доступа (Р3):
// её манифест несёт только `readers: [notify]` без `namespace`.
//
// (а) принят, и применитель заводит РОВНО `service:notify reader
// notification_feed:kaname` — ни одного кортежа с субъектом `service:kaname` и
// объектом `notification_namespace:kaname`; (б) с `namespace` — находка «у
// службы доступа служебного принципала нет (MRW-1 Р1)», ни одного кортежа.
// Близнец формы — тот же документ, судимый как манифест МОДУЛЯ: без `namespace`
// он отвергается, то есть исключение даёт именно разряд службы, а не форма.
func TestNTF1F21_AccessServiceNotificationsLine(t *testing.T) {
	readersOnly := serviceDocument(t, func(doc map[string]any) {
		doc["notifications"] = map[string]any{"readers": []any{"notify"}}
	})
	withNamespace := serviceDocument(t, func(doc map[string]any) {
		doc["notifications"] = map[string]any{"namespace": "kaname", "readers": []any{"notify"}}
	})

	t.Run("(а) только readers — принят, один кортеж reader на ленту kaname", func(t *testing.T) {
		m, err := loadDocument(readersOnly)
		if err != nil {
			t.Fatalf("строка службы доступа `notifications: {readers: [notify]}` отвергнута: %v", err)
		}
		rec := &tupleRecorder{}
		census, err := moduleseed.NewApplier(recorderTx{w: rec}).Apply(context.Background(), m, nil)
		if err != nil {
			t.Fatalf("применитель отверг принятую строку: %v", err)
		}
		t.Logf("перепись: %s", census)
		want := tupleCall{user: "service:notify", relation: "reader", object: "notification_feed:kaname"}
		if len(rec.tuples) != 1 || rec.tuples[0] != want {
			t.Fatalf("заведены кортежи %+v, ожидался ровно %+v", rec.tuples, want)
		}
		for _, tu := range rec.tuples {
			if tu.user == "service:kaname" || strings.HasPrefix(tu.object, "notification_namespace:") {
				t.Fatalf("служба доступа получила служебного принципала либо пространство: %+v", tu)
			}
		}
		if len(rec.grants) != 0 {
			t.Fatalf("службе доступа заведена запись выдачи пространства: %v", rec.grants)
		}
	})

	t.Run("(б) с namespace — находка, кортежей ноль", func(t *testing.T) {
		_, err := loadDocument(withNamespace)
		if !errors.Is(err, manifest.ErrAccessServiceHasNoServicePrincipal) {
			t.Fatalf("строка службы доступа с namespace принята: %v", err)
		}
		if !strings.Contains(err.Error(), "у службы доступа служебного принципала нет (MRW-1 Р1)") {
			t.Fatalf("находка не называет причину словами приёмки: %v", err)
		}

		// Последний рубеж — применитель: разобранная (а) с namespace, дописанным
		// в обход разбора, свой манифест не применяется.
		m, lerr := loadDocument(readersOnly)
		if lerr != nil {
			t.Fatalf("предпосылка не создана — (а) не разобрана: %v", lerr)
		}
		m.Notifications.Namespace = "kaname"
		rec := &tupleRecorder{}
		_, aerr := moduleseed.NewApplier(recorderTx{w: rec}).Apply(context.Background(), m, nil)
		if !errors.Is(aerr, manifest.ErrAccessServiceHasNoServicePrincipal) {
			t.Fatalf("применитель своего манифеста принял namespace: %v", aerr)
		}
		if len(rec.tuples) != 0 {
			t.Fatalf("при отказе заведены кортежи: %+v", rec.tuples)
		}
	})

	t.Run("близнец: та же форма без namespace в манифесте МОДУЛЯ — находка", func(t *testing.T) {
		if _, err := manifest.Load(readersOnly); !errors.Is(err, manifest.ErrNotificationNamespaceForeign) {
			t.Fatalf("манифест модуля без namespace принят — исключение дала форма, а не разряд: %v", err)
		}
	})
}
