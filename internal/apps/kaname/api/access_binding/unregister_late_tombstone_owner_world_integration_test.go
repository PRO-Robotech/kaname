// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_late_tombstone_owner_world_integration_test.go — запоздалое снятие
// регистрации не трогает владельца нового объекта (PRO-Robotech/kaname#969).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Ключ K зарегистрирован с владельцем usr-B (версия v1). Снятие K (версия v2)
// задержано в очереди потребителя. Тем временем тот же ключ зарегистрирован
// заново с владельцем usr-C (версии v3, v4). Задержанное снятие доходит последним.
// Оно снимает регистрацию, которой уже нет: строка зеркала новее надгробия и
// остаётся. Кортежи владельца обязаны вести себя так же — снятие версии v2
// снимает владельца v1 (usr-B) и не трогает владельца новой регистрации (usr-C).
//
// Красная сторона измерена пробой URG-30 приёмки kaname#963 и до правок kaname#963: снятие
// кортежей не знало версии регистрации и снимало все отношения объекта.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ИСХОД СУДИТ ДВЕРЬ РЕШЕНИЯ
//
// Владелец объекта читает его через отношение `owner`, из которого модель выводит
// все глаголы. Поэтому исход — `AuthorizeService.Check` (`v_get`): то значение,
// которое получает модуль. Строка зеркала судится отдельно — регистрация K после
// запоздалого снятия жива.
//
// Близнец отличается ОДНИМ фактом: снятие v2 доходит вовремя — до повторной
// регистрации — и снимает владельца usr-B.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Ключ K — реестр, которого мир П6 не регистрирует.
const lateK = "reg00000000000000007"

// registerKAs — регистрация K в prj-A с владельцем `owner`, у каждого намерения
// своя версия владельца.
func (w *urWorld) registerKAs(owner domain.UserID) {
	w.t.Helper()
	obj := pcrRegType + ":" + lateK
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: "project:" + string(w.prjA), Relation: "project", Object: obj},
		{SubjectId: "user:" + string(owner), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(w.prjA), string(w.accA)
		r.ParentChain = []string{"project:" + string(w.prjA), "account:" + string(w.accA)}
		r.SourceVersion = w.nextVersion()
		require.NoErrorf(w.t, w.reg.Register(w.ctx, r), "регистрация K (%s)", r.GetRelation())
	}
}

// unregisterKAt — снятие регистрации K владельцем с данной версией-надгробием.
func (w *urWorld) unregisterKAt(version *timestamppb.Timestamp) {
	w.t.Helper()
	require.NoError(w.t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId:     "project:" + string(w.prjA),
		Relation:      "project",
		Object:        pcrRegType + ":" + lateK,
		SourceVersion: version,
	}), "снятие регистрации K")
}

// kRegistered — есть ли строка зеркала K.
func (w *urWorld) kRegistered() bool {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_type = $1 AND object_id = $2`,
		pcrRegTgt, lateK).Scan(&n))
	return n > 0
}

// TestUnregister_LateTombstoneLeavesTheNewOwner — задержанное снятие v2,
// дошедшее после повторной регистрации v3/v4, снимает владельца usr-B и не
// трогает владельца usr-C.
func TestUnregister_LateTombstoneLeavesTheNewOwner(t *testing.T) {
	w := newURWorld(t)
	usrB, usrC := fmtSubject("user", string(w.usrB)), fmtSubject("user", string(w.usrC))
	w.registerKAs(w.usrB)
	w.pollAsk(usrB, "v_get", pcrRegType, lateK, true, "kaname#969 контроль фикстуры: владелец usr-B не читает K")
	stale := w.nextVersion() // v2: снятие задержано

	w.registerKAs(w.usrC)
	w.pollAsk(usrC, "v_get", pcrRegType, lateK, true, "kaname#969 контроль живости: новый владелец usr-C не читает K")
	w.unregisterKAt(stale)

	assert.True(t, w.kRegistered(), "kaname#969: запоздалое снятие сняло регистрацию новее себя")
	assert.True(t, w.ask(usrC, "v_get", pcrRegType, lateK),
		"kaname#969: запоздалое снятие сняло владельца новой регистрации — usr-C не читает свой объект")
	assert.False(t, w.ask(usrB, "v_get", pcrRegType, lateK),
		"kaname#969: владелец прежней регистрации usr-B читает K после снятия своей версии")
}

// TestUnregister_TimelyTombstoneRemovesTheOwner — близнец: снятие v2 доходит до
// повторной регистрации и снимает владельца usr-B; новый владелец usr-C читает K.
func TestUnregister_TimelyTombstoneRemovesTheOwner(t *testing.T) {
	w := newURWorld(t)
	usrB, usrC := fmtSubject("user", string(w.usrB)), fmtSubject("user", string(w.usrC))
	w.registerKAs(w.usrB)
	w.pollAsk(usrB, "v_get", pcrRegType, lateK, true, "kaname#969 контроль фикстуры: владелец usr-B не читает K")

	w.unregisterKAt(w.nextVersion())
	w.pollAsk(usrB, "v_get", pcrRegType, lateK, false, "kaname#969 близнец: своевременное снятие не сняло владельца usr-B")

	w.registerKAs(w.usrC)
	assert.True(t, w.ask(usrC, "v_get", pcrRegType, lateK), "kaname#969 близнец: новый владелец usr-C не читает K")
	assert.False(t, w.ask(usrB, "v_get", pcrRegType, lateK), "kaname#969 близнец: прежний владелец usr-B читает K")
}

// TestUnregister_DescendantNewerThanParentTombstoneGoesWhole — потомок, чья
// регистрация новее надгробия родителя, снимается вместе с родителем ЦЕЛИКОМ:
// регистрация потомка снимается безусловно (kaname#1002), и его кортежи — тоже,
// хотя записаны версией новее надгробия (kaname#969). Иначе владелец потомка
// сохранил бы доступ к объекту, регистрации которого уже нет.
func TestUnregister_DescendantNewerThanParentTombstoneGoesWhole(t *testing.T) {
	w := newURWorld(t)
	usrC := fmtSubject("user", string(w.usrC))
	parentTombstone := w.nextVersion()
	newer := timestamppb.New(w.ver.Add(time.Hour)) // версия регистрации потомка новее надгробия
	obj := pcrRepoType + ":" + pcrX + "/fresh"
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: pcrRegType + ":" + pcrX, Relation: "parent", Object: obj},
		{SubjectId: "user:" + string(w.usrC), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(w.prjA), string(w.accA)
		r.ParentChain = []string{pcrRegType + ":" + pcrX, "project:" + string(w.prjA), "account:" + string(w.accA)}
		r.SourceVersion = newer
		newer = timestamppb.New(newer.AsTime().Add(time.Second))
		require.NoErrorf(t, w.reg.Register(w.ctx, r), "регистрация потомка X/fresh (%s)", r.GetRelation())
	}
	w.pollAsk(usrC, "v_get", pcrRepoType, pcrX+"/fresh", true, "kaname#969 контроль фикстуры: владелец usr-C не читает X/fresh")

	require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + string(w.prjA), Relation: "project", Object: pcrRegType + ":" + pcrX,
		SourceVersion: parentTombstone,
	}), "снятие регистрации реестра X")

	var facts int
	require.NoError(t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.relation_fact WHERE object_type = $1 AND object_id = $2`,
		pcrRepoType, pcrX+"/fresh").Scan(&facts))
	assert.Zero(t, facts, "kaname#969: кортежи потомка новее надгробия родителя пережили снятие его регистрации")
	assert.False(t, w.ask(usrC, "v_get", pcrRepoType, pcrX+"/fresh"),
		"kaname#969: владелец снятого потомка usr-C читает X/fresh")
}
