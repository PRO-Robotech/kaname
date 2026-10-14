// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// system_class_publication_integration_test.go — публикация владельца
// становится выдачей классу `anonymous` (приёмка
// anonymous-and-authenticated-are-subject-classes.md, отпечаток fa4ff26f…bb21757e,
// SC-12 и SC-13; задача PRO-Robotech/kaname#829).
//
// Вход соседа не меняется: публикация приходит парой `user:*` + `v_get` через
// `RegisterResource`. Утверждается то, что из него выводится: вопрос от
// `system_class:anonymous` и от вошедшего читает объект, вопрос анонима о чтении
// справочников — нет; снятие публикации закрывает чтение обоим.
package internal_iam_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

const scPublicRepo = "reg53eeeg3578y4ah0q9/team/app"

func scAllowed(t *testing.T, a *relverdict.Asker, subject, objType, objID, relation string) bool {
	t.Helper()
	ok, err := a.Allowed(context.Background(), subject, objType, objID, relation, nil)
	require.NoErrorf(t, err, "вопрос %s %s %s:%s", subject, relation, objType, objID)
	return ok
}

// scPoll — опрос раз в 200 мс до 30 с (окно материализации SC-13).
func scPoll(t *testing.T, a *relverdict.Asker, subject, objType, objID, relation string, want bool, why string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if scAllowed(t, a, subject, objType, objID, relation) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %s %s %s:%s за 30 с не дошёл до %v", why, subject, relation, objType, objID, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// SC-12 и SC-13 — публикация владельца даёт чтение анониму и вошедшему, и
// ничего сверх чтения объекта; снятие публикации закрывает обоим.
func TestSystemClass_SC12_SC13_PublicationIsAGrantToAnonymous(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	uc, probe := newRegisterUC(t)
	a := relverdict.NewAsker(probe.pool)
	const person = "user:usr0000000000000sc12"
	obj := "registry_repository:" + scPublicRepo
	base := time.Now()

	// Положительный контроль: системная выдача чтения справочников действует
	// для вошедшего (Р8, SC-40) — без неё «нет» анониму ниже ничего не различало бы.
	require.True(t, scAllowed(t, a, person, "cluster", "cluster_kacho_root", "viewer"),
		"SC-12 контроль: вошедший читает справочники")
	require.False(t, scAllowed(t, a, "system_class:anonymous", "registry_repository", scPublicRepo, "v_get"),
		"SC-12 предпосылка: до публикации аноним не читает")

	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "user:*", Relation: "v_get", Object: obj, SourceVersion: timestamppb.New(base),
	}), "SC-12 Дано: публикация входом соседа")

	assert.True(t, scAllowed(t, a, "system_class:anonymous", "registry_repository", scPublicRepo, "v_get"), "SC-12: аноним читает")
	assert.True(t, scAllowed(t, a, person, "registry_repository", scPublicRepo, "v_get"), "SC-12: вошедший читает")
	assert.False(t, scAllowed(t, a, "system_class:anonymous", "cluster", "cluster_kacho_root", "viewer"),
		"SC-12: публикация не даёт анониму чтения справочников")

	require.NoError(t, uc.Unregister(ctx, &iamv1.UnregisterResourceRequest{
		SubjectId: "user:*", Relation: "v_get", Object: obj, SourceVersion: timestamppb.New(base.Add(time.Second)),
	}), "SC-13: снятие публикации")
	scPoll(t, a, "system_class:anonymous", "registry_repository", scPublicRepo, "v_get", false, "SC-13: аноним")
	scPoll(t, a, person, "registry_repository", scPublicRepo, "v_get", false, "SC-13: вошедший")
}
