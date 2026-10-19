// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// publication_anonymous_word_test.go — публикация объекта для чтения без входа
// принимает второе входное слово, класс `system_class:anonymous` (kaname#893,
// правило — corelib#116). Владелец ресурса, у которого плоскость данных уже
// спрашивает от класса, не обязан называть публикацию подстановкой `user:*`.
//
// Наблюдаемое на границе — код и текст отказа либо его отсутствие; на пути
// применения — что намерение ушло в порт публикации, а не голым кортежем в
// журнал, и что хранимая форма одна: принятое одним словом снимается другим.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRegisterResource_PublicationAcceptsTheAnonymousClass — граница
// `RegisterResource`/`UnregisterResource` (validateProxyTuple) принимает
// `system_class:anonymous` + `v_get` на репозитории реестра. Каждая строка
// отказа меняет против принятой ровно один факт и отвергается тем же
// `PermissionDenied "permission denied"`, что любой иной недопустимый кортеж.
func TestRegisterResource_PublicationAcceptsTheAnonymousClass(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, domain, subject, relation, object string
		refused                                 bool
	}{
		{"anonymous class publishes", "registry", "system_class:anonymous", "v_get", publicGrantObject, false},
		{"anonymous class, domain unknown", "", "system_class:anonymous", "v_get", publicGrantObject, false},
		{"twin: wildcard user still publishes", "registry", "user:*", "v_get", publicGrantObject, false},
		{"authenticated class", "registry", "system_class:authenticated", "v_get", publicGrantObject, true},
		{"named user", "registry", "user:usr00000000000000a1", "v_get", publicGrantObject, true},
		{"anonymous class, list verb", "registry", "system_class:anonymous", "v_list", publicGrantObject, true},
		{"anonymous class, registry-level object", "registry", "system_class:anonymous", "v_get", "registry_registry:reg53eeeg3578y4ah0q9", true},
		{"anonymous class, foreign domain", "registry", "system_class:anonymous", "v_get", "vpc_network:net1", true},
		{"anonymous class, own non-publishable type", "vpc", "system_class:anonymous", "v_get", "vpc_network:net1", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateProxyTuple(tt.domain, tt.subject, tt.relation, tt.object)
			if !tt.refused {
				if err != nil {
					t.Fatalf("публикация (%s %s %s) отвергнута: %v", tt.subject, tt.relation, tt.object, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("кортеж (%s %s %s) принят; ожидался отказ", tt.subject, tt.relation, tt.object)
			}
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Fatalf("код = %v; ожидался %v", got, codes.PermissionDenied)
			}
			if got := status.Convert(err).Message(); got != "permission denied" {
				t.Fatalf("текст = %q; ожидался %q", got, "permission denied")
			}
		})
	}
}

// TestRegisterResource_AnonymousWordIsAPublication — намерение со словом-классом
// применяется как публикация: в порт публикации с версией владельца, мимо
// журнала голых кортежей и мимо проекции ресурса. Снятие тем же словом
// закрывает публикацию.
func TestRegisterResource_AnonymousWordIsAPublication(t *testing.T) {
	uc, mirror, emitter, _, pub := publicGrantRig()
	ctx := context.Background()
	base := time.Now()

	require.NoError(t, uc.Register(ctx, &grantReq{
		subject: "system_class:anonymous", relation: "v_get", object: publicGrantObject, version: base,
	}))
	require.NoError(t, uc.Unregister(ctx, &grantReq{
		subject: "system_class:anonymous", relation: "v_get", object: publicGrantObject, version: base.Add(time.Second),
	}))

	assert.Equal(t, 0, emitter.writes, "публикация словом-классом не уходит голым кортежем")
	assert.Equal(t, 0, emitter.deletes, "снятие словом-классом не уходит голым кортежем")
	upserts, deletes := mirror.counts()
	assert.Equal(t, 0, upserts, "публикация не переписывает проекцию ресурса")
	assert.Equal(t, 0, deletes, "снятие публикации не удаляет проекцию ресурса")
	assertPublications(t, []publicationCall{
		{objectType: "registry_repository", objectID: "reg53eeeg3578y4ah0q9/team/app", published: true, version: base},
		{objectType: "registry_repository", objectID: "reg53eeeg3578y4ah0q9/team/app", published: false, version: base.Add(time.Second)},
	}, pub.seen(), "оба шага — порт публикации, в порядке версий владельца")
}

// TestRegisterResource_PublicationWordsShareOneStoredForm — переходный срок:
// публикация, сделанная `user:*`, снимается словом-классом и наоборот, потому
// что порт публикации ключуется объектом, а не написанием субъекта. Иначе
// переход потребителя на класс оставил бы чтение без входа, открытое старым
// словом.
func TestRegisterResource_PublicationWordsShareOneStoredForm(t *testing.T) {
	for _, tt := range []struct{ name, open, close string }{
		{"opened by wildcard, closed by class", "user:*", "system_class:anonymous"},
		{"opened by class, closed by wildcard", "system_class:anonymous", "user:*"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uc, _, emitter, _, pub := publicGrantRig()
			ctx := context.Background()
			base := time.Now()

			require.NoError(t, uc.Register(ctx, &grantReq{
				subject: tt.open, relation: "v_get", object: publicGrantObject, version: base,
			}))
			require.NoError(t, uc.Unregister(ctx, &grantReq{
				subject: tt.close, relation: "v_get", object: publicGrantObject, version: base.Add(time.Second),
			}))

			assert.Equal(t, 0, emitter.writes+emitter.deletes, "ни один шаг не уходит голым кортежем")
			assertPublications(t, []publicationCall{
				{objectType: "registry_repository", objectID: "reg53eeeg3578y4ah0q9/team/app", published: true, version: base},
				{objectType: "registry_repository", objectID: "reg53eeeg3578y4ah0q9/team/app", published: false, version: base.Add(time.Second)},
			}, pub.seen(), "открыто одним словом, закрыто другим — один объект порта")
		})
	}
}
