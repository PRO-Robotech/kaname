// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_h_read_integration_test.go — группа H приёмки делегированных
// выдач (PRO-Robotech/kaname#986): чтение, GD-60…GD-62.

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GD-60 — Get.
func TestGrantDelegation_GD60_Get(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-60")
	d1 := w.d1()

	// a, b, c — тело D1 (GD-01).
	for _, c := range []struct {
		name string
		user string
		sva  string
	}{
		{"a: usr-A", string(w.usrA), ""},
		{"b: usr-E", string(w.usrE), ""},
		{"c: sva-iss (делегат)", "", w.svaIss},
	} {
		ctx := asUserID(w, c.user)
		if c.sva != "" {
			ctx = asSA(w.ctx, c.sva)
		}
		body, err := w.getDelegation(ctx, d1)
		require.NoErrorf(t, err, "GD-60 %s", c.name)
		w.requireD1Body(body, d1, w.usrA, "GD-60 "+c.name)
	}
	// d, e, f — отказ в праве; f побайтово как d (скрытие существования).
	_, err := w.getDelegation(asUser(w.ctx, w.usrB), d1)
	d := statusText(requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-60 d: usr-B"))
	_, err = w.getDelegation(asSA(w.ctx, w.svaOther), d1)
	e := statusText(requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-60 e: sva-other"))
	_, err = w.getDelegation(asUser(w.ctx, w.usrA), "gdl00000000000000099")
	f := statusText(requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-60 f: несуществующее"))
	assert.Equal(t, d, e, "GD-60: e побайтово как d")
	assert.Equal(t, d, f, "GD-60: f побайтово как d")
	// g — форма id.
	_, err = w.getDelegation(asUser(w.ctx, w.usrA), "gdl!!")
	requireRefusal(t, err, codes.InvalidArgument, "invalid grant delegation id 'gdl!!'", "GD-60 g")
}

// GD-61 — List по аккаунту.
func TestGrantDelegation_GD61_ListByAccount(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-61")
	d1 := w.d1()
	d2 := w.d2()
	d3 := w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaOther), "GD-61 Дано: D3 (делегат sva-other)")
	w.revokeDelegation(asUser(w.ctx, w.usrA), d3, "GD-61 Дано: отзыв D3")

	list := func(ctxUser string, body string) (map[string]any, error) {
		resp, _, err := w.gdCall(asUserID(w, ctxUser), "List", body)
		return resp, err
	}
	// a — две страницы по pageSize 2.
	p1, err := list(string(w.usrA), fmt.Sprintf(`{"accountId":%q,"pageSize":2}`, w.accA))
	require.NoError(t, err, "GD-61 a: первая страница")
	items1 := listItems(t, p1)
	require.Len(t, items1, 2, "GD-61 a: первая страница — два")
	tok, _ := p1["nextPageToken"].(string)
	require.NotEmpty(t, tok, "GD-61 a: nextPageToken первой страницы")
	p2, err := list(string(w.usrA), fmt.Sprintf(`{"accountId":%q,"pageSize":2,"pageToken":%q}`, w.accA, tok))
	require.NoError(t, err, "GD-61 a: вторая страница")
	items2 := listItems(t, p2)
	require.Len(t, items2, 1, "GD-61 a: вторая страница — одно")
	tok2, _ := p2["nextPageToken"].(string)
	assert.Empty(t, tok2, "GD-61 a: nextPageToken второй страницы пуст")

	all := append(items1, items2...)
	var ids []string
	for i, it := range all {
		ids = append(ids, fmt.Sprint(it["id"]))
		if i > 0 {
			prev := fmt.Sprint(all[i-1]["createdAt"]) + "|" + fmt.Sprint(all[i-1]["id"])
			cur := fmt.Sprint(it["createdAt"]) + "|" + fmt.Sprint(it["id"])
			assert.Truef(t, prev < cur, "GD-61 a: порядок (createdAt, id) по возрастанию: %s, затем %s", prev, cur)
		}
		if it["id"] == d3 {
			assert.Equal(t, "REVOKED", it["status"], "GD-61 a: D3 — REVOKED")
		}
	}
	assert.ElementsMatch(t, []string{d1, d2, d3}, ids, "GD-61 a: три делегирования")

	// b, c — форма страницы, до права: те же ответы от usr-A и от usr-C.
	for _, who := range []string{string(w.usrA), string(w.usrC)} {
		_, err = list(who, fmt.Sprintf(`{"accountId":%q,"pageToken":"garbage"}`, w.accA))
		requireRefusal(t, err, codes.InvalidArgument, "Illegal argument page_token", "GD-61 b ("+who+")")
		requireFieldViolationExact(t, err, "page_token", "Illegal argument page_token", "GD-61 b ("+who+")")
		_, err = list(who, fmt.Sprintf(`{"accountId":%q,"pageSize":1001}`, w.accA))
		requireRefusal(t, err, codes.InvalidArgument, "invalid argument", "GD-61 c ("+who+")")
		requireFieldViolationExact(t, err, "page_size", "page_size must be in [0..1000] (0 means default)", "GD-61 c ("+who+")")
	}
	// d — без права.
	_, err = list(string(w.usrC), fmt.Sprintf(`{"accountId":%q}`, w.accA))
	requireRefusal(t, err, codes.PermissionDenied, "permission denied", "GD-61 d")
}

// GD-62 — выдача несёт ссылку на делегирование.
func TestGrantDelegation_GD62_GrantCarriesTheDelegationReference(t *testing.T) {
	t.Run("a: B10 и Bo", func(t *testing.T) {
		w := newGDWorld(t)
		bo := w.boOf()
		w.requireSubject("GD-62 a")
		d1 := w.d1()
		b10 := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "GD-62 Дано: B10")
		got, ok := delegationIDOf(t, w.getBinding(b10))
		assert.True(t, ok, "GD-62 a: у B10 ключа delegationId нет")
		assert.Equal(t, d1, got, "GD-62 a: delegationId B10")
		_, ok = delegationIDOf(t, w.getBinding(bo))
		assert.False(t, ok, "GD-62 a: у Bo (близнец) ключ delegationId есть")
	})
	t.Run("b: делегат, держащий право сам", func(t *testing.T) {
		w := newGDWorld(t)
		w.requireSubject("GD-62 b")
		w.d1()
		w.createDoneX(asUser(w.ctx, w.usrA), &iamv1.CreateAccessBindingRequest{
			Subjects:  []*iamv1.Subject{svaSubject(w.svaIss)},
			RoleId:    gdAdminRID,
			ScopeType: "iam.account",
			ScopeId:   string(w.accA),
			Target:    allInScopeTarget(),
		}, "GD-62 b Дано: admin учётке sva-iss на acc-A")
		w.pollRelation("service_account:"+w.svaIss, "admin", "account:"+string(w.accA), true,
			"GD-62 b контроль: sva-iss проходит Путь 2")
		id := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "GD-62 b")
		_, ok := delegationIDOf(t, w.getBinding(id))
		assert.False(t, ok, "GD-62 b: выдача прежним путём несёт delegationId (Р2 «Порядок путей»)")
	})
}
