// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// FB29 отключает соединение только отдельного runtime LOGIN этой базы.
// Настройка и наблюдение остаются на owner pool; ни проверяющий права, ни SQL
// ответ не подменяются ошибочным дублёром. После восстановления запрос тот же.
func TestFullBind_FB29_BackendOutageIsUnavailableAndCannotGrant(t *testing.T) {
	w := newFBStructuredWorld(t, false)
	roleAtAPI := func(name string, rules ...*iamv1.Rule) domain.RoleID {
		t.Helper()
		id := w.fullBindWorld.role(name, rules...)
		require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.role", string(id)))
		return id
	}
	role := roleAtAPI("fb29_proposed", fullBindBoxRule("get"))
	source := roleAtAPI("fb29_source", fullBindBoxRule("get"))
	w.grant(fbStructuredRequest(userSubject(w.usrD), source, "project", string(w.prjA)))
	w.createCapability(userSubject(w.usrD), "project", string(w.prjA))
	actor := "user:" + string(w.usrD)
	w.noScopeAdmin(actor)
	w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Allow)
	w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
	w.capability(actor, role, "project", string(w.prjA), relverdict.Deny)
	req := w.request(w.usrE, role, allInScopeTarget())
	fixed, before := proto.Clone(req), w.artifacts()
	login := w.pool.Config().ConnConfig.User
	quoted := pgx.Identifier{login}.Sanitize()
	_, err := w.observer.Exec(w.ctx, "ALTER ROLE "+quoted+" NOLOGIN")
	require.NoError(t, err)
	restore := func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_, err := w.observer.Exec(ctx, "ALTER ROLE "+quoted+" LOGIN")
		require.NoError(t, err)
		w.pool.Reset()
	}
	defer restore()
	w.pool.Reset()
	ctx, cancel := context.WithTimeout(w.ctx, 10*time.Second)
	defer cancel()
	require.Error(t, w.pool.Ping(ctx), "настоящий backend connection должен быть недоступен")
	require.NoError(t, ctx.Err(), "ошибка соединения не маскируется истечением контекста")
	op, callErr := w.ab.Create(asUser(ctx, w.usrD), req)
	require.Nil(t, op)
	require.Equal(t, codes.Unavailable, status.Code(callErr))
	require.NoError(t, ctx.Err())
	require.True(t, proto.Equal(fixed, req))
	require.Equal(t, before, w.artifacts())
	restore()
	require.NoError(t, w.pool.Ping(w.ctx))
	w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Allow)
	w.noScopeAdmin(actor)
	created := w.allow(asUser(w.ctx, w.usrD), req)
	w.materialized(created, "user:"+string(w.usrE), "v_get", atcBoxType, atcB1, true)
	w.native("user:"+string(w.usrE), "v_get", atcBoxType, atcB1, relverdict.Allow)
}
