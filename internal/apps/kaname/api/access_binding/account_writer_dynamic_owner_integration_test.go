// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Использует настоящий проверенный TLS-сеанс слушателя AW, боевой загрузчик перечня,
// политику вызывающего и страж аккаунта. Фикстура каталога — буквально модуль ATC;
// для этих RPC нет подмены скомпилированного модуля или тестового Authority.
func TestAccountWriter_DynamicCatalogOwnerThroughMTLS(t *testing.T) {
	w := newAWWorld(t)
	_, compiled := authzmap.DottedType(atcBoxType)
	require.False(t, compiled, "dynamic fixture must stay outside the compiled dictionary")
	doc, err := atcProbemodDoc()
	require.NoError(t, err)
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	w.applyDelivered("dynamic owner catalog", m)
	require.NoError(t, kanamepg.NewModuleSeedWriteRepo(w.pool).RunInWriteTx(w.ctx, func(ctx context.Context, seed moduleseed.Writer) error {
		_, err := seed.UpsertServiceAccount(ctx, "system", "kacho-probemod", "dynamic owner probe")
		return err
	}))
	w.startListener(t, "probemod")
	r := dpReq("project:"+string(w.prjA), "project", atcBoxType+":aw-dynamic-owner", string(w.prjA), "")
	t.Run("declared-without-account-grant-denied", func(t *testing.T) {
		w.denied(func() error { return w.call("probemod", r) })
	})
	p := w.plan
	p.Assignments = append(append([]domain.RegistrationAccountWriter{}, p.Assignments...), domain.RegistrationAccountWriter{AssignmentID: "aw-probemod-a", AccountID: string(w.accA), Module: "probemod"})
	require.NoError(t, w.apply(p))
	t.Run("foreign-known-module-denied", func(t *testing.T) {
		// У registry уже есть та же выдача аккаунта: отличается только владелец каталога.
		w.denied(func() error { return w.call("registry", r) })
	})
	t.Run("dynamic-module-foreign-type-denied", func(t *testing.T) {
		w.denied(func() error { return w.call("probemod", w.regIn("aw-dynamic-foreign", w.prjA, w.accA)) })
	})
	t.Run("unregistered-module-denied", func(t *testing.T) {
		w.denied(func() error { return w.call("nonmodule", r) })
	})
	t.Run("empty-actor-denied", func(t *testing.T) {
		// Отсутствие сертификата на транспорте отвергается строгим TLS ещё до RPC;
		// прямой сценарий проверяет тот же боевой страж без извлечённого действующего лица.
		w.denied(func() error { return w.reg.Register(context.Background(), r) })
	})
	t.Run("own-type-wrong-account-denied", func(t *testing.T) {
		w.denied(func() error {
			return w.call("probemod", dpReq("project:"+string(w.prjC), "project", atcBoxType+":aw-dynamic-b", "", ""))
		})
	})
	t.Run("dynamic-owner-registered", func(t *testing.T) {
		require.NoError(t, w.call("probemod", r))
		var account string
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT parent_account_id FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`, atcBoxes, "aw-dynamic-owner").Scan(&account))
		require.Equal(t, string(w.accA), account)
	})
	t.Run("dynamic-publication-stays-closed", func(t *testing.T) {
		w.denied(func() error { return w.call("probemod", dpReq("system_class:anonymous", "v_get", r.Object, "", "")) })
	})
	t.Run("unknown-catalog-type-invalid-argument", func(t *testing.T) {
		before := w.snapshot()
		err := w.call("probemod", dpReq("project:"+string(w.prjA), "project", "probemod_unknown:aw-unknown", "", ""))
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		require.Equal(t, before, w.snapshot())
	})
	// Выводим из обращения обычным применителем манифеста, сохраняя каноническую строку.
	// Его пустой, явно объявленный набор ресурсов снимает оба динамических типа.
	retired, err := manifest.Load([]byte("apiVersion: iam/v1\nmodule: probemod\nresources: []\n"))
	require.NoError(t, err)
	w.applyDelivered("retire dynamic owner types", retired)
	var owner string
	var live bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT module,live FROM kaname.catalog_resource WHERE dotted=$1`, atcBoxes).Scan(&owner, &live))
	require.Equal(t, "probemod", owner)
	require.False(t, live)
	var present int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`, atcBoxes, "aw-dynamic-owner").Scan(&present))
	require.Equal(t, 1, present, "retirement must leave a real registration to clean up")
	t.Run("retired-type-foreign-cleanup-denied", func(t *testing.T) {
		w.denied(func() error { return w.unregister("registry", r) })
	})
	t.Run("retired-type-own-cleanup", func(t *testing.T) {
		require.NoError(t, w.unregister("probemod", r))
		var mirrors, facts int
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`, atcBoxes, "aw-dynamic-owner").Scan(&mirrors))
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2`, atcBoxType, "aw-dynamic-owner").Scan(&facts))
		require.Zero(t, mirrors)
		require.Zero(t, facts)
	})
}
