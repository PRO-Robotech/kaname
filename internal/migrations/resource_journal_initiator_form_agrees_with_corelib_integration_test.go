// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// resource_journal_initiator_form_agrees_with_corelib_integration_test.go —
// CHECK формы инициатора журнала службы доступа и `auth.InitiatorOf`
// фундамента говорят об одной форме (NTF-3, Р2).
//
// Выражение CHECK выписано в миграции регулярным выражением, а форму строит
// функция фундамента; два места об одном предмете расходятся молча. Сверка —
// опытом: каждый инициатор, которого строит `InitiatorOf`, база принимает, а
// каждую строку, которой он не строит никогда, база отвергает `23514`.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/auth"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/journaltx"
	"github.com/PRO-Robotech/corelib/operations"
)

func initiatorAccepted(t *testing.T, db *sql.DB, initiator string) (bool, string) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `SELECT set_config($1, $2, true)`, journaltx.SettingInitiator, initiator)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `INSERT INTO kaname.resource_journal
		  (resource_kind, resource_id, event_type, payload)
		VALUES ('iam_group', 'grp-form', 'CREATED', '{}'::jsonb)`)
	if err == nil {
		return true, ""
	}
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "отказ не от базы: %v", err)
	return false, pgErr.Code
}

func TestResourceJournal_InitiatorFormAgreesWithCorelib(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	produced := []operations.Principal{
		{Type: "user", ID: ids.NewID(ids.PrefixUser)},
		{Type: "user", ID: ids.NewHyphenID(ids.PrefixUser)},
		{Type: "service_account", ID: ids.NewID(ids.PrefixServiceAccount)},
		{Type: "service_account", ID: ids.NewHyphenID(ids.PrefixServiceAccount)},
		auth.SystemPrincipalFor("kaname", "seed"),
		auth.SystemPrincipalFor("kaname", "registration"),
		{Type: "user", ID: "system." + strings.Repeat("a", 63)},
	}
	for _, p := range produced {
		i, err := auth.InitiatorOf(p)
		require.NoError(t, err, "фикстура: фундамент не строит инициатора для %+v", p)
		ok, code := initiatorAccepted(t, db, i.String())
		require.True(t, ok, "инициатор %q, построенный фундаментом, база отвергла (%s)", i, code)
	}

	usr := ids.NewID(ids.PrefixUser)
	sva := ids.NewID(ids.PrefixServiceAccount)
	neverProduced := []string{
		usr,                                  // без типа
		"user:" + sva,                        // чужое семейство
		"service_account:" + usr,             // чужое семейство
		"user:system.kaname-seed",            // признак компонента под типом пользователя
		"system:",                            // пустая метка
		"system:Kaname-Seed",                 // заглавные
		"system:-kaname",                     // дефис первым
		"system:" + strings.Repeat("a", 64),  // длиннее DNS-метки
		"group:" + ids.NewID(ids.PrefixUser), // тип вне трёх
		"user:" + usr + " ",                  // хвост
	}
	for _, s := range neverProduced {
		ok, code := initiatorAccepted(t, db, s)
		require.False(t, ok, "строку %q фундамент не строит никогда, а база её приняла", s)
		require.Equal(t, "23514", code, "строка %q отвергнута не формой", s)
	}
	t.Logf("сверено: построенных фундаментом %d · не строимых %d", len(produced), len(neverProduced))
}
