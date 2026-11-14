// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authoritycallbacks проверяет прочитанный граф DB guards kaname#1034.
// Pins относятся к установленным телам, а не только к разрешённым именам.
package authoritycallbacks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// AssertReviewedGraph удерживает весь достижимый authority callback graph:
// guards/ownership и их private callees читают состояние. Записи callbacks:
// catalog_changed закрывает identity.phase в transition; binding_epoch_changed
// и policy_changed/carrier_flush меняют только epoch/pending metadata.
// carrier_flush достижим также от deferred trigger на pending. Domain/outbox
// писателей здесь нет; lifecycle entry/lock API не являются callback roots.
// Новое тело, callee, язык либо search_path требует нового разбора графа.
func AssertReviewedGraph(t testing.TB, ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) {
	t.Helper()
	for _, f := range []struct{ name, digest, volatility string }{
		{"authority_binding_epoch_changed", "bce0146640201c5039f1006873fd5e514995d359569d4dfa71b362ad6352396f", "v"},
		{"authority_binding_epoch_scope", "ae4b14d1640a4473eb8852512b1722b6439a178b2f1fde5fdc76dcc637e2fb30", "s"},
		{"authority_binding_mutation_scopes", "520582c7dca0731080b562c1f7dcc948391f722bf6779e7b64c7e30898518fd5", "s"},
		{"authority_group_member_row_scopes", "892302f4e4f38e2c9c016749bd6a10cadbcfa01d98ea19214500f9d6105ae6de", "s"},
		{"authority_group_member_scopes", "7304db913bb560413b1b5db276939b10d6674b12e9fceb11cac2f8c1b2f5dae1", "s"},
		{"authority_group_object_scopes", "ed9f62070e461be31342d7c4e3cfcbbb2e3542f2309b63f9592b80a46bd3cc60", "s"},
		{"authority_group_object_subject", "a264aedc8a97a6e60b92af1c14c043a27bb41e7aa0241948056b757f5bb57493", "s"},
		{"authority_policy_carrier_flush", "4fa7d4c836fe4fbf974aba5aa4bf2b586f590c007b1909e75262825ca1fe42ac", "v"},
		{"authority_policy_changed", "fea085db09d6c8185b8f805a1a17ac5bed238a19cd36d96c54696d36ebee36a3", "v"},
		{"authority_policy_keys", "5bed24d2efa4e9dd3eadd3224d06031b5eeebf6785e7461ece8a4830adb46e86", "s"},
		{"authority_policy_object_account", "ae235eb8c5286d375d830c4d86f9f52d956035c49af8119d1b175173e81d7337", "s"},
		{"authority_protocol_attestation", "67714f8db5e7ee3e0b071834695d3239ef029bd122f8ee3bf0bff0cc00ae3086", "v"},
		{"authority_protocol_catalog_changed", "974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb", "v"},
		{"authority_protocol_row_account", "36453c01ccca68634dcf0aac077f00cb17a82cb6fe9bb2406ac633380c4b4a9e", "s"},
		{"authority_protocol_row_guard", "8a6d1f6c871726264eb08e82d9073a5a65ab8b066715874c7a96ff3a35eb934f", "v"},
		{"authority_protocol_row_scopes", "e45ac0e22f60f4dfee2d813f29a43a63d9859dc2c3551a3f4eeacf1103ee5d1d", "s"},
		{"authority_protocol_row_scopes_before_binding", "635a0ee4afa8490d61d3023caa6e15c5fc57f244e2ae4b66a2466b1714062f63", "s"},
		{"authority_protocol_statement_guard", "f3398d2774a14432272498e79c8cf27346b09725be0340369c09d2b0dd8db939", "v"},
	} {
		var source, language, volatility, settings string
		var definer bool
		var count int
		require.NoError(t, q.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_proc p WHERE p.pronamespace='kaname'::regnamespace AND p.proname=$1`, f.name).Scan(&count))
		require.Equal(t, 1, count, "неоднозначная authority callback function: "+f.name)
		require.NoError(t, q.QueryRow(ctx, `SELECT p.prosrc,l.lanname,p.prosecdef,p.provolatile::text,array_to_string(p.proconfig,';') FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE p.pronamespace='kaname'::regnamespace AND p.proname=$1`, f.name).Scan(&source, &language, &definer, &volatility, &settings))
		require.Equal(t, f.digest, fmt.Sprintf("%x", sha256.Sum256([]byte(source))), "непрочитанное тело callback: "+f.name)
		require.Equal(t, "plpgsql", language)
		require.True(t, definer)
		require.Equal(t, f.volatility, volatility)
		require.Equal(t, "search_path=pg_catalog,pg_temp", strings.ReplaceAll(settings, " ", ""))
	}
}
