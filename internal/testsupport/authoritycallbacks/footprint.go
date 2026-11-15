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
// писателей среди прежних authority guards нет. Новый signed fact fold и
// canonical command проверяются отдельно ниже; entry/lock API не callback roots.
// Новое тело, callee, язык либо search_path требует нового разбора графа.
func AssertReviewedGraph(t testing.TB, ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) {
	t.Helper()
	for _, f := range []struct{ name, digest, volatility string }{
		{"authority_binding_epoch_changed", "c75ff7ef8281b75973bd0a6d7fe2a4e3920adc4471a06d52a68613330205efc3", "v"},
		{"authority_binding_epoch_scope", "ae4b14d1640a4473eb8852512b1722b6439a178b2f1fde5fdc76dcc637e2fb30", "s"},
		{"authority_binding_mutation_scopes", "520582c7dca0731080b562c1f7dcc948391f722bf6779e7b64c7e30898518fd5", "s"},
		{"authority_group_member_row_scopes", "892302f4e4f38e2c9c016749bd6a10cadbcfa01d98ea19214500f9d6105ae6de", "s"},
		{"authority_group_member_scopes", "7304db913bb560413b1b5db276939b10d6674b12e9fceb11cac2f8c1b2f5dae1", "s"},
		{"authority_group_object_scopes", "ed9f62070e461be31342d7c4e3cfcbbb2e3542f2309b63f9592b80a46bd3cc60", "s"},
		{"authority_group_object_subject", "a264aedc8a97a6e60b92af1c14c043a27bb41e7aa0241948056b757f5bb57493", "s"},
		{"authority_policy_carrier_flush", "a7c37c306eab607cb0946ec362223ac2e7a3aef89eab24adec452287a84c546c", "v"},
		{"authority_policy_changed", "ae1bdc1254eb50995fbcd58fd520e2eb82cc7eac59433cc65602c72d8b8d49bd", "v"},
		{"authority_policy_keys", "5bed24d2efa4e9dd3eadd3224d06031b5eeebf6785e7461ece8a4830adb46e86", "s"},
		{"authority_policy_object_account", "ae235eb8c5286d375d830c4d86f9f52d956035c49af8119d1b175173e81d7337", "s"},
		{"authority_protocol_attestation", "08a5fa40928f579b763b6870192f241842145ef57b8889ecef0891768557f9ad", "v"},
		{"authority_protocol_catalog_changed", "974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb", "v"},
		{"authority_protocol_row_account", "36453c01ccca68634dcf0aac077f00cb17a82cb6fe9bb2406ac633380c4b4a9e", "s"},
		{"authority_protocol_row_guard", "28a374ab14661c74d6922d400a085f4edf8c8da60269d0b478ac9112a3c08708", "v"},
		{"authority_protocol_row_scopes", "e45ac0e22f60f4dfee2d813f29a43a63d9859dc2c3551a3f4eeacf1103ee5d1d", "s"},
		{"authority_protocol_row_scopes_before_binding", "635a0ee4afa8490d61d3023caa6e15c5fc57f244e2ae4b66a2466b1714062f63", "s"},
		{"authority_protocol_statement_guard", "d22abfe60fef1cbdae8b23b0b5ebbaa3e4de29593d0fc6d75ec72145b9a1797c", "v"},
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
	// Замкнутые Resource callbacks: точные тела проверены вместе с cutover1300.
	// AFTER-consumption меняет только private TEMP; signed fold пишет fact лишь
	// после подтверждённого INSERT журнала. Canonical command остаётся единственным
	// входящим писателем mirror/parent, с прежним legacy fallback.
	for _, f := range []struct {
		name, digest, volatility, settings string
		definer                            bool
	}{
		{"_authority_protocol_attestation_v1_body", "37d74a207dbe6322420c256ab367d6a131ee5a42a0687fb568b132f078aedc70", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_compare_legacy_write_allowed_v2", "03256f78ee7927bdaf33de3e3253638159353d55866f315ab0517f5e3f0ecbcc", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_producer_resource_v2", "eb65f305291505ff8cd3400b5aa9257d86613f97a71aa83326524e82ee3b151b", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_manifest_v2", "a80529dcdf4cb68395a9311f2f7b737fb467f0768c5b8a7e4488679bd5f3c63f", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_row_image_v2", "f6c7bdc6437dd7e32592f53af7795438fc97164a8ed1d33f7d9522e659548e42", "i", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_key_array_v2", "ec975c9c1dd185c9582596cbc96c7916c26f93b20d91c7c9eefb5ef22755d7a1", "i", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_preheld_key_v2", "77d85a114d79fb9d60470f0bdd63e2f688d5164fd5a225c5cebef10e43da78ea", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_validate_write_v2", "5822cc5ce9bb836e9537eae96472a55918d99d9f66a48ebea277320d7f661dd6", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_write_v2", "cdb26211660f6fc89ee193516c9bc7cfa3e3bdcd427d3cf71c17c4a047272c2f", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_side_v2", "09f8a713bf8e2a59ec0051910a49f5df93dec5bc5c776271c2f1a54dbb1eb8f1", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_consume_outbox_v2", "d91f9262b60ef7014532419fa24fd2531ed590212e37586aa32099dbd12c53f1", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_consume_required_v2", "3072f2d4cb1c9b0991af2998f7317fd710f9ad86886b02ee146e3a74eefc51ba", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_require_completion_v2", "44b4f1d0b6a9cf7e0ca9e35147f1e424bf51beed2c152cb4b9084d50e28f6c51", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_effect_applied_v2", "3c4ccafbb1580f3dae3f88ca5491fdbed5f99cbe70ea6d394e6b38996fe95028", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_policy_epoch_monotonic_v2", "c8b62494628d305d0bc031154f07f1aef6dd3df936801a387e593ca4eb1f2d94", "v", "search_path=pg_catalog", false},
		{"authority_audit_id_guard_v2", "4ea1d0c5498b5ee040b6c7878260e319b455127ac8f75c57ee86be8269c86732", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_audit_applied_v2", "2d083ffda77a2c7b57468026f6e6291c6f6e8503dec830406d8f5dfb5eb85e0a", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_audit_statement_guard_v2", "f67cd67ca621317392511bf0a054935cbfe3bc187fd7deca346ac0a3c15caabc", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_reconcile_id_guard_v2", "6e414e43962580748f91ca1cbd9ba4f1a842baa0d3f7d004967444aaea9f85f9", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_reconcile_applied_v2", "9c8514fc851017709d8dc63db0b71599df6681f04091dd7672cdc12f99045482", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_reconcile_statement_guard_v2", "d4a7e5cdc6f1a9d5e1734b6483fe8625a3372b665212fec285f034229fbcb587", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_registration_binding_guard_v2", "3419906be522c12cb827ee2ae9a7a76a86062643efc34f4148b2e15b9537f95f", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_registration_binding_applied_v2", "1848605707d774cab3b13d47753021747798c3cf6feb61bb41a7eeed27bbbe30", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_subject_change_id_guard_v2", "3d4b5dd51204c41da0d6d113283276b22d6eab6cab35828f3e1517bc779beaef", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_subject_change_applied_v2", "3a25296a1f5b76c6a8a062dc928723ec6be8bf6249944c38cf375b5fbd5de887", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_subject_change_statement_guard_v2", "b20c73772ff7efb941a609fde2bb54684ddcfbfc22b5649cea9c781b59194a00", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_resource_registration_command_values_v2", "f578c73b8e09ea4f03c4510507f1a7d47dd14b8e0e5defff8c96086e6857101b", "v", "search_path=pg_catalog,pg_temp", true},
		{"resource_registration_command_apply", "164e53f2d7b9c9aff2b0c474a9782ef278c4b0cfd0aa1a2b101f9a7f9c2553fe", "v", "search_path=pg_catalog,kaname", false},
		{"resource_registration_locks_writers", "296db8b4f26f47e0189ce71b01295d5e2ff8e5a8f40b8cdf9807fac347a787c0", "v", "search_path=pg_catalog,pg_temp", true},
		{"relation_fact_fold_row", "b4e42d485f7d34296a31e107a63eb83cfab02e3e80840b4b64a5d0fea450fcb0", "v", "", false},
		{"authority_resource_fold_body_v2", "b7c301ffb71bf80d70e2f891ac3f2985225bfc611f07b9890f5fe767d486a4a4", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_unregistration_operation_acl_v2", "075c20b7bb9f2d06dec73df64186da0b9d4bcc500b99fcbc28ef9b4f21ce7fea", "i", "search_path=pg_catalog,pg_temp", true},
	} {
		var source, language, volatility string
		var settings *string
		var definer bool
		var count int
		require.NoError(t, q.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='kaname'::regnamespace AND proname=$1`, f.name).Scan(&count))
		require.Equal(t, 1, count, "неоднозначный Resource callback: "+f.name)
		require.NoError(t, q.QueryRow(ctx, `SELECT p.prosrc,l.lanname,p.prosecdef,p.provolatile::text,array_to_string(p.proconfig,';') FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE p.pronamespace='kaname'::regnamespace AND p.proname=$1`, f.name).Scan(&source, &language, &definer, &volatility, &settings))
		require.Equal(t, f.digest, fmt.Sprintf("%x", sha256.Sum256([]byte(source))), "непрочитанное тело Resource callback: "+f.name)
		require.Equal(t, "plpgsql", language)
		require.Equal(t, f.definer, definer, "режим callback: "+f.name)
		require.Equal(t, f.volatility, volatility)
		actualSettings := ""
		if settings != nil {
			actualSettings = strings.ReplaceAll(*settings, " ", "")
		}
		require.Equal(t, f.settings, actualSettings, "search_path callback: "+f.name)
	}

}
