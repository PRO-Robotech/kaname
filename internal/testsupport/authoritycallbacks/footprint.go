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

// AssertReviewedGraph закрепляет актуальные тела рассмотренных authority callbacks
// и их private callees, включая новые корни CRUD/sequence/forward и зависимости.
// Это профиль перечисленных функций; общий обход всех установленных триггеров,
// проверка входящих писателей и точных trigger definitions остаются у вызывающих тестов.
// BEFORE/AFTER guards могут менять private TEMP receipts. Epoch/pending callbacks
// меняют metadata, catalog_changed закрывает identity.phase, signed folds пишут
// relation_fact; canonical command пишет mirror/parent, legacy fence — свой witness.
// Deferred forward completion удаляет только завершённый persistent receipt.
// Owner/ACL контракты storage guards проверяются отдельно и здесь не ослабляются.
// Новое тело, callee, язык либо search_path требует нового разбора графа.
func AssertReviewedGraph(t testing.TB, ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) {
	t.Helper()
	for _, f := range []struct{ name, digest, volatility string }{
		{"authority_binding_epoch_changed", "bcf0e606baaa81d738d99f2dfb8882f9723c37ccb59f70fb0785e2507119ccef", "v"},
		{"authority_binding_epoch_scope", "ae4b14d1640a4473eb8852512b1722b6439a178b2f1fde5fdc76dcc637e2fb30", "s"},
		{"authority_binding_mutation_scopes", "520582c7dca0731080b562c1f7dcc948391f722bf6779e7b64c7e30898518fd5", "s"},
		{"authority_group_member_row_scopes", "892302f4e4f38e2c9c016749bd6a10cadbcfa01d98ea19214500f9d6105ae6de", "s"},
		{"authority_group_member_scopes", "7304db913bb560413b1b5db276939b10d6674b12e9fceb11cac2f8c1b2f5dae1", "s"},
		{"authority_group_object_scopes", "ed9f62070e461be31342d7c4e3cfcbbb2e3542f2309b63f9592b80a46bd3cc60", "s"},
		{"authority_group_object_subject", "a264aedc8a97a6e60b92af1c14c043a27bb41e7aa0241948056b757f5bb57493", "s"},
		{"authority_policy_carrier_flush", "a7c37c306eab607cb0946ec362223ac2e7a3aef89eab24adec452287a84c546c", "v"},
		{"authority_policy_changed", "d11c7b0992c5c8ddaa323fc03bfbc1822b52edbae5a181fa449589500e6440fe", "v"},
		{"authority_policy_keys", "5bed24d2efa4e9dd3eadd3224d06031b5eeebf6785e7461ece8a4830adb46e86", "s"},
		{"authority_policy_object_account", "ae235eb8c5286d375d830c4d86f9f52d956035c49af8119d1b175173e81d7337", "s"},
		{"authority_protocol_attestation", "130a504f7da2b6780cd4e91a2c7103f9fabe765541f0f2611f900ce679ddd502", "v"},
		{"authority_protocol_catalog_changed", "974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb", "v"},
		{"authority_protocol_row_account", "36453c01ccca68634dcf0aac077f00cb17a82cb6fe9bb2406ac633380c4b4a9e", "s"},
		{"authority_protocol_row_guard", "cb90a95df9b7105f053ae0c8652407335ef82745a2e749dc395b1c82e8435d12", "v"},
		{"authority_protocol_row_scopes", "e45ac0e22f60f4dfee2d813f29a43a63d9859dc2c3551a3f4eeacf1103ee5d1d", "s"},
		{"authority_protocol_row_scopes_before_binding", "635a0ee4afa8490d61d3023caa6e15c5fc57f244e2ae4b66a2466b1714062f63", "s"},
		{"authority_protocol_statement_guard", "e188d77b0c72ec88024fb6ab264e2ae639679213ff727b5c61946dfde596bdad", "v"},
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
	// Resource callbacks и общий signed fold сохраняют точные body/metadata pins.
	// AFTER-consumption подтверждает actual effects в private TEMP; fold пишет
	// relation_fact только после consumed journal. Canonical command остаётся
	// входящим писателем mirror/parent с прежним legacy fallback.
	for _, f := range []struct {
		name, digest, volatility, settings string
		definer                            bool
	}{
		{"_authority_protocol_attestation_v1_body", "2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54", "v", "search_path=pg_catalog,pg_temp", true},
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
		{"_authority_resource_require_completion_v2", "bbcfca0b3d5ff59ad273695dfed2451f1ff37bf4030f8f7083415396dafee0e6", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_effect_applied_v2", "759a821396ab5850fd5aac25756c0403129d685aec1aa7e7f63bf95c8126f136", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_policy_epoch_monotonic_v2", "c8b62494628d305d0bc031154f07f1aef6dd3df936801a387e593ca4eb1f2d94", "v", "search_path=pg_catalog", false},
		{"authority_audit_id_guard_v2", "a349a4a051b336afdec4cb5422edf5738fe4e354acec98163abc0d4a2c70d8f2", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_audit_applied_v2", "b43a45a017d3b646301d3b0eb746d46ae7ee7d3a0539b2c8b91600c5a4c697a3", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_audit_statement_guard_v2", "cc9fd152b1c8fa68a65eb6451baf977a12b0866cc52668254280265f10f9271c", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_reconcile_id_guard_v2", "6e414e43962580748f91ca1cbd9ba4f1a842baa0d3f7d004967444aaea9f85f9", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_reconcile_applied_v2", "9c8514fc851017709d8dc63db0b71599df6681f04091dd7672cdc12f99045482", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_reconcile_statement_guard_v2", "d4a7e5cdc6f1a9d5e1734b6483fe8625a3372b665212fec285f034229fbcb587", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_registration_binding_guard_v2", "3419906be522c12cb827ee2ae9a7a76a86062643efc34f4148b2e15b9537f95f", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_registration_binding_applied_v2", "1848605707d774cab3b13d47753021747798c3cf6feb61bb41a7eeed27bbbe30", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_subject_change_id_guard_v2", "aa4bc39730f137bdf11491afaf41d9c8451c88e2cda40358fc0e33be2f29cb53", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_subject_change_applied_v2", "fa776df6d3b95dadb13fa1684424b2db105b21f5b8862bd045680fb8129d094e", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_subject_change_statement_guard_v2", "600129602604e3cac17840ff155738e5c886677cd8be781b62b9b29f2fe785b0", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_resource_registration_command_values_v2", "f578c73b8e09ea4f03c4510507f1a7d47dd14b8e0e5defff8c96086e6857101b", "v", "search_path=pg_catalog,pg_temp", true},
		{"resource_registration_command_apply", "164e53f2d7b9c9aff2b0c474a9782ef278c4b0cfd0aa1a2b101f9a7f9c2553fe", "v", "search_path=pg_catalog,kaname", false},
		{"resource_registration_locks_writers", "296db8b4f26f47e0189ce71b01295d5e2ff8e5a8f40b8cdf9807fac347a787c0", "v", "search_path=pg_catalog,pg_temp", true},
		{"relation_fact_fold_row", "7f7b25757447007572b06ef18edbf60b3256b5ca218484ef98fefaf0f338e635", "v", "", false},
		{"authority_resource_fold_body_v2", "3eb8735862b7643f353c9e10312c2fe9ca251489f875c1faf30289f3d166b5d9", "v", "search_path=pg_catalog,pg_temp", true},
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

	// Дополнительные private callees и новые trigger roots актуальной схемы.
	// Единственная SQL-функция имеет собственный точный language pin; допуска
	// произвольного языка, нового overload или второго digest здесь нет.
	// Audit roots 151500 теперь читают _authority_audit_binding_store_v3:
	// чужие TEMP, исчезнувший witness и несовпавший backend/xid/invoker
	// отвергаются; bootstrap/reconcile требуют owner receipt и прежние locks.
	// Binding-ветка идёт в уже закреплённый _authority_binding_mirror_store_v3,
	// проверяет точную active audit row/preheld key, затем потребляет эту row.
	// Ordinary audit не получает нового admission; UPDATE/DELETE/TRUNCATE
	// при binding program запрещены. Старый Resource exact-step guard сохранён.
	for _, f := range []struct {
		name, signature, digest, language, volatility, settings string
		definer                                                 bool
	}{
		{"_authority_audit_binding_store_v3", "_authority_audit_binding_store_v3()", "77412a99e3ea64432ee6ffe551d84ae7eae02bc2e0be1cbbe8e15941b407f595", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_binding_mirror_before_write_v3", "_authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb)", "91ee46ad24bb6267178100747185c18546bd1f01566e7b2780403f60c8995854", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_binding_mirror_store_v3", "_authority_binding_mirror_store_v3()", "94398fb5e832f685ced7c84e6975e21e04729db15a39893977cce3dc32809b61", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_crud_aux_statement_v3", "_authority_crud_aux_statement_v3()", "8d2c6a5f46066b400d9c42c158a337eb784a405c895145beedc7205133be7bc6", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_crud_aux_write_v3", "_authority_crud_aux_write_v3()", "5b549be379610152a2c2efc86836606fb82c298d885be0125cee3b535cf8cd32", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_crud_intent_v3", "_authority_crud_intent_v3(jsonb)", "e62f470c0c69a980308bec36a35f515609cb8fea56c79ec7632ac654a43e0f49", "plpgsql", "i", "search_path=pg_catalog,pg_temp", true},
		{"_authority_crud_manifest_domain_v3", "_authority_crud_manifest_domain_v3(jsonb)", "72c12f24e9c426b44fcc41b7690423a30675175589cd2ea6554beb48ad555387", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_crud_require_completion_v3", "_authority_crud_require_completion_v3(jsonb)", "9a9d56a95bbb255d52eeddf6c07a6f5e5663490ded6d8a558d097848a885d75c", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_crud_step_complete_v3", "_authority_crud_step_complete_v3(jsonb,integer)", "6a1951e0f4eb8b4dcd3a417f68938ac5e4771f04b1cf085938994dc45130e146", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_crud_unique_key_v3", "_authority_crud_unique_key_v3(text,jsonb)", "b7407a60f467821e6fe19c697ea37079807dbd5bed88c51a4ad645de731cf5b3", "plpgsql", "i", "search_path=pg_catalog,pg_temp", true},
		{"_authority_forward_anchor_complete_v4", "_authority_forward_anchor_complete_v4()", "0d9fdf6c02abe69e333b5584eee4628cafb7ec37849b7820e33aba4bea4396f1", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_forward_complete_v4", "_authority_forward_complete_v4(uuid)", "06cfcd8f144243fc529aacba57f452b0913cc6d5b1ab6bf2daf7c4e6a9a38290", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_forward_context_v4", "_authority_forward_context_v4()", "67a9f0c6d896048f52b3eeb396250c7e33e16ab3170b874734154197d247dd5c", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_forward_custody_v4", "_authority_forward_custody_v4()", "c5d84795becb1a5b12efc89bb553ac12db864c5ce31c90272041b15a09cd59b4", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_forward_program_v4", "_authority_forward_program_v4(uuid)", "d1100eb62bfc267ed7cc58d4d0cd0194f42b6285f8f465939381b60161607cca", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_forward_row_v4", "_authority_forward_row_v4(bigint,jsonb,boolean)", "31eb7a5ae8eec2af1f31d7aa9e55d49c80e787838ec3a34130de6db4b3dcc56f", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_forward_shape_v4", "_authority_forward_shape_v4()", "ef281d009e6201f0c03e49cfc049b4950290fe1953bb05b3638536b45b0d66aa", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_group_add_complete_v3", "_authority_group_add_complete_v3()", "158eca8cc62068a844f08ce5f746ad909a504fb429567d11c30d6f496dcd17eb", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_group_add_program_v3", "_authority_group_add_program_v3()", "e78556f1ccd014face052206b727651ce7e238bc9c3706f5a8d65f1f6559cce4", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_group_add_row_v3", "_authority_group_add_row_v3(text,text,jsonb,jsonb)", "a5973b00860baf37167efaf588cd3f3fe492248214708e3db6fa94ad7367590a", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_group_add_statement_v3", "_authority_group_add_statement_v3(text,text)", "b2bad5333c59b9db498767c0a6546c089633f849799ab87efa991183ee799b11", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_group_add_subject_v3", "_authority_group_add_subject_v3(text,text,jsonb)", "93f1e1147874032a6e7f4e1c08ad7651148e6ec5f25da7ffc2486d234ae14a8c", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_protocol_snapshot_v3", "_authority_protocol_snapshot_v3()", "f994c63975e86be78b2854a4f51aed55e615ad2c380b0f58fc1e0390662fc30a", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_resource_before_write_v3", "_authority_resource_before_write_v3(jsonb,text,text,jsonb,jsonb)", "10cfd5fcbe108b1f0b62f688d7ae80b72e34a536593fae3343c730cc0cb82da5", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_protocol_catalog_changed_v3", "_authority_protocol_catalog_changed_v3()", "974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_sequence_complete_v3", "_authority_sequence_complete_v3()", "c9f728c4492acf65f92ea6a6f411b3af85e63e765c5226bbf3ea1e80fd9291d1", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_sequence_excluded_v3", "_authority_sequence_excluded_v3(oid)", "eb4872a7f8c5bb7c40564e17fcc1928eac64bdbd8ac2e5609d261bd9ad36594b", "sql", "s", "search_path=pg_catalog,pg_temp", true},
		{"_authority_sequence_expected_v3", "_authority_sequence_expected_v3()", "e318cafb455438dd9a40e3c2cec7cc2d88daedf4307dd1e43248175005ab045b", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_native_delete_batch_read_v4", "authority_native_delete_batch_read_v4()", "79e71a95aac2ded09885f8c65165ad8ac169ef3b7f09bbda82a11ce1baec80f9", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_native_delete_batch_begin_v4", "_authority_native_delete_batch_begin_v4()", "d5f062e5543ded46945e843444184aed9f958ee776d63413095cc98c0ad5bd10", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_native_delete_batch_end_v4", "_authority_native_delete_batch_end_v4()", "3b8173b76b57f85ae4f73287e25b6e143a40c72a13d1423bf6ee218fa04d65fa", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_native_delete_batch_graph_v4", "_authority_native_delete_batch_graph_v4()", "7b70a67aa67a72d2bf2a1136bf0477cda6239ef79b6ace61e4b2e6d8f3f841e6", "plpgsql", "s", "search_path=pg_catalog,pg_temp", true},
		{"_authority_native_write_weights_v4", "_authority_native_write_weights_v4(jsonb)", "907111b7e806c46a660311a6a97fcc2ab2f86ea0430260fb501306f0e2ef522e", "plpgsql", "s", "search_path=pg_catalog,pg_temp", true},
		{"_authority_native_write_closure_v4", "_authority_native_write_closure_v4()", "a6da6a23e1899bf23d71ba4c5969f66cdfe15a4038fb9a89223df803b74c0e14", "plpgsql", "s", "search_path=pg_catalog,pg_temp", true},
		{"authority_native_write_arm_v4", "authority_native_write_arm_v4(uuid)", "ec1e1600c2673f4d02947f7dca7b4a719abc794a91d0045bad38fc2c642e5638", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_native_write_read_v4", "authority_native_write_read_v4()", "f6a0242967e246de3f3d305655783afd29ed8bef4f4e8d95a8821c965aa33e9c", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_sequence_header_v3", "_authority_sequence_header_v3()", "375b51310e57a7016673ba26f5b9925d59e67a2599ba74fe9c11d3f5bf9c70f5", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_sequence_probe_v3", "_authority_sequence_probe_v3()", "2e2a3266993eadee820fba438960cde53cf25cd05a4e806661e8d62664f075c3", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"_authority_sequence_store_v3", "_authority_sequence_store_v3()", "adca627a6c7ce9b1ee755a231793134d5ebcc372f370c694cbac3f067fb471d2", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_crud_fga_id_applied_v3", "authority_crud_fga_id_applied_v3()", "12aadb134df61a6f55b28252be5d22773e70f7b75f0a2117577faa2565a99594", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_crud_fga_id_guard_v3", "authority_crud_fga_id_guard_v3()", "cc6115bf7fafa0e7a70da14aa14db4232644f3a10d1ba34b1df131d93c616a49", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_crud_journal_applied_v3", "authority_crud_journal_applied_v3()", "d8238730f4bb3d9754ddc7108ad4dc70b348494f51b2dea1567b06cd69e9c7e2", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_crud_sequence_guard_v3", "authority_crud_sequence_guard_v3()", "4132523d01f6ddd5e893fa0c21ad9c2c944009dc8e968dc7228e5de3e8bf9ce0", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_crud_unique_guard_v3", "authority_crud_unique_guard_v3()", "5e8dbb8ba000bde51e8aa64c8e2fb708666f4822bb677a059adc623b0b45eb7d", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_group_add_fold_v3", "authority_group_add_fold_v3(text,jsonb,timestamptz)", "cb582cd47c5e210fa7f4c4a4c0a211ba1b120b455ce9a868a453d05335a2d1ef", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_resource_catalog_held_v2", "authority_resource_catalog_held_v2(text,text)", "253b7e0162038d53d4541789d1f69cbf8945123c865a4133966b713fffe9f4f2", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_sequence_expectation_complete_v3", "authority_sequence_expectation_complete_v3()", "aef5c1e0bfa60d5587aa8c0f342b3f5df1166a1a699af56019f5bdf36e856c99", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_sequence_origin_v3", "authority_sequence_origin_v3()", "d1b7a54b0cf83d53d416b6cc2bbcb1c20e60d985356931a45a6804ebf2f27df3", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_sequence_program_applied_v3", "authority_sequence_program_applied_v3()", "6ccad306aa7cd3524f1d2f5e172efdac14f2df3fdde38569d022b5a95a555ccc", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"authority_sequence_program_completion_v3", "authority_sequence_program_completion_v3()", "055164a539031177a7605113484f5667702c9074b84d03ab1a827cd614b66e35", "plpgsql", "v", "search_path=pg_catalog,pg_temp", true},
		{"registration_catalog_fence_ensure", "registration_catalog_fence_ensure(text,text)", "b14e6b304459d37dfe0add18ce5e592dc859097d48f2be56957ff505b79f802a", "plpgsql", "v", "search_path=pg_catalog,kaname", false},
	} {
		var source, language, volatility string
		var settings *string
		var definer bool
		var count int
		require.NoError(t, q.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_proc WHERE pronamespace='kaname'::regnamespace AND proname=$1`, f.name).Scan(&count))
		require.Equal(t, 1, count, "неоднозначный callback актуальной схемы: "+f.name)
		require.NoError(t, q.QueryRow(ctx, `SELECT p.prosrc,l.lanname,p.prosecdef,p.provolatile::text,array_to_string(p.proconfig,';') FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE p.oid=pg_catalog.to_regprocedure('kaname.'||$1)`, f.signature).Scan(&source, &language, &definer, &volatility, &settings))
		require.Equal(t, f.digest, fmt.Sprintf("%x", sha256.Sum256([]byte(source))), "непрочитанное тело callback актуальной схемы: "+f.name)
		require.Equal(t, f.language, language, "язык callback: "+f.name)
		require.Equal(t, f.definer, definer, "режим callback: "+f.name)
		require.Equal(t, f.volatility, volatility, "volatility callback: "+f.name)
		actualSettings := ""
		if settings != nil {
			actualSettings = strings.ReplaceAll(*settings, " ", "")
		}
		require.Equal(t, f.settings, actualSettings, "search_path callback: "+f.name)
	}

}
