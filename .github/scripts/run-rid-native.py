#!/usr/bin/env python3
# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Штатный производитель нативных RID. Сводка не содержит закрытые данные прогона."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "github.com/PRO-Robotech/kaname/cmd/kaname"
# Имена прямых подтестов после замены пробелов на подчёркивания в testing.T.Run.
CASES = {
    'registry-installation-rid11': ('TestRID_11_InputAuthnAuthorityBackend', frozenset({
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair',
        'exact_exit_stage_field_pair_completedPairs;_no_bootstrap_I_fallback_or_self-provision',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes',
        'real_structured_stdout_stderr_and_absence_of_raw_or_JSON-escaped_credential_key_token_values',
    }), 128),
    'registry-installation-rid12': ('TestRID_12_ClosedShapeAndBounds', frozenset({
        'absent_and_empty_GD_field_normal_full_seed_success_zero_GD',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes',
        'UNSPECIFIED_unknown_enum_iam_module_role_type_rejected_exact_fields',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs',
        'single-bad-field-only_repair_twins;_array_reorder_idempotence',
    }), 65),
    'registry-installation-rid03': ('TestRID_03_DelegatedGrantAndIssuerBounds', frozenset({
        'explicit_account_registration_writer_authority,_missing/revoked/wildcard_refusals_and_lawful_twins',
        'real_production_listener_grant_Operation_Get_ACTIVE_with_installation_delegationId',
        'out-of-axis_role_denial_and_same-subject_legal_role_twin',
        'I_Create_denied_without_Operation;_caller-only_C_twin_succeeds',
        'allowed_anonymous_system-class_succeeds;_authenticated_refused',
    }), 44),
    'registry-installation-rid05': ('TestRID_05_CreatorDeletionAndNewID', frozenset({
        'normal_full_key_revoke_and_reference_census;_Delete_and_Get_NOT_FOUND',
        'old_creator_credentials_unauthenticated;_new_same-name_C2_does_not_resurrect_GD',
        'active_delegate_reference_blocks_Delete;_revoke-only_twin_permits_Delete',
        'O_explicitly_grants_C2;_old_GD_revoked;_explicit_new_Create_restores_issuance',
    }), 30),
    'registry-installation-rid06': ('TestRID_06_RevokeDuringApply', frozenset({
        'apply_at_real_before-pair_barrier;_O_commits_revoke_before_release',
        'overlap_and_sequential_reinstall_refuse;_old_G_and_GD_revoked;_replacement_zero',
        'no-revoke_overlap_twin_preserves_original_ID',
        'explicit_C_Create_recovery_preserves_revoked_history_and_new_issuer_grant_works',
    }), 30),
    "registry-installation-rid01": ("TestRID_01_CleanInstallAndRenewal", frozenset({
        "real_standalone_F0_->_verified_O_->_standing_C_->_full_serve_delivery",
        "exact_creator_and_axes;_C_I_A_distinct;_I_not_admin",
        "actual_token_expiry_renewal_with_same_live_key_and_unchanged_IDs_createdAt_counts",
        "expired_standing_key_refusal_and_valid-time-only_twin",
        "pace1_and_pace5_large_repeated_concurrent_authentication_and_cancellation",
    }), 8),
    "registry-installation-rid02": ("TestRID_02_ConcurrentAndRepeat", frozenset({
        "axis_reorder_sequential_repeat_preserves_IDs_and_createdAt",
        "two_real_absent-pair_arrivals_->_one_GD_and_two_successful_Operations",
        "raw_Any_metadata_index_and_response_identities_agree_on_both_Operations",
        "stop_before_writer_before_commit_after_commit_before_terminal;_primary_recovery",
        "cancellation_and_reconciler_overlap_preserve_terminal_refusal",
    }), 4),
    "registry-installation-rid04": ("TestRID_04_CreatorRetirement", frozenset({
        "independent_verified_O_gateway_RevokeAdmin_materialized_before_I_grant_and_apply",
        "new_grant_and_apply_denied;_old_G_and_GD_ACTIVE_and_no_self-restoration",
        "O_explicit_GrantAdmin_only_->_same_request_succeeds_with_same_delegationId",
    }), 14),
    "registry-installation-rid08": ("TestRID_08_SnapshotPagesAndFutureAccount", frozenset({
        "same_verified_O_initial_A_plus_normal_B_T;_actual_admission1+2_of3/hour",
        "actual_window_expiry_then_same_O_creates_D_only_after_frozen_N3_pageSize2_snapshot",
        "first_run_N3_includes_system-tenant_excludes_canonical_SYS_and_D;_repeat_N4_stable_IDs",
        "full_pages_compared_to_canonical_primary_census",
        "actual_empty_census_success;_second-page_BeginTx_unknown_fault_INTERNAL_before_Operations",
        "fault-only_removed_twin_and_retry_converge_without_duplicates",
    }), 6),
    "registry-installation-rid10": ("TestRID_10_MidRunFaultAndRetirement", frozenset({
        "first_pair_committed_observed;_unknown_Writer_BeginTx_only_after_normal_second_Operation_Create",
        "second_Operation_done_INTERNAL_internal_error;_first_kept;_no_later_pairs",
        "independent_O_RevokeAdmin_at_same_boundary;_denial_before_next_Operation",
        "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins",
    }), 6),
    'registry-installation-rid07': ('TestRID_07_ExistingPairConflict', frozenset({
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION',
        'each_failure_preserves_complete_pair_and_grants_without_update_or_revoke',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match',
    }), 32),
    'registry-installation-rid09': ('TestRID_09_WholeDeliveryPreflight', frozenset({
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate',
        'every_invalid_axis_preserves_catalog_roles_own_seed_SA_groups_joins_grants_GD_snapshots',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair',
    }), 32),
}
# Все шесть вложенных узлов обязательны в полном RID10.
RID10_NESTED = frozenset({
    "first_pair_committed_observed;_unknown_Writer_BeginTx_only_after_normal_second_Operation_Create/fault",
    "independent_O_RevokeAdmin_at_same_boundary;_denial_before_next_Operation/retirement",
    "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins/fault-independent-twin",
    "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins/fault-independent-twin/fault-lawful-twin",
    "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins/retirement-independent-twin",
    "remove_only_fault_or_restore_only_admin;_retry_N_stable_first_ID;_no-fault_twins/retirement-independent-twin/retirement-lawful-twin",
})

# Полные матрицы существующих фикстур: slash в t.Run не создаёт промежуточных узлов.
RID_MATRIX_NESTED = {
    'TestRID_11_InputAuthnAuthorityBackend': frozenset({
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/credential-missing/S1/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/credential-missing/S1/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/credential-missing/S2/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/credential-missing/S2/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/credential-unreadable/S1/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/credential-unreadable/S1/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/credential-unreadable/S2/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/credential-unreadable/S2/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/deleted-creator/S1/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/deleted-creator/S1/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/deleted-creator/S2/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/deleted-creator/S2/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/revoked-key/S1/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/revoked-key/S1/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/revoked-key/S2/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/revoked-key/S2/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/bad-signature/S1/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/bad-signature/S1/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/bad-signature/S2/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/bad-signature/S2/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/authority/S1/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/authority/S1/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/authority/S2/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/authority/S2/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/backend/S1/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/backend/S1/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/backend/S2/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/backend/S2/ACTIVE/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/account/S1/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/census/S2/absent/negative',
        'every_accepted_result-table_input_authn_authority_backend_row_on_absent_and_ACTIVE_pair/census/S2/ACTIVE/negative',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/credential-missing/S1/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/credential-missing/S1/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/credential-missing/S2/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/credential-missing/S2/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/credential-unreadable/S1/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/credential-unreadable/S1/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/credential-unreadable/S2/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/credential-unreadable/S2/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/deleted-creator/S1/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/deleted-creator/S1/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/deleted-creator/S2/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/deleted-creator/S2/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/revoked-key/S1/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/revoked-key/S1/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/revoked-key/S2/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/revoked-key/S2/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/bad-signature/S1/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/bad-signature/S1/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/bad-signature/S2/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/bad-signature/S2/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/authority/S1/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/authority/S1/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/authority/S2/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/authority/S2/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/backend/S1/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/backend/S1/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/backend/S2/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/backend/S2/ACTIVE/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/account/S1/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/census/S2/absent/lawful-control',
        'each_fact-only_legal_twin_succeeds_and_converges;_missing_S1_A_before_writes/census/S2/ACTIVE/lawful-control',
    }),
    'TestRID_12_ClosedShapeAndBounds': frozenset({
        'absent_and_empty_GD_field_normal_full_seed_success_zero_GD/absent/no-GD',
        'absent_and_empty_GD_field_normal_full_seed_success_zero_GD/empty/no-GD',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/unknown-field/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/empty-roleIds/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/duplicate-roleIds/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/empty-targetTypes/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/duplicate-targetTypes/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/empty-subjectTypes/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/duplicate-subjectTypes/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/roles17/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/types17/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/subjects5/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/subject-unspecified/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/subject-unknown/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/iam-role/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/iam-type/negative',
        'unknown_field_each_empty_or_duplicate_axis_and17roles17types5subjects_rejected_before_all_writes/iam-module/negative',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/unknown-field/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/empty-roleIds/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/duplicate-roleIds/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/empty-targetTypes/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/duplicate-targetTypes/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/empty-subjectTypes/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/duplicate-subjectTypes/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/roles17/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/types17/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/subjects5/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/subject-unspecified/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/subject-unknown/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/iam-role/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/iam-type/lawful-twin',
        'all17_lawful_catalog_types_and_roles_retained;_legal16/16/4_N_pairs/iam-module/lawful-twin',
    }),
    'TestRID_03_DelegatedGrantAndIssuerBounds': frozenset({
        'real_production_listener_grant_Operation_Get_ACTIVE_with_installation_delegationId/S1',
        'real_production_listener_grant_Operation_Get_ACTIVE_with_installation_delegationId/S2',
        'out-of-axis_role_denial_and_same-subject_legal_role_twin/S1',
        'out-of-axis_role_denial_and_same-subject_legal_role_twin/S2',
        'I_Create_denied_without_Operation;_caller-only_C_twin_succeeds/S1',
        'I_Create_denied_without_Operation;_caller-only_C_twin_succeeds/S2',
        'allowed_anonymous_system-class_succeeds;_authenticated_refused/S1',
        'allowed_anonymous_system-class_succeeds;_authenticated_refused/S2',
    }),
    'TestRID_05_CreatorDeletionAndNewID': frozenset({
        'normal_full_key_revoke_and_reference_census;_Delete_and_Get_NOT_FOUND/S1',
        'normal_full_key_revoke_and_reference_census;_Delete_and_Get_NOT_FOUND/S2',
        'old_creator_credentials_unauthenticated;_new_same-name_C2_does_not_resurrect_GD/S1',
        'old_creator_credentials_unauthenticated;_new_same-name_C2_does_not_resurrect_GD/S2',
        'active_delegate_reference_blocks_Delete;_revoke-only_twin_permits_Delete/S1',
        'active_delegate_reference_blocks_Delete;_revoke-only_twin_permits_Delete/S2',
        'O_explicitly_grants_C2;_old_GD_revoked;_explicit_new_Create_restores_issuance/S1',
        'O_explicitly_grants_C2;_old_GD_revoked;_explicit_new_Create_restores_issuance/S2',
    }),
    'TestRID_06_RevokeDuringApply': frozenset({
        'apply_at_real_before-pair_barrier;_O_commits_revoke_before_release/S1',
        'apply_at_real_before-pair_barrier;_O_commits_revoke_before_release/S2',
        'overlap_and_sequential_reinstall_refuse;_old_G_and_GD_revoked;_replacement_zero/S1',
        'overlap_and_sequential_reinstall_refuse;_old_G_and_GD_revoked;_replacement_zero/S2',
        'no-revoke_overlap_twin_preserves_original_ID/S1',
        'no-revoke_overlap_twin_preserves_original_ID/S2',
        'explicit_C_Create_recovery_preserves_revoked_history_and_new_issuer_grant_works/S1',
        'explicit_C_Create_recovery_preserves_revoked_history_and_new_issuer_grant_works/S2',
    }),
    "TestRID_08_SnapshotPagesAndFutureAccount": frozenset({
        "actual_empty_census_success;_second-page_BeginTx_unknown_fault_INTERNAL_before_Operations/normal-delete-real-empty",
        "actual_empty_census_success;_second-page_BeginTx_unknown_fault_INTERNAL_before_Operations/real-second-page-fault-twin-retry",
    }),
    'TestRID_07_ExistingPairConflict': frozenset({
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/role/S1',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/role/S2',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/target/S1',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/target/S2',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/subject/S1',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/subject/S2',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/creator/S1',
        'independent_lawful_role_target_subject_creator_conflicts_each_FAILED_PRECONDITION/creator/S2',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/role/S1',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/role/S2',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/target/S1',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/target/S2',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/subject/S1',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/subject/S2',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/creator/S1',
        'one-axis-only_twin_for_each_conflict_is_idempotent_exact_match/creator/S2',
    }),
    'TestRID_09_WholeDeliveryPreflight': frozenset({
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/roleIds/M1-M2/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/targetTypes/M1-M2/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/subjectTypes/M1-M2/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/delegate/M1-M2/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/roleIds/M2-M1/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/targetTypes/M2-M1/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/subjectTypes/M2-M1/negative',
        'complete_M1_M2_fresh_worlds_both_orders_for_foreign_role_target_subject_delegate/delegate/M2-M1/negative',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/roleIds/M1-M2/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/targetTypes/M1-M2/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/subjectTypes/M1-M2/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/delegate/M1-M2/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/roleIds/M2-M1/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/targetTypes/M2-M1/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/subjectTypes/M2-M1/lawful-twin',
        'single-field_legal_twin_writes_both_full_manifests_and_every_N_pair/delegate/M2-M1/lawful-twin',
    }),
}

# Исходный бюджет полного нативного теста сохраняется.
TEST_SECONDS = 1200
OUTER_SECONDS = 1320
# RID-08 подтверждает час допуска по реальным часам.
RID08_WINDOW_SECONDS = 3600


class Rejected(Exception):
    pass


def need(value):
    if not value:
        raise Rejected()


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def tree_sha(root):
    # Каноническая внешняя фиксация rid-tool-tree-v1 до первого запуска Node.
    root = root.resolve(strict=True)
    records, files, total = [], 0, 0

    def safe(value):
        need(0 < len(value) <= 4096 and all(32 <= ord(c) <= 126 for c in value))

    def visit(directory, depth):
        nonlocal files, total
        need(depth <= 128)
        for path in directory.iterdir():
            need(len(records) < 32768)
            rel = path.relative_to(root).as_posix()
            safe(rel)
            st = path.lstat()
            mode = format(stat.S_IMODE(st.st_mode) & 0o777, "03o")
            if path.is_symlink():
                value = path.resolve(strict=True).relative_to(root).as_posix()
                safe(value)
                kind = "S"
            elif stat.S_ISDIR(st.st_mode):
                kind, value = "D", "-"
            else:
                need(stat.S_ISREG(st.st_mode) and st.st_size <= 32 * 1048576)
                files += 1
                total += st.st_size
                need(total <= 256 * 1048576)
                kind, value = "F", sha(path)
                need(path.stat().st_size == st.st_size)
            records.append(f"{kind}\t{rel}\t{mode}\t{value}\n")
            if kind == "D":
                visit(path, depth + 1)
    visit(root, 0)
    need(files > 0)
    return hashlib.sha256("".join(sorted(records)).encode("ascii")).hexdigest()


def command(argv, env, log, cwd=ROOT, timeout=900):
    # Вывод компилятора, Docker и теста всегда остаётся в закрытом каталоге.
    with log.open("xb") as stream:
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stream,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return child.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
            raise


def docker(argv, env):
    result = subprocess.run(["docker", *argv], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=45, check=False)
    need(result.returncode == 0)
    return result.stdout.decode("utf-8").splitlines()


def descendants():
    # subreaper удерживает осиротевших потомков, включая отдельные setsid-группы.
    rows = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = path.read_text().rsplit(")", 1)[1].split()
            rows[int(path.parent.name)] = (int(fields[1]), fields[19], fields[0])
        except (FileNotFoundError, ProcessLookupError):
            continue
    owned = {os.getpid()}
    while True:
        found = {pid for pid, (ppid, _, _) in rows.items() if ppid in owned}
        if found <= owned:
            break
        owned |= found
    return {pid: rows[pid] for pid in owned if pid != os.getpid()}


def cleanup(evidence, env, before, root_test):
    result = {"ok": False, "processesRemaining": 0, "forcedProcesses": 0,
              "containers": 0, "volumes": 0, "containersRemaining": 0,
              "volumesRemaining": 0, "fallbackContainers": 0}
    initial = descendants()
    result["forcedProcesses"] = sum(row[2] != "Z" for row in initial.values())
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, (_, start, state) in descendants().items():
            if state != "Z":
                try:
                    # Владение и время рождения сверяются непосредственно перед сигналом.
                    if descendants().get(pid, (None, None, None))[1] == start:
                        os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        until = time.monotonic() + 5
        while time.monotonic() < until:
            try:
                while os.waitpid(-1, os.WNOHANG)[0]:
                    pass
            except ChildProcessError:
                pass
            if not descendants():
                break
            time.sleep(0.1)
    result["processesRemaining"] = len(descendants())
    # Без начального снимка Docker никакое удаление не разрешено.
    need(before is not None)
    ownerships = sorted(evidence.glob("*/pg-ownership.json"))
    need(ownerships)
    containers, volumes, mounts_by_container = set(), set(), {}
    natural = True

    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result

    def read_receipt(path):
        need(path.is_file() and not path.is_symlink() and not path.parent.is_symlink())
        value = json.loads(path.read_bytes(), object_pairs_hook=unique_fields)
        need(type(value) is dict)
        return value

    def mount_ids(mounts):
        need(type(mounts) is list and mounts)
        found = set()
        for mount in mounts:
            need(type(mount) is dict and mount.get("Type") == "volume")
            name, destination = mount.get("Name"), mount.get("Destination")
            need(isinstance(name, str) and re.fullmatch(r"[a-f0-9]{64}", name))
            need(destination == "/var/lib/postgresql/data")
            need((name, destination) not in found and name not in before["volumes"])
            found.add((name, destination))
        return found

    # Сначала проверяем ВСЮ ведомость владения. Без неё удаление запрещено.
    # Отсутствующий terminal после аварии допускает только scoped cleanup, никогда PASS.
    for path in ownerships:
        identity = read_receipt(path.parent / "test-identity.json")
        name = identity.get("testIdentity")
        need(set(identity) == {"testIdentity"} and isinstance(name, str) and name.startswith(root_test + "/"))
        need(path.parent.name == "case-" + hashlib.sha256(name.encode()).hexdigest())
        owned = read_receipt(path)
        need(set(owned) == {"containerId", "mounts"})
        cid = owned["containerId"]
        need(isinstance(cid, str) and re.fullmatch(r"[a-f0-9]{64}", cid))
        need(cid not in before["containers"] and cid not in containers)
        expected_mounts = mount_ids(owned["mounts"])
        need(not (volumes & {name for name, _ in expected_mounts}))
        containers.add(cid)
        volumes.update(name for name, _ in expected_mounts)
        mounts_by_container[cid] = expected_mounts
        def optional_receipt(name):
            receipt_path = path.parent / name
            # Повреждённый существующий файл (включая dangling symlink) не является отсутствующим.
            if not receipt_path.exists() and not receipt_path.is_symlink():
                return None
            return read_receipt(receipt_path)

        pg = optional_receipt("pg-cleanup.json")
        mail = optional_receipt("mailbox-cleanup.json")
        process = optional_receipt("mailbox-process.json")
        if pg is not None:
            need(set(pg) == {"containerId", "terminateSucceeded"} and pg["containerId"] == cid)
            need(type(pg["terminateSucceeded"]) is bool)
        if mail is not None:
            need(set(mail) == {"pid", "forced", "exited"} and type(mail["pid"]) is int and mail["pid"] > 0)
            need(type(mail["forced"]) is bool and type(mail["exited"]) is bool)
        if process is not None:
            need(set(process) == {"name", "pid"} and process["name"] == "mailbox")
            need(type(process["pid"]) is int and process["pid"] > 0)
        if mail is not None and process is not None:
            need(process["pid"] == mail["pid"])
        # PID из квитанции не используется для сигналов: выше действует проверка потомков/starttime.
        natural &= bool(pg is not None and mail is not None and process is not None and
                        pg["terminateSucceeded"] and mail["exited"] and not mail["forced"])
    current = set(docker(["ps", "-aq", "--no-trunc"], env))
    for cid in sorted(containers & current):
        inspected = json.loads("\n".join(docker(["inspect", "--type=container", cid], env)))
        need(type(inspected) is list and len(inspected) == 1 and inspected[0].get("Id") == cid)
        need(mount_ids(inspected[0].get("Mounts")) == mounts_by_container[cid])
    current_volumes = set(docker(["volume", "ls", "-q"], env))
    for volume in sorted(volumes & current_volumes):
        # Даже новый том нельзя удалить, если его уже использует чужой контейнер.
        users = set(docker(["ps", "-aq", "--no-trunc", "--filter", "volume=" + volume], env))
        need(users <= containers)
    for cid in sorted(containers & current):
        result["fallbackContainers"] += 1
        # Без -v: Docker не получает права неявно удалить неучтённый том.
        docker(["rm", "-f", cid], env)
    for volume in sorted(volumes & set(docker(["volume", "ls", "-q"], env))):
        need(not docker(["ps", "-aq", "--no-trunc", "--filter", "volume=" + volume], env))
        docker(["volume", "rm", volume], env)
    result.update(containers=len(containers), volumes=len(volumes),
                  containersRemaining=len(containers & set(docker(["ps", "-aq", "--no-trunc"], env))),
                  volumesRemaining=len(volumes & set(docker(["volume", "ls", "-q"], env))))
    result["ok"] = bool(natural and not any(result[key] for key in
        ("processesRemaining", "forcedProcesses", "containersRemaining", "volumesRemaining", "fallbackContainers")))
    return result


# Только публичные исходники существующих native fixture/bridge, не пути из Output.
ASSERTION_FILES = (
    "cmd/kaname/installation_delegated_grant_native_test.go",
    "cmd/kaname/installation_newman_delegated_grant_test.go",
    "cmd/kaname/installation_newman_delegated_delta_test.go",
    "cmd/kaname/installation_newman_delegated_evidence_test.go",
    "cmd/kaname/installation_newman_delegated_observation_test.go",
    "cmd/kaname/installation_native_fixture_test.go",
    "cmd/kaname/installation_native_concurrency_test.go",
    "cmd/kaname/installation_operation_observation_test.go",
    "cmd/kaname/installation_creator_deletion_native_test.go",
    "cmd/kaname/installation_newman_deletion_test.go",
    "cmd/kaname/installation_newman_deletion_wire_test.go",
    "cmd/kaname/installation_newman_deletion_delta_test.go",
    "cmd/kaname/installation_native_baseline_test.go",
    "cmd/kaname/installation_native_stock_premise_test.go",
    "cmd/kaname/installation_public_lifecycle_fixture_test.go",
    "cmd/kaname/installation_native_renewal_test.go",
    "cmd/kaname/installation_newman_install_test.go",
    "cmd/kaname/installation_creator_retirement_native_test.go",
    "cmd/kaname/installation_newman_retirement_test.go",
    "cmd/kaname/installation_newman_bridge_test.go",
    "cmd/kaname/installation_owned_child_driver_test.go",
    "cmd/kaname/installation_rid_integration_test.go",
    "cmd/kaname/installation_revoke_full_startup_test.go",
    "cmd/kaname/installation_full_startup_child_test.go",
    "cmd/kaname/installation_newman_revoke_test.go",
    "cmd/kaname/installation_newman_revoke_delta_test.go",
    "cmd/kaname/installation_revoke_failed_startup_test.go",
    "cmd/kaname/installation_pair_conflict_native_test.go",
    "cmd/kaname/installation_newman_conflict_test.go",
    "cmd/kaname/installation_snapshot_runtime_test.go",
    "cmd/kaname/installation_whole_delivery_native_test.go",
    "cmd/kaname/installation_newman_whole_projection_test.go",
    "cmd/kaname/installation_whole_delivery_snapshot_test.go",
    "cmd/kaname/installation_newman_whole_phase_test.go",
    "cmd/kaname/installation_midrun_runtime_test.go",
    "cmd/kaname/installation_newman_midrun_test.go",
    "cmd/kaname/installation_input_authn_native_test.go",
    "cmd/kaname/installation_input_authn_child_test.go",
    "cmd/kaname/installation_newman_input_authn_test.go",
    "cmd/kaname/installation_newman_input_authn_admission_test.go",
    "cmd/kaname/installation_newman_input_authn_restore_test.go",
    "cmd/kaname/installation_newman_input_authn_binding_restore_test.go",
    "cmd/kaname/installation_snapshot_child_test.go",
    "cmd/kaname/installation_closed_shape_start_test.go",
    "cmd/kaname/installation_closed_shape_native_test.go",
    "cmd/kaname/installation_closed_shape_public_test.go",
    "cmd/kaname/installation_newman_closed_shape_test.go",
    "internal/testsupport/installruntime/stand.go",
)


class NativeFailureMarkers:
    """Распознаёт только форму закрытого вывода; текст сообщений не сохраняется."""

    def __init__(self, seconds):
        hours, rest = divmod(seconds, 3600)
        minutes, seconds = divmod(rest, 60)
        duration = (f"{hours}h{minutes}m{seconds}s" if hours else
                    f"{minutes}m{seconds}s" if minutes else f"{seconds}s")
        self.timeout_header = f"panic: test timed out after {duration}\n"
        self.timeout = False
        self.alarm = False
        self.panic = False
        self.ambiguous = False

    def observe(self, output):
        # Не склеиваем фрагменты и не выводим ни сообщение panic, ни стек.
        if not isinstance(output, str):
            self.ambiguous = True
            return
        if output.count("\n") != 1 or not output.endswith("\n"):
            self.ambiguous = True
            return
        if output == self.timeout_header:
            self.timeout = True
        elif output.startswith("panic: test timed out after "):
            self.ambiguous = True
        elif re.fullmatch(r"panic: [^\r\n]+\n", output):
            self.panic = True
        elif output == "testing.(*M).startAlarm.func1()\n" and self.timeout:
            self.alarm = True

    def verdict(self, scan_status, site):
        # Это классификация наблюдённых маркеров, не доказательство первопричины.
        if scan_status != "complete":
            return {"kind": "unknown", "reason": "incomplete-scan"}
        if self.ambiguous or (self.timeout and self.panic):
            return {"kind": "unknown", "reason": "ambiguous-output"}
        if self.timeout:
            if self.alarm:
                return {"kind": "go-timeout", "reason": "configured-deadline-and-alarm"}
            return {"kind": "unknown", "reason": "timeout-without-alarm"}
        if self.panic:
            return {"kind": "panic", "reason": "panic-header"}
        if site.get("status") == "matched":
            return {"kind": "assertion", "reason": "allowlisted-error-trace"}
        return {"kind": "unknown", "reason": "no-recognized-marker"}


# Закрытая проекция RID03: ни значения столбцов, ни произвольные строки не сохраняются.
RID03_OPERATION_COLUMNS = frozenset({
    "id", "description", "created_at", "created_by", "principal_type", "principal_id",
    "principal_display_name", "modified_at", "done", "metadata_type", "metadata_data",
    "resource_id", "error_code", "error_message", "error_details", "response_type",
    "response_data", "account_id", "other",
})
RID03_OPERATION_MARKER_LIMIT = 16


def rid03_old_operation_diff(output, line_limit):
    # Маркер обязан быть одной полной строкой штатного t.Logf из известного файла.
    if not isinstance(output, str) or len(output) > 2048:
        return None
    source = "installation_newman_delegated_grant_test.go"
    match = re.fullmatch(
        r"[ \t]+(?:" + re.escape(str(ROOT / "cmd/kaname") + "/") + r")?" +
        re.escape(source) + r":([1-9][0-9]{0,6}): RID03_OLD_OPERATION_DIFF ([^\r\n]{1,1024})\n",
        output)
    if match is None or int(match[1]) > line_limit:
        return None

    def unique_fields(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate field")
            value[key] = item
        return value

    try:
        value = json.loads(match[2], object_pairs_hook=unique_fields)
    except (ValueError, RecursionError):
        return None
    if (type(value) is not dict or set(value) != {
            "missing", "columns", "beforeDone", "afterDone", "kind"}
            or type(value["missing"]) is not bool
            or type(value["columns"]) is not list
            or len(value["columns"]) > len(RID03_OPERATION_COLUMNS)
            or any(type(column) is not str or column not in RID03_OPERATION_COLUMNS
                   for column in value["columns"])
            or value["columns"] != sorted(set(value["columns"]))
            or type(value["beforeDone"]) is not str
            or value["beforeDone"] not in ("done", "pending", "unknown")
            or type(value["afterDone"]) is not str
            or value["afterDone"] not in ("done", "pending", "unknown")
            or type(value["kind"]) is not str
            or value["kind"] not in ("service-account-key", "user-token", "other", "unknown")):
        return None
    return value


def rid02_rid10_marker(output, marker, bounds):
    # Только полная строка из точного исходника; никаких значений из журнала в ключах.
    sources = {
        "RID02_OPERATION_CENSUS": "cmd/kaname/installation_native_concurrency_test.go",
        "RID10_SNAPSHOT": "cmd/kaname/installation_newman_midrun_test.go",
        "RID_PROJECTION": "cmd/kaname/installation_newman_whole_projection_test.go",
    }
    source = sources[marker]
    if not isinstance(output, str) or len(output) > 512:
        return None
    match = re.fullmatch(
        r"[ \t]+(?:" + re.escape(str(ROOT / "cmd/kaname") + "/") + r")?" +
        re.escape(Path(source).name) + r":([1-9][0-9]{0,6}): " + marker +
        r" ([^\r\n]{1,350})\n", output)
    if match is None or int(match[1]) > bounds.get(source, 0):
        return None
    if marker == "RID02_OPERATION_CENSUS":
        fields = ("matched", "scoped_pending", "scoped_terminal", "other_pending", "other_terminal")
        number = r"(0|[1-9][0-9]{0,6})"
        unavailable = re.fullmatch(r"status=unavailable matched=" + number, match[2])
        if unavailable:
            return {"status": "unavailable", "matched": int(unavailable[1])}
        value = re.fullmatch("status=complete " + " ".join(field + "=" + number for field in fields), match[2])
        return {"status": "complete", **dict(zip(fields, map(int, value.groups())))} if value else None
    fields = (("pull_role", "public_operations", "raw_delegations", "raw_bindings", "raw_operations")
              if marker == "RID10_SNAPSHOT" else
              ("accounts", "service_accounts", "groups", "members", "roles", "bindings",
               "delegations", "catalog", "materialization"))
    value = re.fullmatch(" ".join(field + "=(true|false)" for field in fields), match[2])
    return dict(zip(fields, (item == "true" for item in value.groups()))) if value else None


def test_diagnostics(path, root_test, predicates, *, timeout_seconds=None):
    # Только известные имена и ограниченные структурные проекции отдельных RID.
    names = {root_test, *(root_test + "/" + name for name in predicates)}
    if root_test == CASES["registry-installation-rid04"][0]:
        names.update(root_test + "/" + name + "/" + mode
                     for name in predicates for mode in ("S1", "S2"))
    if root_test == CASES["registry-installation-rid02"][0]:
        names.update(root_test + "/" + name + "/" + mode for name in (
            "two_real_absent-pair_arrivals_->_one_GD_and_two_successful_Operations",
            "raw_Any_metadata_index_and_response_identities_agree_on_both_Operations",
        ) for mode in ("S1", "S2"))
    if root_test == CASES["registry-installation-rid10"][0]:
        names.update(root_test + "/" + name for name in RID10_NESTED)
    names.update(root_test + "/" + name for name in RID_MATRIX_NESTED.get(root_test, frozenset()))
    known = {name: name for name in names}
    actions = {action: action for action in ("run", "pass", "fail", "skip")}
    result = {"status": "complete", "events": []}
    markers = None
    if (root_test == CASES["registry-installation-rid11"][0]
            and type(timeout_seconds) is int and timeout_seconds > 0):
        markers = NativeFailureMarkers(timeout_seconds)
    seen, fragmented, sites = set(), set(), {}
    bounds = {}
    for relative in ASSERTION_FILES:
        try:
            bounds[relative] = len((ROOT / relative).read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeError):
            continue
    rid03_names = set()
    if root_test == CASES["registry-installation-rid03"][0]:
        rid03_names = {root_test + "/" + name for name in RID_MATRIX_NESTED[root_test]}
    old_operation_diffs, old_operation_counts = {}, {}
    rid05_cleanup, ambiguous_cleanup = {}, set()
    projection_changes, ambiguous_projection = {}, set()
    binding_premise, ambiguous_premise = {}, set()
    bounded_markers, invalid_bounded_markers = {}, set()
    bounded_leaves, bounded_kinds = set(), ()
    if root_test == CASES["registry-installation-rid02"][0]:
        bounded_leaves = {name for name in names if name.endswith(("/S1", "/S2"))}
        bounded_kinds = ("RID02_OPERATION_CENSUS",)
    elif root_test == CASES["registry-installation-rid10"][0]:
        bounded_leaves = {root_test + "/" + name for name in RID10_NESTED
                          if not name.endswith("-independent-twin")}
        bounded_kinds = ("RID10_SNAPSHOT", "RID_PROJECTION")
    premise_reasons = {
        "budget-or-facts", "retired-history", "inventory", "role-index", "user-index", "subject-census",
        "member-census", "duplicate-member", "member-clock", "binding-status", "binding-lifecycle",
        "binding-subject", "roleless-binding", "role-live", "role-rules", "role-policy", "binding-scope",
        "iam-target", "iam-selector", "subject-type", "subject-user", "subject-reference",
        "account-reference", "desired-tuples", "duplicate-desired", "old-member-state", "missing-object-type",
        "scope-self-member", "scope-self-tuples", "old-member-desired", "ledger-shape", "ledger-object",
        "duplicate-ledger", "ledger-census",
    }
    premise_marker = re.compile(
        r"[ \t]*[a-z0-9_]+_test\.go:[1-9][0-9]{0,5}: "
        r"RID11_BINDING_PREMISE reason=([a-z-]{1,32})\n")
    projection_fields = ("accounts", "service_accounts", "groups", "members", "roles",
                         "bindings", "delegations", "catalog", "materialization")
    projection_marker = re.compile(
        r"[ \t]*installation_newman_whole_projection_test\.go:[1-9][0-9]{0,5}: RID_PROJECTION "
        + " ".join(field + "=(true|false)" for field in projection_fields) + r"\n")
    total = 0
    try:
        with path.open("rb") as stream:
            while True:
                line = stream.readline(1048577)
                if not line:
                    break
                total += len(line)
                if len(line) > 1048576 or total > 64 * 1048576:
                    result["status"] = "limit-exceeded"
                    break
                event = json.loads(line)
                if not isinstance(event, dict) or event.get("Package") != PACKAGE:
                    continue
                name, action = event.get("Test"), event.get("Action")
                if action == "output" and isinstance(name, str) and name in bounded_leaves:
                    output = event.get("Output")
                    for kind in bounded_kinds:
                        if not isinstance(output, str) or kind not in output:
                            continue
                        key = (name, kind)
                        active = ((root_test, "run") in seen and (name, "run") in seen
                                  and not any((subject, end) in seen for subject in (root_test, name)
                                              for end in ("pass", "fail", "skip")))
                        value = rid02_rid10_marker(output, kind, bounds) if active else None
                        if value is None or key in bounded_markers:
                            invalid_bounded_markers.add(key)
                        elif key not in invalid_bounded_markers:
                            bounded_markers[key] = value
                if (markers is not None and action == "output" and (root_test, "run") in seen
                        and (name is None or isinstance(name, str) and name in known)):
                    markers.observe(event.get("Output"))
                if (action == "output" and isinstance(name, str) and name in rid03_names
                        and (root_test, "run") in seen and (name, "run") in seen
                        and not any((name, end) in seen for end in ("pass", "fail", "skip"))):
                    diff = rid03_old_operation_diff(event.get("Output"), bounds.get(
                        "cmd/kaname/installation_newman_delegated_grant_test.go", 0))
                    if diff is not None:
                        count = old_operation_counts.get(name, 0) + 1
                        old_operation_counts[name] = count
                        if count <= RID03_OPERATION_MARKER_LIMIT:
                            old_operation_diffs.setdefault(name, []).append(diff)
                        else:
                            # Переполнение не должно оставлять правдоподобный неполный список.
                            old_operation_diffs.pop(name, None)
                if (root_test == CASES["registry-installation-rid05"][0]
                        and action == "output" and isinstance(name, str) and name in known
                        and (name, "run") in seen and (name, "fail") not in seen):
                    output = event.get("Output")
                    marker = re.fullmatch(
                        r"[ \t]*installation_newman_deletion_delta_test\.go:[1-9][0-9]{0,5}: "
                        r"RID05_CLEANUP policy=(true|false) binding=(true|false)"
                        r" facts=([0-9]{1,7})/([0-9]{1,7}) fga=([0-9]{1,7})/([0-9]{1,7})"
                        r" journal=([0-9]{1,7})/([0-9]{1,7}) reconcile=([0-9]{1,7})/([0-9]{1,7})\n",
                        output) if isinstance(output, str) and len(output) <= 240 else None
                    if marker:
                        if name in rid05_cleanup:
                            ambiguous_cleanup.add(name)
                        rid05_cleanup[name] = {
                            "policyEpochChanged": marker[1] == "true",
                            "bindingEpochChanged": marker[2] == "true",
                            "rowCountsBeforeAfter": {
                                table: [int(marker[i]), int(marker[i + 1])]
                                for i, table in ((3, "relation_fact"), (5, "fga_outbox"),
                                                 (7, "resource_journal"), (9, "resource_reconcile_outbox"))
                            },
                        }
                if (root_test in (CASES["registry-installation-rid07"][0], CASES["registry-installation-rid11"][0])
                        and action == "output" and isinstance(name, str) and name in known
                        and (name, "run") in seen
                        and not any((name, end) in seen for end in ("pass", "fail", "skip"))):
                    output = event.get("Output")
                    marker = projection_marker.fullmatch(output) if isinstance(output, str) and len(output) <= 260 else None
                    if marker:
                        if name in projection_changes:
                            ambiguous_projection.add(name)
                        projection_changes[name] = [
                            field for field, changed in zip(projection_fields, marker.groups()) if changed == "true"
                        ]
                if (markers is not None and action == "output" and isinstance(name, str) and name in known
                        and (name, "run") in seen
                        and not any((name, end) in seen for end in ("pass", "fail", "skip"))):
                    output = event.get("Output")
                    marker = premise_marker.fullmatch(output) if isinstance(output, str) and len(output) <= 180 else None
                    if marker and marker[1] in premise_reasons:
                        if name in binding_premise:
                            ambiguous_premise.add(name)
                        binding_premise[name] = marker[1]
                if (action == "output" and isinstance(name, str) and name in known and name not in sites
                        and (name, "run") in seen
                        and not any((name, end) in seen for end in ("pass", "fail", "skip"))):
                    output = event.get("Output")
                    # Никакой сборки фрагментов: потеря координаты безопаснее ложной склейки.
                    if not isinstance(output, str) or output.count("\n") != 1 or not output.endswith("\n"):
                        fragmented.add(name)
                    elif re.match(r"^[ \t]*Error Trace:", output):
                        sites[name] = {"status": "unrecognized-trace"}
                        for relative, limit in bounds.items():
                            match = re.fullmatch(r"[ \t]*Error Trace:[ \t]+" +
                                re.escape(str(ROOT / relative)) + r":([1-9][0-9]{0,6})\n", output)
                            if match and int(match[1]) <= limit:
                                sites[name] = {"status": "matched", "file": relative, "line": int(match[1])}
                                break
                if not isinstance(action, str) or action not in actions:
                    continue
                if name is None:
                    if action == "run":
                        continue
                    key = (None, action)
                    row = {"scope": "package", "action": actions[action]}
                elif isinstance(name, str) and name in known:
                    key = (name, action)
                    row = {"scope": "test", "test": known[name], "action": actions[action]}
                else:
                    continue
                if key not in seen:
                    seen.add(key)
                    result["events"].append(row)
    except (ValueError, RecursionError):
        result["status"] = "malformed"
    except OSError:
        result["status"] = "unavailable"
    first = next((row["test"] for row in result["events"]
                  if row["scope"] == "test" and row["action"] == "fail"), None)
    if first is not None:
        if result["status"] != "complete":
            site = {"status": "incomplete-scan"}
        elif first in fragmented:
            site = {"status": "fragmented-output"}
        else:
            site = sites.get(first, {"status": "not-observed"})
        result["firstFailureSite"] = {"test": first, **site}
        if (result["status"] == "complete" and site.get("status") == "matched"
                and first in bounded_leaves
                and not any((first, end) in seen for end in ("pass", "skip"))):
            for kind, source, field in (
                    ("RID02_OPERATION_CENSUS", "cmd/kaname/installation_native_concurrency_test.go", "operationCensus"),
                    ("RID10_SNAPSHOT", "cmd/kaname/installation_newman_midrun_test.go", "snapshotChanges"),
                    ("RID_PROJECTION", "cmd/kaname/installation_newman_midrun_test.go", "changedProjectionFields")):
                key = (first, kind)
                if site.get("file") == source and key in bounded_markers and key not in invalid_bounded_markers:
                    value = bounded_markers[key]
                    result[field] = ([name for name, changed in value.items() if changed]
                                     if kind == "RID_PROJECTION" else value)
        if (site.get("file") == "cmd/kaname/installation_newman_deletion_delta_test.go"
                and first in rid05_cleanup and first not in ambiguous_cleanup):
            result["deleteCleanup"] = rid05_cleanup[first]
        if (site.get("file") in ("cmd/kaname/installation_newman_conflict_test.go",
                                "cmd/kaname/installation_newman_retirement_test.go")
                and first not in ambiguous_projection and projection_changes.get(first)):
            result["changedProjectionFields"] = projection_changes[first]
        if (site.get("file") == "cmd/kaname/installation_newman_input_authn_restore_test.go"
                and first not in ambiguous_premise and first in binding_premise):
            result["bindingRestorationPremise"] = binding_premise[first]
    if result["status"] == "complete":
        failures = [{"test": name, "diffs": old_operation_diffs[name]}
                    for name in sorted(old_operation_diffs)
                    if (name, "fail") in seen and not any(
                        (name, end) in seen for end in ("pass", "skip"))]
        if failures:
            result["oldOperationDiffs"] = failures
    if markers is not None:
        result["failureMarker"] = markers.verdict(result["status"], result.get("firstFailureSite", {}))
    return result


def startup_diagnostics(evidence, root_test, predicates, diagnostics, binary_sha):
    # Только первый fail, уже связанный с точным require.NoError после StartBase.
    site = diagnostics.get("firstFailureSite", {})
    if diagnostics.get("status") != "complete" or site.get("status") != "matched":
        return {"status": "first-failure-site-unavailable"}
    fixture_source = "cmd/kaname/installation_native_fixture_test.go"
    names = {root_test + "/" + name for name in predicates}
    if root_test == CASES["registry-installation-rid04"][0]:
        names = {name + "/" + mode for name in names for mode in ("S1", "S2")}
    if site.get("file") != fixture_source or site.get("test") not in names:
        return {"status": "not-first-startbase-failure"}
    try:
        source_lines = (ROOT / fixture_source).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return {"status": "unavailable-fixture-source"}
    location = site.get("line")
    if (type(location) is not int or not 2 <= location <= len(source_lines)
            or source_lines[location - 2].strip() != "base, err := session.StartBase(ctx, f.writerPlan)"
            or source_lines[location - 1].strip() != "require.NoError(t, err)"):
        return {"status": "not-first-startbase-failure"}
    name = site["test"]
    events = diagnostics.get("events", [])
    first = next((i for i, row in enumerate(events) if row.get("action") == "fail"), None)
    if (first is None or events[first].get("test") != name
            or not any(row.get("test") == name and row.get("action") == "run" for row in events[:first])
            or any(row.get("test") == name and row.get("action") in ("pass", "skip") for row in events[:first])):
        return {"status": "unbound-failure"}
    fixture = "case-" + hashlib.sha256(name.encode()).hexdigest()

    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result)
            result[key] = value
        return result

    def read(parts, limit):
        # Каждый каталог и файл открывается относительно fd без следования ссылкам.
        fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in (fixture, *parts[:-1]):
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(leaf, "rb") as stream:
                before = os.fstat(stream.fileno())
                need(stat.S_ISREG(before.st_mode) and before.st_size <= limit)
                raw = stream.read(limit + 1)
                after = os.fstat(stream.fileno())
                need(len(raw) <= limit and len(raw) == before.st_size == after.st_size)
                need(before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns)
                return raw
        except FileNotFoundError:
            return None
        finally:
            os.close(fd)

    def receipt(parts):
        raw = read(parts, 4096)
        return None if raw is None else json.loads(raw, object_pairs_hook=unique)

    try:
        need(receipt(("test-identity.json",)) == {"testIdentity": name})
        process = receipt(("serve-001", "process", "process.json"))
        terminal = receipt(("serve-001", "process", "terminal.json"))
        result = {"status": "observed", "process": "receipt-absent", "terminal": "receipt-absent"}
        if process is None:
            need(terminal is None)
            return result  # Не утверждаем, что exec точно не происходил без process receipt.
        need(type(process) is dict and set(process) == {"pid", "binarySHA256", "configSHA256"})
        need(type(process["pid"]) is int and 0 < process["pid"] <= 2147483647)
        need(isinstance(binary_sha, str) and re.fullmatch(r"[a-f0-9]{64}", binary_sha))
        need(process["binarySHA256"] == binary_sha)
        need(isinstance(process["configSHA256"], str) and re.fullmatch(r"[a-f0-9]{64}", process["configSHA256"]))
        config = read(("serve-001", "config.yaml"), 65536)
        need(config is not None and hashlib.sha256(config).hexdigest() == process["configSHA256"])
        result["process"] = "matched-binary-and-config"
        if terminal is not None:
            need(type(terminal) is dict and set(terminal) == {"pid", "exited", "exitCode"})
            need(type(terminal["pid"]) is int and terminal["pid"] == process["pid"] and terminal["exited"] is True)
            need(type(terminal["exitCode"]) is int and -1 <= terminal["exitCode"] <= 255)
            result.update(terminal="matched-process", exitCode=terminal["exitCode"])
        # main.go bootstrap logger пишет эти четыре сообщения только в stderr.
        messages = {"refusal domain declaration failed": "refusal-domain",
                    "config load failed": "config-load", "config validation failed": "config-validation",
                    "kaname exited with error": "serve"}
        # Только фиксированные префиксы ошибок запуска. Суффикс не выходит наружу.
        prefixes = {"registration-account-writers: ": "registration-writer-plan",
                    "module identities: ": "module-identities", "refusal domain: ": "refusal-domain",
                    "посадка процесса: ": "process-posture",
                    "sign-in lane: authn.login.verifier-capacity: предел памяти средой не наложен": "sign-in-memory-limit-missing",
                    "sign-in lane: authn.login.verifier-capacity =": "sign-in-memory-budget",
                    "предел соединений базы не прочитан: ": "database-connection-limit-read",
                    "KANAME_REPOSITORY__POSTGRES__MAX_CONNS / KANAME_REPOSITORY__POSTGRES__REPLICA_BUDGET: ": "database-connection-budget",
                    "состояние схем базы не прочитано: ": "database-schema-read",
                    "load server mTLS config: ": "server-mtls",
                    "public listener mTLS creds: ": "public-listener-mtls",
                    "internal listener mTLS creds: ": "internal-listener-mtls",
                    "metrics listener mTLS config: ": "metrics-listener-mtls"}
        try:
            raw = read(("serve-001", "process", "stderr.jsonl"), 262144)
            if raw is None:
                result["bootstrap"] = {"status": "log-absent"}
                return result
            need(not raw or raw.endswith(b"\n"))  # Фрагменты не склеиваются и не признаются событием.
            lines = raw.splitlines(keepends=True)
            need(len(lines) <= 1024)
            found = []
            origins = []
            origin_message = "kaname startup error origin"
            origin_source = "cmd/kaname/serve.go"
            origin_classes = {"other", "context-canceled", "context-deadline", "address-in-use",
                              "connection-refused", "permission", "not-exist", "file", "database", "network"}
            for event_index, line in enumerate(lines):
                need(len(line) <= 32768 and line.endswith(b"\n"))
                event = json.loads(line, object_pairs_hook=unique)
                need(type(event) is dict)
                message = event.get("msg")
                if message == origin_message:
                    need(set(event) == {"time", "level", "msg", "source", "line", "class"})
                    need(isinstance(event["time"], str) and event["level"] == "ERROR")
                    need(event["source"] == origin_source and type(event["line"]) is int)
                    need(isinstance(event["class"], str) and event["class"] in origin_classes)
                    source_lines = (ROOT / origin_source).read_text(encoding="utf-8").splitlines()
                    need(1 <= event["line"] <= len(source_lines))
                    need(re.fullmatch(r"\s*return startupFailureAt\(.+", source_lines[event["line"] - 1]))
                    origins.append(({"source": origin_source, "line": event["line"],
                                     "class": event["class"]}, event_index))
                    continue
                if not isinstance(message, str) or message not in messages:
                    continue
                need(set(event) == {"time", "level", "msg", "err"})
                need(isinstance(event["time"], str) and event["level"] == "ERROR" and isinstance(event["err"], str))
                cause = "unclassified"
                if messages[message] == "serve":
                    for prefix, value in prefixes.items():
                        if event["err"].startswith(prefix):
                            cause = value
                            break
                elif messages[message] == "config-validation" and event["err"] in (
                    "registration-account-writers must be explicitly declared",
                    "registration-account-writers.assignments must be explicitly declared (an empty list disables registrars)",
                ):
                    cause = "registration-writer-declaration"
                found.append({"stage": messages[message], "cause": cause})
                fatal_index = event_index
            need(len(found) <= 1 and len(origins) <= 1)
            if origins:
                need(found and found[0]["stage"] == "serve" and origins[0][1] < fatal_index)
            if found and terminal is not None and terminal["exitCode"] == 1:
                result["bootstrap"] = {"status": "fatal-exit-matched", **found[0]}
                result["startupOrigin"] = ({"status": "matched-return", **origins[0][0]}
                                           if origins else {"status": "not-observed"})
            elif found:
                result["bootstrap"] = {"status": "event-without-matching-exit"}
            else:
                # terminal после cleanup сам по себе не отличает ранний выход от остановки по readiness timeout.
                result["bootstrap"] = {"status": "no-known-fatal-event"}
        except (OSError, ValueError, TypeError, Rejected, RecursionError):
            result["bootstrap"] = {"status": "invalid-or-unavailable"}
        return result
    except (OSError, ValueError, TypeError, Rejected, RecursionError):
        return {"status": "invalid-or-unavailable"}


def judge_test(path, root_test, predicates, *, rid11_nested=None):
    need(rid11_nested is None or root_test == CASES["registry-installation-rid11"][0])
    running, passed, terminal = set(), set(), []
    with path.open() as stream:
        for line in stream:
            event = json.loads(line)
            need(event.get("Package") == PACKAGE)
            name, action = event.get("Test"), event.get("Action")
            need(action not in ("fail", "skip"))
            if name:
                need(name == root_test or name.startswith(root_test + "/"))
                if action == "run":
                    need(name not in running)
                    running.add(name)
                if action == "pass":
                    need(name in running and name not in passed)
                    passed.add(name)
            elif action in ("pass", "fail"):
                terminal.append(action)
    need(root_test in passed and passed == running and terminal == ["pass"])
    if root_test in RID_MATRIX_NESTED:
        # Литеральный slash внутри имени t.Run не создаёт промежуточного узла.
        # Засчитываем предикаты только после равенства полного множества узлов.
        nested = RID_MATRIX_NESTED[root_test] if rid11_nested is None else rid11_nested
        expected = {root_test, *(root_test + "/" + name for name in predicates | nested)}
        need(running == expected)
        direct = set(predicates)
    else:
        direct = {name.split("/", 1)[1] for name in passed if name.count("/") == 1}
        need(direct == predicates)
    if root_test == CASES["registry-installation-rid10"][0]:
        expected = {root_test, *(root_test + "/" + name for name in predicates | RID10_NESTED)}
        need(running == expected)
    return {"ok": True, "passedTests": len(passed), "skippedTests": 0, "failedTests": 0,
            "directPredicates": sorted(direct)}


def hosted_memory_scope():
    # Читаем предел области процесса из ядра. GOMEMLIMIT не ограничивает RSS
    # и не подтверждает условие запуска полосы входа.
    need(os.geteuid() != 0)
    rows = Path("/proc/self/cgroup").read_text().splitlines()
    memberships = [row.removeprefix("0::") for row in rows if row.startswith("0::")]
    need(len(memberships) == 1)
    member = Path(memberships[0])
    need(member.is_absolute() and member.as_posix() == memberships[0]
         and member != Path("/") and ".." not in member.parts)
    group = Path("/sys/fs/cgroup").joinpath(*member.parts[1:])
    memory = (group / "memory.max").read_text().strip()
    swap = (group / "memory.swap.max").read_text().strip()
    need(memory == "4294967296" and swap == "0")
    return {"memoryMaxBytes": int(memory), "memorySwapMaxBytes": int(swap), "unprivileged": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=CASES, required=True)
    parser.add_argument("--private-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--require-hosted-memory-scope", action="store_true")
    parser.add_argument("--rid11-group", choices=("input", "identity", "proof-authority", "availability"))
    args = parser.parse_args()
    os.umask(0o077)
    root_test, predicates, phase_count = CASES[args.suite]
    group = args.rid11_group
    need(group is None or args.suite == "registry-installation-rid11")
    extra = RID08_WINDOW_SECONDS if args.suite == "registry-installation-rid08" else 0
    test_seconds = TEST_SECONDS + extra
    outer_seconds = OUTER_SECONDS + extra
    summary = {"schemaVersion": 1, "ok": False, "suite": args.suite, "status": "precondition-failed"}
    need(args.private_dir.is_absolute() and args.out.is_absolute())
    private, output = args.private_dir.resolve(), args.out.resolve()
    # Свежий закрытый каталог исключает смешивание доказательств разных вызовов.
    need(private.is_absolute() and output != private and private not in output.parents)
    need(ROOT != private and ROOT not in private.parents)
    need(ROOT != output and ROOT not in output.parents)
    need(not private.exists() and not output.exists())
    private.mkdir(mode=0o700, parents=True)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence = private / "evidence"
    evidence.mkdir(mode=0o700)
    env = {k: v for k, v in os.environ.items() if not k.startswith("KANAME_")}
    env.pop("NODE_OPTIONS", None)
    env.pop("NODE_PATH", None)
    started = False
    before = None
    try:
        if args.require_hosted_memory_scope:
            summary["status"] = "hosted-memory-scope-invalid"
            summary["nativeProcessScope"] = hosted_memory_scope()
            summary["status"] = "precondition-failed"
        need(sys.platform == "linux" and ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0)
        started = True
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, interrupted)
        for tool in ("go", "docker", "bash", "openssl", "python3"):
            need(shutil.which(tool))
        node = Path(os.environ["KANAME_RID_NODE_BINARY"])
        module = Path(os.environ["KANAME_RID_NEWMAN_MODULE"])
        need(node.is_absolute() and module.is_absolute())
        node, module = node.resolve(strict=True), module.resolve(strict=True)
        need(json.loads((module / "package.json").read_bytes())["version"] == "6.2.2")
        # Пользовательские NODE_OPTIONS и отключение штатного сборщика контейнеров не наследуются.
        env.pop("TESTCONTAINERS_RYUK_DISABLED", None)
        env.update(GOMAXPROCS="2", GOMEMLIMIT="3GiB", CGO_ENABLED="0")
        source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()
        need(re.fullmatch(r"[a-f0-9]{40}", source))
        need(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                         cwd=ROOT, stderr=subprocess.DEVNULL))
        source_tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT,
                                              stderr=subprocess.DEVNULL).decode().strip()
        need(re.fullmatch(r"[a-f0-9]{40}", source_tree))
        summary["sourceTree"] = source_tree
        summary["sourceRevision"] = source
        summary["status"] = "build-failed"
        bins = private / "bin"
        bins.mkdir(mode=0o700)
        for name, package, test in (("kaname", "./cmd/kaname", False),
                                    ("kaname-migrator", "./cmd/migrator", False),
                                    ("rid-tests", "./cmd/kaname", True)):
            argv = ["go", "test", "-c"] if test else ["go", "build"]
            need(command([*argv, "-p=1", "-o", str(bins / name), package], env,
                         private / (name + "-build.log")) == 0)
        runner = ROOT / "tests/newman/scripts/run-rid-native.cjs"
        collection = ROOT / "tests/newman/collections" / (args.suite + ".postman_collection.json")
        collector = ROOT / "tests/newman/scripts/collect-rid-native.py"
        expected = {"nodeSHA256": sha(node), "runnerSHA256": sha(runner),
                    "toolTreeSHA256": tree_sha(module), "collectionSHA256": sha(collection),
                    "testExecutableSHA256": sha(bins / "rid-tests")}
        artifact_hashes = {name: sha(bins / name) for name in ("kaname", "kaname-migrator", "rid-tests")}
        collector_sha = sha(collector)
        spec = importlib.util.spec_from_file_location("rid_native_collector", collector)
        impl = importlib.util.module_from_spec(spec)
        sys.dont_write_bytecode = True
        spec.loader.exec_module(impl)
        rid11_nested = None
        if group is not None:
            groups = impl.rid11_phase_groups(json.loads(collection.read_bytes()))
            need(group in groups and sha(collection) == expected["collectionSHA256"])
            phase_count = len(groups[group])
            variants = frozenset(variant.lower() for variant in impl.RID11_GROUP_VARIANTS[group])
            rid11_nested = frozenset(
                name for name in RID_MATRIX_NESTED[root_test] if name.split("/")[1] in variants
            )
            # Два публичных этапа на мир и ещё четыре после отзыва ключа
            # перед удалением создателя в отрицательных сценариях.
            need(2 * len(rid11_nested) + (4 if "deleted-creator" in variants else 0) == phase_count)
            env["KANAME_RID11_CASE_GROUP"] = group
            summary["rid11Group"] = group
            summary["producerSHA256"] = sha(Path(__file__).resolve())
        identity_file = private / "expected-identities.json"
        write_json(identity_file, expected)
        run_id = args.suite.removeprefix("registry-installation-") + "-ci-" + uuid.uuid4().hex
        env.update(KANAME_RID_ACCEPTANCE="1", KANAME_RID_NEWMAN="1",
                   KANAME_RID_NODE_BINARY=str(node), KANAME_RID_NEWMAN_MODULE=str(module),
                   KANAME_RID_EXPECTED_IDENTITIES_FILE=str(identity_file), KANAME_RID_RUN_ID=run_id,
                   KANAME_RID_EVIDENCE=str(evidence), KANAME_RID_BINARY=str(bins / "kaname"),
                   KANAME_RID_BINARY_SHA256=artifact_hashes["kaname"],
                   KANAME_RID_MIGRATOR=str(bins / "kaname-migrator"))
        summary.update(status="native-test-failed", expectedIdentities=expected, artifactSHA256=artifact_hashes,
                       collectorSHA256=collector_sha, runIdSHA256=hashlib.sha256(run_id.encode()).hexdigest(),
                       testDeadlineSeconds=test_seconds, outerDeadlineSeconds=outer_seconds)
        before = {"containers": frozenset(docker(["ps", "-aq", "--no-trunc"], env)),
                  "volumes": frozenset(docker(["volume", "ls", "-q"], env))}
        need(all(re.fullmatch(r"[a-f0-9]{64}", cid) for cid in before["containers"]))
        write_json(private / "docker-before.json", {key: sorted(value) for key, value in before.items()})
        summary["status"] = "native-test-command-failed"
        test_started = time.monotonic_ns()
        try:
            rc = command(["go", "tool", "test2json", "-t", "-p", PACKAGE, str(bins / "rid-tests"),
                          "-test.v=test2json", "-test.parallel=1", "-test.run=^" + root_test + "$",
                          "-test.count=1", f"-test.timeout={test_seconds}s"], env, private / "test.jsonl",
                         cwd=ROOT / "cmd/kaname", timeout=outer_seconds)
        finally:
            if args.suite == "registry-installation-rid11":
                # Только длительность команды по монотонным часам, без абсолютного времени.
                summary["testElapsedMilliseconds"] = max(0, (time.monotonic_ns() - test_started) // 1000000)
                if sys.exc_info()[0] is not None:
                    summary["testDiagnostics"] = test_diagnostics(
                        private / "test.jsonl", root_test, predicates, timeout_seconds=test_seconds)
        summary["testExitCode"] = rc if type(rc) is int and -255 <= rc <= 255 else None
        if rc != 0:
            summary["testDiagnostics"] = test_diagnostics(
                private / "test.jsonl", root_test, predicates, timeout_seconds=test_seconds)
        need(rc == 0)
        summary["status"] = "native-test-verdict-failed"
        try:
            summary["test"] = judge_test(private / "test.jsonl", root_test, predicates, rid11_nested=rid11_nested)
        except (Rejected, ValueError, OSError, TypeError, RecursionError):
            summary["testDiagnostics"] = test_diagnostics(
                private / "test.jsonl", root_test, predicates, timeout_seconds=test_seconds)
            raise
        summary["status"] = "receipt-proof-failed"
        need(sha(node) == expected["nodeSHA256"] and tree_sha(module) == expected["toolTreeSHA256"])
        need(sha(runner) == expected["runnerSHA256"] and sha(collector) == collector_sha)
        if group is not None:
            need(sha(Path(__file__).resolve()) == summary["producerSHA256"])
        need(all(sha(bins / name) == value for name, value in artifact_hashes.items()))
        reports = sorted(evidence.glob("**/newman/stdout"))
        need(len(reports) == phase_count)
        merged = impl.combine(collection, reports, run_id, expected["testExecutableSHA256"], expected, rid11_group=group)
        need(len(merged["sources"]) == phase_count)
        write_json(private / "combined.json", merged)
        # Проецируются только проверенные числовые поля и хеши, ни один HTTP-запрос/ответ.
        summary["phases"] = [{"phaseSHA256": hashlib.sha256(row["phase"].encode()).hexdigest(),
                              "reportSHA256": row["reportSHA256"], "requests": row["requests"],
                              "uniqueRequests": row["uniqueRequests"], "assertions": row["assertions"]}
                             for row in merged["sources"]]
        summary["counts"] = {"phases": phase_count, "requests": merged["run"]["stats"]["requests"]["total"],
                             "assertions": merged["run"]["stats"]["assertions"]["total"]}
        need(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                     stderr=subprocess.DEVNULL).decode().strip() == source)
        need(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                         cwd=ROOT, stderr=subprocess.DEVNULL))
        need(subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT,
                                     stderr=subprocess.DEVNULL).decode().strip() == source_tree)
        summary["status"] = "cleanup-proof-failed"
        summary["cleanup"] = cleanup(evidence, env, before, root_test)
        need(summary["cleanup"]["ok"])
        need(subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT,
                                     stderr=subprocess.DEVNULL).decode().strip() == source_tree)
        summary.update(ok=True, status="passed")
    except (Exception, KeyboardInterrupt):
        # Исключения могут содержать закрытые пути/ответы: наружу идёт только стадия отказа.
        if started and "cleanup" not in summary:
            try:
                summary["cleanup"] = cleanup(evidence, env, before, root_test)
            except Exception:
                summary["cleanup"] = {"ok": False}
    finally:
        if not summary["ok"] and "testDiagnostics" in summary:
            summary["startupDiagnostics"] = startup_diagnostics(
                evidence, root_test, predicates, summary["testDiagnostics"], summary["artifactSHA256"]["kaname"])
        write_json(output, summary)
    print(json.dumps({"ok": summary["ok"], "status": summary["status"]}))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt):
        print(json.dumps({"ok": False, "status": "invalid-or-unavailable-output"}))
        sys.exit(1)
