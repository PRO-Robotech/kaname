// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
)

// Вызывается один раз при закрытом composition handoff. A/C внутри того же
// pg package могут переиспользовать проверку без повторной source discovery.
func validatePolicyEpochStorage(ctx context.Context, r *Repository) error {
	if r == nil {
		return errors.New("policy epoch repository unavailable")
	}
	var valid bool
	err := r.master.QueryRow(ctx, `SELECT
 NOT has_table_privilege(current_user,'kaname.authority_policy_epoch','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND NOT has_table_privilege(current_user,'kaname.authority_policy_carrier_pending','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 AND has_function_privilege(current_user,'kaname.authority_policy_epoch_read(text[])','EXECUTE')
 AND has_function_privilege(current_user,'kaname.authority_policy_epoch_lock(jsonb)','EXECUTE')
 AND has_function_privilege(current_user,'kaname.authority_policy_epoch_lock_for_write(jsonb,text[])','EXECUTE')
 AND NOT has_function_privilege(current_user,'kaname.authority_policy_keys(text,jsonb)','EXECUTE')
 AND NOT has_function_privilege(current_user,'kaname.authority_policy_carrier_flush()','EXECUTE')
 AND EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.authority_policy_carrier_pending'::regclass
 AND t.tgname='policy_carrier_flush' AND t.tgenabled='O' AND t.tgtype::integer=5
 AND t.tgdeferrable AND t.tginitdeferred AND t.tgfoid='kaname.authority_policy_carrier_flush()'::regprocedure)
 AND NOT EXISTS (
 SELECT 1 FROM unnest(ARRAY['users','groups','roles','accounts','grant_delegations','memberships','service_accounts','group_members','cluster_admin_grants',
 'access_bindings','access_binding_subjects','producer_source_receipt','public_read_publication','resource_registration_scope',
 'resource_registration_retirement','resource_mirror','projects','relation_fact','resource_parent_edge',
 'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','catalog_module','catalog_resource','catalog_verb']) source(name)
 CROSS JOIN (VALUES ('policy_epoch_insert',4),('policy_epoch_update',16),('policy_epoch_delete',8),('policy_epoch_truncate',32)) required(name,kind)
 WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
 WHERE t.tgrelid=to_regclass('kaname.'||source.name) AND t.tgname=required.name AND t.tgenabled='O'
 AND t.tgtype::integer=required.kind AND t.tgfoid='kaname.authority_policy_changed()'::regprocedure))`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("policy epoch storage is not protected")
	}
	return nil
}
