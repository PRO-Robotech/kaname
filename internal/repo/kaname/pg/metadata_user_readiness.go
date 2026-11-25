// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Тела проверяются по pg_catalog до первого вызова функции готовности.
const userReadinessCatalogSQL = `
WITH root AS (
    SELECT c.relowner, n.oid AS namespace
    FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_class c ON c.relnamespace=n.oid
    WHERE n.nspname='kaname' AND c.relname='authority_writer_protocol'
      AND c.relowner=n.nspowner AND c.relkind='r' AND c.relpersistence='p'
), expected(signature,digest,result,argnames,definer,volatility) AS (
    VALUES
        ('kaname.authority_metadata_user_access_label_ready_v1()',
         '9886259fc2bb278e7bae5123f5df0ae56ddf4f1bb8220ad8e2edb03e71a98ddd',
         'pg_catalog.bool', NULL::text[], true, 's'),
        ('kaname._authority_metadata_user_exports_v1(oid,boolean)',
         '54f31a9d2f6ce4e1ee963d0d1e9a42fd82c162b4d433f7b5a5b13359e257153e',
         'pg_catalog.regprocedure[]', ARRAY['p_executor','p_installed'], false, 's'),
        ('kaname.authority_metadata_user_install_v1(regrole,regrole,boolean)',
         'f57ab3f10762ef5dc47b2315301215e4f180fbf6cdb51e1292b5a5c09d27df9e',
         'pg_catalog.void', ARRAY['p_runtime','p_executor','p_enable'], false, 'v')
), verified AS (
    SELECT p.oid
    FROM expected e JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(e.signature)
    JOIN root r ON p.pronamespace=r.namespace AND p.proowner=r.relowner
    JOIN pg_catalog.pg_language l ON l.oid=p.prolang AND l.lanname='plpgsql'
    WHERE p.prokind='f' AND p.prosecdef=e.definer AND p.provolatile::text=e.volatility AND p.proparallel='u'
      AND p.prorettype=pg_catalog.to_regtype(e.result) AND NOT (p.proretset OR p.proisstrict OR p.proleakproof)
      AND p.proargnames IS NOT DISTINCT FROM e.argnames AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
      AND p.pronargdefaults=0 AND p.provariadic=0 AND p.prosupport=0 AND p.protrftypes IS NULL
      AND p.probin IS NULL AND p.prosqlbody IS NULL
      AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')=e.digest
      AND NOT EXISTS (SELECT FROM pg_catalog.pg_proc other WHERE other.pronamespace=p.pronamespace
                       AND other.proname=p.proname AND other.oid<>p.oid)
      AND NOT EXISTS (SELECT FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
                      WHERE a.grantee<>p.proowner AND
                            (NOT e.definer OR a.grantee<>session_user::regrole OR a.grantor<>p.proowner OR a.is_grantable))
      AND (NOT e.definer OR EXISTS (SELECT FROM pg_catalog.aclexplode(p.proacl) a
                                    WHERE a.grantee=session_user::regrole AND a.privilege_type='EXECUTE'))
), enabled AS (
    SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
    WHERE n.nspname='kaname' AND a.grantee<>p.proowner AND (
        starts_with(p.proname::text,'authority_metadata_user_') OR starts_with(p.proname::text,'_authority_metadata_user_')
        OR p.proname IN ('authority_user_access_labels_operation_create_v1','_authority_user_access_labels_operation_create_v1',
                         '_authority_user_access_labels_operation_guard_v1'))
)
SELECT NOT EXISTS (SELECT FROM root) OR EXISTS (SELECT FROM enabled), (SELECT count(*) FROM verified)=3`

// InstalledUserAccessLabels возвращает порт только для явно разрешённого User.Update.
// Пустой результат соответствует закрытому набору ACL, включая прежнюю версию схемы.
func (p *RolePolicyWriters) InstalledUserAccessLabels(ctx context.Context) (kaname.UserAccessLabelsWriter, error) {
	if p == nil || p.policy == nil || p.ValidateFor(p.shared, p.policy.bundle) != nil {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	var installed bool
	err := pgx.BeginTxFunc(ctx, p.policy.repo.master, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := lockMetadataAuthority(ctx, tx); err != nil {
			return err
		}
		var verified bool
		if err := tx.QueryRow(ctx, userReadinessCatalogSQL).Scan(&installed, &verified); err != nil {
			return err
		}
		if !installed {
			return nil
		}
		if !verified {
			return kaname.ErrSemanticIdentityUnavailable
		}
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT current_user=session_user
            AND kaname.authority_role_actor_pair_ready_v1($1::oid,$2::text)
            AND kaname.authority_metadata_user_access_label_ready_v1()`, p.runtimeOID, p.runtimeName).Scan(&ready); err != nil {
			return err
		}
		if !ready {
			return kaname.ErrSemanticIdentityUnavailable
		}
		return nil
	})
	if err != nil {
		return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	if !installed {
		return nil, nil
	}
	if err := p.policy.repo.ValidateFullAuthorityBundle(ctx, p.policy.bundle); err != nil {
		return nil, err
	}
	return &userAccessLabelsWriter{factory: &MetadataMutationWriters{policy: p.policy}}, nil
}
