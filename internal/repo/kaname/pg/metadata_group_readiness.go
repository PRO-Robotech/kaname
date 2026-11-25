// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Отпечатки тел из 20261128008000 закреплены в бинарном клиенте. Даже функция
// с корректным именем и типом результата не может сама подтвердить своё тело.
const groupReadinessCatalogSQL = `
WITH root AS (
    SELECT c.relowner, n.oid AS namespace
    FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_class c ON c.relnamespace=n.oid
    WHERE n.nspname='kaname' AND c.relname='authority_writer_protocol'
      AND c.relowner=n.nspowner AND c.relkind='r' AND c.relpersistence='p'
), expected(signature, digest, result, argnames, definer) AS (
    VALUES
        ('kaname.authority_metadata_group_access_label_ready_v1()',
         '042cf9e049cf12002f88b4b6bb5c45907a957e755f056f636dfc20d842b09ac3',
         'pg_catalog.bool', NULL::text[], true),
        ('kaname._authority_metadata_group_exports_v1(oid,boolean)',
         '3234dd763c77c78dee8e3cd67984b6de014fd56bf43219a43146bbd4b01ce456',
         'pg_catalog.regprocedure[]', ARRAY['p_runtime','p_require_private'], false)
), verified AS (
    SELECT p.oid
    FROM expected e JOIN pg_catalog.pg_proc p ON p.oid=pg_catalog.to_regprocedure(e.signature)
    JOIN root r ON p.pronamespace=r.namespace AND p.proowner=r.relowner
    JOIN pg_catalog.pg_language l ON l.oid=p.prolang AND l.lanname='plpgsql'
    WHERE p.prokind='f' AND p.prosecdef=e.definer AND p.provolatile='s' AND p.proparallel='u'
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
                            (NOT e.definer OR a.grantee=0 OR a.grantor<>p.proowner OR a.is_grantable))
      AND (NOT e.definer OR EXISTS (SELECT FROM pg_catalog.aclexplode(p.proacl) a
                                    WHERE a.grantee=session_user::regrole AND a.privilege_type='EXECUTE'))
), installed AS (
    SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='kaname' AND (
        p.proname IN ('authority_metadata_group_access_label_ready_v1',
                      '_authority_metadata_group_exports_v1','_authority_metadata_group_grant_v1')
        OR (p.proname IN ('authority_metadata_group_prepare_v1','authority_metadata_group_retention_inputs_v1',
                          'authority_metadata_group_reserve_v1','authority_metadata_group_ordinary_reserve_v1',
                          'authority_metadata_group_accept_v1','authority_metadata_group_write_v1')
            AND (pg_catalog.has_function_privilege(p.oid,'EXECUTE') OR EXISTS (
                SELECT FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
                WHERE a.grantee<>p.proowner))))
)
SELECT NOT EXISTS (SELECT FROM root) OR EXISTS (SELECT FROM installed),
       (SELECT count(*) FROM verified)=2`

// WithInstalledGroupAccessLabels подключает Group-порт к подтверждённому FULL
// контракту. Старые установки с закрытыми фасадами сохраняют обычные маски.
func (p *MetadataMutationWriters) WithInstalledGroupAccessLabels(ctx context.Context) (kaname.GroupAccessLabelsWriterFactory, error) {
	if p == nil || p.policy == nil || !p.policy.repo.fullContractMatches(p.policy.bundle) {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	pool := p.policy.repo.master
	var installed bool
	err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := lockMetadataAuthority(ctx, tx); err != nil {
			return err
		}
		var verified bool
		if err := tx.QueryRow(ctx, groupReadinessCatalogSQL).Scan(&installed, &verified); err != nil {
			return err
		}
		if !installed {
			return nil
		}
		if !verified {
			return kaname.ErrSemanticIdentityUnavailable
		}
		var ready bool
		if err := tx.QueryRow(ctx, `SELECT kaname.authority_metadata_group_access_label_ready_v1()`).Scan(&ready); err != nil {
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
	return &groupAccessLabelMetadataWriters{
		&serviceAccountAccessLabelMetadataWriters{&accessLabelMetadataWriters{p}},
	}, nil
}
