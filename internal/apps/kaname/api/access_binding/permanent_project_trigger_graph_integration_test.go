// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// verifies https://github.com/PRO-Robotech/kaname/issues/983
// Conservative installed-schema gate for the reviewed trigger call graph. This
// is a change detector, not a general SQL parser or an administrator DDL sandbox.

import (
    "regexp"
    "strings"
    "testing"

    "github.com/stretchr/testify/require"
)

func TestPermanentProjectCommand_InstalledTriggerGraphIsClosed(t *testing.T){
    w:=newPPWorld(t)
    type fn struct{name,body,language string}
    funcs:=map[uint32]fn{}
    byName:=map[string][]uint32{}
    rows,err:=w.pool.Query(w.ctx,`SELECT p.oid,p.proname,p.prosrc,l.lanname FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.prokind='f'`)
    require.NoError(t,err)
    for rows.Next(){var oid uint32;var f fn;require.NoError(t,rows.Scan(&oid,&f.name,&f.body,&f.language));funcs[oid]=f;byName[f.name]=append(byName[f.name],oid)}
    require.NoError(t,rows.Err());rows.Close()
    var roots []uint32
    rows,err=w.pool.Query(w.ctx,`SELECT DISTINCT tgfoid FROM pg_trigger WHERE NOT tgisinternal`)
    require.NoError(t,err)
    for rows.Next(){var oid uint32;require.NoError(t,rows.Scan(&oid));roots=append(roots,oid)}
    require.NoError(t,rows.Err());rows.Close()
    stripComments:=regexp.MustCompile(`(?s)/\*.*?\*/|(?m)--[^\n]*`)
    calls:=regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\s*\(`)
    writes:=regexp.MustCompile(`(?i)\b(?:insert\s+into|update|delete\s+from|merge\s+into)\s+(?:only\s+)?(?:kaname\.)?resource_(?:mirror|parent_edge)\b`)
    // The only reviewed dynamic SQL reachable from existing triggers: reads of
    // fixed trigger-argument relations. Any new EXECUTE requires explicit review.
    dynamicReads:=regexp.MustCompile(`(?is)EXECUTE\s+format\(\s*'(?:SELECT to_jsonb\(t\) FROM kaname\.%I t WHERE t\.id = \$1|SELECT count\(\*\) FROM %I\.%I WHERE %I = \$1 AND id <> \$2)'[^;]*;`)
    dynamic:=regexp.MustCompile(`(?i)\bEXECUTE\b`)
    seen:=map[uint32]bool{}
    for len(roots)>0{
        oid:=roots[0];roots=roots[1:]
        if seen[oid]{continue};seen[oid]=true
        f,ok:=funcs[oid];require.True(t,ok,"unreviewed trigger function oid %d",oid)
        body:=stripComments.ReplaceAllString(f.body,"")
        require.Contains(t,[]string{"plpgsql","sql"},f.language,"unreviewed callback language: "+f.name)
        require.NotEqual(t,"rename_cluster_anchor",f.name,"dynamic rename must never become trigger-reachable")
        if writes.MatchString(body){require.Equal(t,"resource_registration_command_apply",f.name,"unchecked incoming physical writer")}
        require.False(t,dynamic.MatchString(dynamicReads.ReplaceAllString(body,"")),"unreviewed dynamic callback in "+f.name)
        for _,call:=range calls.FindAllStringSubmatch(body,-1){roots=append(roots,byName[strings.ToLower(call[1])]...)}
    }
    var bad int
    require.NoError(t,w.pool.QueryRow(w.ctx,`SELECT count(*) FROM pg_constraint WHERE contype='f'
        AND conrelid IN ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass)`).Scan(&bad))
    require.Zero(t,bad,"incoming FK actions require a new graph proof")
    require.NoError(t,w.pool.QueryRow(w.ctx,`SELECT count(*) FROM pg_rewrite WHERE ev_class IN
        ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass)`).Scan(&bad))
    require.Zero(t,bad,"physical rewrite callbacks are not part of the approved graph")
    require.NoError(t,w.pool.QueryRow(w.ctx,`SELECT count(*) FROM pg_class WHERE oid IN
        ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass,'kaname.resource_registration_command'::regclass)
        AND (relrowsecurity OR relforcerowsecurity)`).Scan(&bad))
    require.Zero(t,bad,"RLS callbacks require a new graph proof")
    require.NoError(t,w.pool.QueryRow(w.ctx,`SELECT count(*) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
        WHERE t.tgrelid IN ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass)
        AND NOT t.tgisinternal AND p.proname NOT IN ('resource_mirror_keeps_the_bound_project','resource_parent_edge_keeps_the_bound_project')`).Scan(&bad))
    require.Zero(t,bad,"no observable callback may precede complete command validation")
    require.NoError(t,w.pool.QueryRow(w.ctx,`SELECT count(*) FROM pg_constraint WHERE conrelid IN
        ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass)
        AND pg_get_constraintdef(oid) LIKE '%kaname.%'`).Scan(&bad))
    require.Zero(t,bad,"physical checks must remain built-in expressions, without custom callbacks")
}
