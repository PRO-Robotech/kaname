// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
    "context"
    "fmt"
    "reflect"
    "strings"
    "testing"

    "github.com/jackc/pgx/v5"
    "github.com/PRO-Robotech/kaname/internal/hierarchy"
    "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

type listParentParityRow struct { Type, ID string; Depth int }

// Извлекается production scope И его production min-depth dedup. У эталона
// заменяется только чтение родителей, а не рекурсия или алгоритм дедупликации.
func listParentParityStatements(t *testing.T) (string,string) {
    t.Helper()
    sql:=relverdict.ListQuerySQLForTest("")
    const start="        WITH RECURSIVE scope(s_type, s_id, depth) AS ("
    const end="        SELECT EXISTS ("
    if strings.Count(sql,start)!=1 || strings.Count(sql,end)!=1 {t.Fatal("production List scope anchors changed")}
    a,b:=strings.Index(sql,start),strings.Index(sql,end)
    if a>=b {t.Fatal("production scope anchor order changed")}
    scope:=sql[a:b]
    if strings.Count(scope,"SELECT $2::text, c.object_id, 0")!=1 || strings.Count(scope,"c.object_id")!=1 || strings.Count(scope,"scope_distinct(s_type, s_id, depth) AS (")!=1 {t.Fatal("production scope seed/dedup shape changed")}
    const lateral="              CROSS JOIN LATERAL (\n"
    const close="                   ) e\n"
    if strings.Count(scope,lateral)!=1 || strings.Count(scope,close)!=1 {t.Fatal("parent lookup is not uniquely extractable")}
    first:=strings.Index(scope,lateral)+len(lateral)
    last:=strings.Index(scope,close)
    if first>=last {t.Fatal("parent lookup anchor order changed")}
    canonical:=scope[:first]+`                     SELECT pe.parent_type, pe.parent_id
                       FROM kaname.resource_scope_edge pe
                      WHERE pe.object_type = s.s_type AND pe.object_id = s.s_id
                      ORDER BY pe.depth
                      LIMIT $12::int
`+scope[last:]
    adapt:=func(text string)string{
        // Корень подставляется ПОСЛЕ перенумерации исходного $2-типа:
        // иначе новый $2-корень превратился бы в $1-тип.
        text=strings.NewReplacer("$12::int","$4::int","$5::int","$3::int","$2::text","$1::text").Replace(text)
        text=strings.Replace(text,"c.object_id","$2::text",1)
        return text+"SELECT s_type,s_id,depth FROM scope_distinct ORDER BY s_type,s_id"
    }
    return adapt(scope),adapt(canonical)
}

func listParentParityRead(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args ...any) []listParentParityRow {
    t.Helper()
    rows,err:=tx.Query(ctx,sql,args...)
    if err!=nil {t.Fatal(err)}
    defer rows.Close()
    var out []listParentParityRow
    for rows.Next() {
        var r listParentParityRow
        if err:=rows.Scan(&r.Type,&r.ID,&r.Depth);err!=nil {t.Fatal(err)}
        out=append(out,r)
    }
    if err:=rows.Err();err!=nil {t.Fatal(err)}
    return out
}

func TestListParentLookupMatchesCanonicalScopeView(t *testing.T) {
    if testing.Short() {t.Skip("integration: PostgreSQL")}
    actual,canonical:=listParentParityStatements(t)
    // Существующие helpers дают30s TX, независимый5s rollback и bounded pool cleanup.
    h:=newReportSeed(t)
    h.transaction(t,false,func(ctx context.Context,tx pgx.Tx){
        seedTenant(t,ctx,tx)
        r74SeedFiveOwnObjects(t,ctx,tx)
        exec(t,ctx,tx,`INSERT INTO kaname.roles(id,name,permissions,rules,project_id)
          VALUES('rol-parity-project','parity_project','[]'::jsonb,
           '[{"module":"test","resources":["*"],"verbs":["get"]}]'::jsonb,'prj-1')`)
        r74SeedBinding(t,ctx,tx,"acb-parity-account","usr-1",r74InertRole,"account","acc-1")
        r74SeedBinding(t,ctx,tx,"acb-parity-cluster","usr-1",r74InertRole,"cluster","cluster_root")
        r74SeedBinding(t,ctx,tx,"acb-parity-resource","usr-1",r74InertRole,"vpc_network","net-parity")
        r74SeedBinding(t,ctx,tx,"acb-parity-any","usr-1",r74InertRole,"*","*")
        type rootCase struct { name,typ,id string; parents []listParentParityRow }
        cases:=[]rootCase{
            {"project fact","project","prj-1",[]listParentParityRow{{"account","acc-1",1}}},
            {"account cross cluster","account","acc-1",[]listParentParityRow{{"cluster","cluster_root",1}}},
            {"user membership","iam_user","usr-own",[]listParentParityRow{{"account","acc-1",1}}},
            {"group account","iam_group","grp-own",[]listParentParityRow{{"account","acc-1",1}}},
            {"service account","iam_service_account","sac-own",[]listParentParityRow{{"account","acc-1",1}}},
            {"role account branch","iam_role","rol-own",[]listParentParityRow{{"account","acc-1",1}}},
            {"role project branch","iam_role","rol-parity-project",[]listParentParityRow{{"project","prj-1",1}}},
            {"binding project","iam_access_binding","acb-own",[]listParentParityRow{{"project","prj-1",1}}},
            {"binding account","iam_access_binding","acb-parity-account",[]listParentParityRow{{"account","acc-1",1}}},
            {"binding cluster","iam_access_binding","acb-parity-cluster",[]listParentParityRow{{"cluster","cluster_root",1}}},
            {"binding resource refused","iam_access_binding","acb-parity-resource",nil},
            {"binding wildcard refused","iam_access_binding","acb-parity-any",nil},
            {"unsupported empty","parity_unknown","empty",nil},
        }
        immediate:=func(typ,id string)[]listParentParityRow{
            return listParentParityRead(t,ctx,tx,`SELECT parent_type,parent_id,depth
              FROM kaname.resource_scope_edge WHERE object_type=$1 AND object_id=$2
              ORDER BY parent_type,parent_id,depth`,typ,id)
        }
        compare:=func(typ,id string)[]listParentParityRow{
            args:=[]any{typ,id,hierarchy.MaxPointerHops,hierarchy.MaxImmediateParents}
            got:=listParentParityRead(t,ctx,tx,actual,args...)
            want:=listParentParityRead(t,ctx,tx,canonical,args...)
            if !reflect.DeepEqual(got,want) {t.Fatalf("%s:%s production=%v canonical=%v",typ,id,got,want)}
            roots:=0;seen:=map[string]bool{}
            for _,row:=range got {
                key:=row.Type+"\x00"+row.ID
                if seen[key] || row.Depth<0 || row.Depth>5 {t.Fatalf("dedup/depth violated: %v",got)}
                seen[key]=true
                if row.Type==typ && row.ID==id && row.Depth==0 {roots++}
            }
            if roots!=1 {t.Fatalf("%s:%s depth-zero root count=%d",typ,id,roots)}
            return got
        }
        roleParents:=0
        for _,c:=range cases {
            // Без этой предпосылки физические рёбра могли бы скрыть мёртвую
            // fallback-ветвь. Положительная и отрицательная части разделены.
            if n:=countScalar(t,ctx,tx,`SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type=$1 AND object_id=$2`,c.typ,c.id);n!=0 {t.Fatalf("%s masked by %d physical edges",c.name,n)}
            got:=immediate(c.typ,c.id)
            if !reflect.DeepEqual(got,c.parents) {t.Fatalf("%s fallback precondition=%v expected=%v",c.name,got,c.parents)}
            scope:=compare(c.typ,c.id)
            if c.typ=="iam_role" {roleParents+=len(got)}
            if c.id=="rol-parity-project" {
                found:=false
                for _,row:=range scope {if row.Type=="account" && row.ID=="acc-1" && row.Depth==2 {found=true}}
                if !found {t.Fatal("project role did not reach account through project")}
            }
            if len(c.parents)==0 && len(scope)!=1 {t.Fatalf("unsupported root acquired ancestors: %v",scope)}
        }
        // XOR схемы запрещает одну роль с обоими владельцами. Здесь ДВЕ
        // легальные роли, по одной строке родителя у каждой, суммарно две.
        if roleParents!=2 {t.Fatalf("two lawful role roots have %d immediate parents instead of2",roleParents)}
        // Прямые рёбра — SQL-boundary fixture как у существующей hierarchy
        // пробы; это не заявление о production writer для собственных iam типов.
        // По одному ребру depth4: неполный fanout НЕ разрешает top-up fallback.
        for _,c:=range cases[:10] {
            parent:="physical-"+c.id
            exec(t,ctx,tx,`INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
              VALUES($1,$2,'parity_leaf',$3,4)`,c.typ,c.id,parent)
            want:=[]listParentParityRow{{"parity_leaf",parent,4}}
            if got:=immediate(c.typ,c.id);!reflect.DeepEqual(got,want) {t.Fatalf("physical override %s canonical=%v expected=%v",c.name,got,want)}
            scope:=compare(c.typ,c.id)
            if len(scope)!=2 {t.Fatalf("physical override topped up %s: %v",c.name,scope)}
            leaf:=false;for _,row:=range scope {if row.Type=="parity_leaf" && row.ID==parent && row.Depth==1 {leaf=true}}
            if !leaf {t.Fatal("stored depth must not replace recursive step depth")}
        }
        edge:=func(id,parent string,depth int){exec(t,ctx,tx,`INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth) VALUES('parity_unknown',$1,'parity_unknown',$2,$3)`,id,parent,depth)}
        for i:=0;i<6;i++ {edge(fmt.Sprintf("hop%d",i),fmt.Sprintf("hop%d",i+1),1)}
        hops:=compare("parity_unknown","hop0")
        if len(hops)!=6 {t.Fatalf("fivehop boundary=%v",hops)}
        for i:=1;i<=4;i++ {edge("fanout",fmt.Sprintf("parent%d",i),i)}
        if got:=compare("parity_unknown","fanout");len(got)!=5 {t.Fatalf("fourparent boundary=%v",got)}
        edge("diamond","a",1);edge("diamond","b",2);edge("diamond","shared",3)
        edge("a","shared",1);edge("b","shared",1)
        diamond:=compare("parity_unknown","diamond")
        if len(diamond)!=4 {t.Fatalf("multipath dedup=%v",diamond)}
        found:=false;for _,row:=range diamond {if row.ID=="shared" && row.Depth==1 {found=true}}
        if !found {t.Fatalf("minimum depth lost: %v",diamond)}
        t.Log("canonical List parent parity: all8fallbackbranches, two lawful role roots, restricted binding scopes, physical suppression, unsupported, fivehop/fourparent and minDepth checked")
    })
}
