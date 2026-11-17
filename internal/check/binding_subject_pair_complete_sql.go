// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"
	"strings"
)

// Закрытые SQL формы — не parser и не исключения по имени файла/константы.
// Сравнивается весь token stream, включая корреляцию, OR/UNION, вторую ветвь,
// параметры и paging predicate. Незнакомый CTE, shadow alias, дополнительный
// фильтр или тот же счётчик пары с испорченным набором не получают proof.
//
//  1. Actor carriers: primary OR EXISTS всего child set, одинаковый binding_id,
//     speaker array и wildcard/system_class ветви. Остальные UNION не сужают его.
//  2. Mutation carriers: group primary OR child match; в output есть primary
//     guard и все child guards через JOIN того же carriers binding.
//  3. Old binding: primary и все children одного $3 через UNION ALL.
//
// Эти три программы применяются только через точный complete paging consumer.
var bindingPairCompleteSQLPrograms = []string{
	`WITH carriers AS (
 SELECT b.* FROM kaname.access_bindings b
 WHERE b.status IN ('ACTIVE','PENDING') AND b.revoked_at IS NULL AND (b.expires_at IS NULL OR b.expires_at>transaction_timestamp())
 AND (b.subject_type||':'||b.subject_id=ANY($3::text[]) OR b.subject_id='*' OR b.subject_type='system_class'
 OR EXISTS(SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id AND (s.subject_type||':'||s.subject_id=ANY($3::text[]) OR s.subject_id='*' OR s.subject_type='system_class')))
), source_rows AS (
 SELECT 'binding:'||b.id key,coalesce(kaname.authority_protocol_row_account('access_bindings',to_jsonb(b)),'') account,
 CASE WHEN b.role_id IS NULL THEN '' ELSE 'role:'||b.role_id END guard,
 ((kaname.authority_protocol_row_account('access_bindings',to_jsonb(b)) IS NULL AND b.resource_type<>'cluster') OR b.resource_type NOT IN ('account','project','cluster') OR (b.role_id IS NOT NULL AND r.id IS NULL)
 OR (b.target->'resources' IS NOT NULL AND b.target->'resources'<>'[]'::jsonb)
 OR EXISTS(SELECT 1 FROM kaname.role_rule_selectors s WHERE s.role_id=b.role_id AND (s.arm<>'anchor' OR s.container_type IS NOT NULL))
 OR EXISTS(SELECT 1 FROM kaname.role_bind_role_rule s WHERE s.role_id=b.role_id)) global
 FROM carriers b LEFT JOIN kaname.roles r ON r.id=b.role_id
 UNION ALL SELECT 'role:'||b.id,coalesce(kaname.authority_protocol_row_account('roles',to_jsonb(r)),''),'',b.role_id IS NOT NULL AND r.id IS NULL FROM carriers b LEFT JOIN kaname.roles r ON r.id=b.role_id
 UNION ALL SELECT 'identity:user:'||u.id,coalesce(u.account_id,''),'',false FROM kaname.users u WHERE $4='user' AND u.id=$5
 UNION ALL SELECT 'identity:service_account:'||s.id,s.account_id,'',false FROM kaname.service_accounts s WHERE $4='service_account' AND s.id=$5
 UNION ALL SELECT 'owner:'||a.id,a.id,'',false FROM kaname.accounts a WHERE $4='user' AND a.owner_user_id=$5
 UNION ALL SELECT 'delegation:'||d.id,d.account_id,'',false FROM kaname.grant_delegations d WHERE $4='service_account' AND d.delegate_id=$5
 UNION ALL SELECT 'creator:'||s.id,s.account_id,'service_account:'||s.id,false FROM kaname.service_accounts s WHERE s.created_by_type=$4 AND s.created_by_id=$5
 UNION ALL SELECT 'cluster:'||g.id,'','',false FROM kaname.cluster_admin_grants g WHERE g.subject_type=$4 AND g.subject_id=$5 AND (g.granted_until IS NULL OR g.granted_until>transaction_timestamp())
 UNION ALL SELECT 'receipt:'||jsonb_build_array(r.kind,r.module,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id)::text,'','',false
 FROM kaname.producer_source_receipt r WHERE r.active AND ((r.kind='registration_owner' AND r.subject_type=$4 AND r.subject_id=$5) OR r.kind='publication')
) SELECT key,account,guard,coalesce(global,true) FROM source_rows WHERE key COLLATE "C">$1 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $2`,
	`WITH carriers AS (
 SELECT b.* FROM kaname.access_bindings b WHERE ($3<>'' AND b.role_id=$3) OR ($4<>'' AND
 ((b.subject_type='group' AND b.subject_id=$4) OR EXISTS(SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id AND s.subject_type='group' AND s.subject_id=$4)))
), source_rows AS (
 SELECT 'write:binding:'||b.id key,coalesce(kaname.authority_protocol_row_account('access_bindings',to_jsonb(b)),'') account,
 b.subject_type||':'||b.subject_id guard,kaname.authority_protocol_row_account('access_bindings',to_jsonb(b)) IS NULL OR b.resource_type NOT IN ('account','project') OR b.subject_id='*' global FROM carriers b
 UNION ALL SELECT 'write:subject:'||s.binding_id||':'||s.subject_type||':'||s.subject_id,'',s.subject_type||':'||s.subject_id,false FROM kaname.access_binding_subjects s JOIN carriers b ON b.id=s.binding_id
 UNION ALL SELECT 'role:'||b.id,coalesce(kaname.authority_protocol_row_account('roles',to_jsonb(r)),''),'role:'||r.id,r.id IS NULL
 OR EXISTS(SELECT 1 FROM kaname.role_rule_selectors s WHERE s.role_id=r.id AND (s.arm<>'anchor' OR s.container_type IS NOT NULL)) FROM carriers b LEFT JOIN kaname.roles r ON r.id=b.role_id
) SELECT key,account,coalesce(guard,''),coalesce(global,true) FROM source_rows WHERE key COLLATE "C">$1 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $2`,
	`WITH source_rows AS (
 SELECT 'write:primary:'||id key,''::text account,subject_type||':'||subject_id guard,subject_id='*' global FROM kaname.access_bindings WHERE id=$3
 UNION ALL SELECT 'write:secondary:'||subject_type||':'||subject_id,'',subject_type||':'||subject_id,false FROM kaname.access_binding_subjects WHERE binding_id=$3
 UNION ALL SELECT 'carrier:'||role_id,'','carrier_latch:role:'||role_id,false FROM kaname.access_bindings WHERE id=$3 AND role_id IS NOT NULL
 UNION ALL SELECT 'role:'||role_id,'','role:'||role_id,false FROM kaname.access_bindings WHERE id=$3 AND role_id IS NOT NULL
) SELECT key,account,guard,global FROM source_rows WHERE key COLLATE "C">$1 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $2`,
}

func bindingPairCompleteSQL(raw string) bool {
	if !strings.Contains(strings.ToLower(raw), "access_bindings") {
		return false
	}
	tokens := sqlTokens(raw)
	for _, expected := range bindingPairCompleteSQLPrograms {
		if bindingPairSQLTokensEqual(tokens, sqlTokens(expected)) {
			return true
		}
	}
	return false
}

// Consumer проверяется по всей структуре тела; имя метода не является
// разрешением. Завершение только после count<limit, error paths не выдают allow,
// каждый row сканируется/добавляется, cursor продвигается по key, SQL не меняется.
const bindingPairCompleteScanBody = `{
	after := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		limit := min(policyDiscoveryPage, policyDiscoveryRows-p.rows+1)
		params := append([]any{after, limit}, args...)
		if p.nativeBudget != nil {
			if err := chargeNativePolicyBudget(p.nativeBudget, 0, 1); err != nil {
				return err
			}
		}
		rows, err := tx.Query(ctx, query, params...)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			var key, account, guard string
			var global bool
			if err = rows.Scan(&key, &account, &guard, &global); err != nil {
				rows.Close()
				return err
			}
			if p.nativeBudget != nil {
				if err = chargeNativePolicyBudget(p.nativeBudget, 1, 0); err != nil {
					rows.Close()
					if p.rows >= policyDiscoveryRows {
						return errors.Join(err, errPolicyDiscoveryBudget)
					}
					return err
				}
			}
			p.rows++
			count++
			if p.rows > policyDiscoveryRows {
				rows.Close()
				return errPolicyDiscoveryBudget
			}
			if key <= after {
				rows.Close()
				return fmt.Errorf("non-monotonic policy discovery cursor")
			}
			after = key
			p.add(account, guard, global)
			if strings.HasPrefix(key, "write:") {
				p.write(guard)
				if account != "" {
					p.write("scope:" + account)
				}
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if count < limit {
			return nil
		}
	}
}`

var bindingPairGroupSQLPrograms = []string{
	`SELECT b.id,b.resource_type,b.resource_id,b.role_id FROM kaname.access_bindings b WHERE b.subject_type='group' AND b.subject_id=$1 AND b.id COLLATE "C">$2 COLLATE "C" ORDER BY b.id COLLATE "C" LIMIT $3`,
	`SELECT b.id,b.resource_type,b.resource_id,b.role_id FROM kaname.access_binding_subjects s JOIN kaname.access_bindings b ON b.id=s.binding_id WHERE s.subject_type='group' AND s.subject_id=$1 AND b.id COLLATE "C">$2 COLLATE "C" ORDER BY b.id COLLATE "C" LIMIT $3`,
}

// У array две реальные Query-фазы, обе со своим полным cursor loop. Этот
// закрытый AST shape запрещает range [:1], условный пропуск phase, ранний
// успешный выход, замену query и урезание rows.Next. Имена local binders здесь
// намеренно фиксированы; любое unsupported переписывание требует нового proof.
const bindingPairGroupRange = `for phase, query := range _queries {
		after := ""
		for {
			if err := ctx.Err(); err != nil {
				return nil, total, err
			}
			if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
				return nil, total, err
			}
			rows, err := tx.Query(ctx, query, string(m.GroupID), after, policyDiscoveryPage)
			if err != nil {
				return nil, total, err
			}
			count := 0
			for rows.Next() {
				if err = ctx.Err(); err != nil {
					rows.Close()
					return nil, total, err
				}
				var b domain.AccessBinding
				if err = rows.Scan(&b.ID, &b.ResourceType, &b.ResourceID, &b.RoleID); err != nil {
					rows.Close()
					return nil, total, err
				}
				physical := 1 + phase // дополнительная строка subjects плюс header.
				if err = chargeNativePolicyBudget(budget, physical, 0); err != nil {
					rows.Close()
					return nil, total, err
				}
				total += physical
				count++
				if string(b.ID) <= after {
					rows.Close()
					return nil, total, kaname.ErrCanonicalSourceInvalid
				}
				after = string(b.ID)
				if err = questions.groupCarrier(actor, b); err != nil {
					rows.Close()
					return nil, total, err
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, total, err
			}
			if err = ctx.Err(); err != nil {
				return nil, total, err
			}
			if count < policyDiscoveryPage {
				break
			}
		}
	}`

func bindingPairGroupSQLProofs(files []*ast.File, info *types.Info) map[token.Pos]bool {
	out := map[token.Pos]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
					continue
				}
				variable, ok := info.Defs[value.Names[0]].(*types.Var)
				if !ok || variable.Exported() {
					continue
				}
				array, ok := value.Values[0].(*ast.CompositeLit)
				if !ok || len(array.Elts) != 2 {
					continue
				}
				arrayType, ok := info.TypeOf(array).Underlying().(*types.Array)
				if !ok || arrayType.Len() != 2 || !types.Identical(arrayType.Elem(), types.Typ[types.String]) {
					continue
				}
				var literals [2]*ast.BasicLit
				for i, element := range array.Elts {
					lit, ok := element.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						break
					}
					raw, err := strconv.Unquote(lit.Value)
					if err != nil || !bindingPairSQLTokensEqual(sqlTokens(raw), sqlTokens(bindingPairGroupSQLPrograms[i])) {
						break
					}
					literals[i] = lit
				}
				if literals[1] == nil {
					continue
				}
				var use *ast.Ident
				uses := 0
				for id, object := range info.Uses {
					if object == variable {
						use = id
						uses++
					}
				}
				if uses != 1 {
					continue
				}
				for _, consumer := range files {
					ast.Inspect(consumer, func(node ast.Node) bool {
						loop, ok := node.(*ast.RangeStmt)
						if !ok || loop.X != use {
							return true
						}
						candidate := *loop
						candidate.X = ast.NewIdent("_queries")
						if bindingPairGoShape(&candidate, bindingPairGroupRange) && bindingPairHasTypedQuery(loop, info) {
							out[literals[0].Pos()], out[literals[1].Pos()] = true, true
						}
						return false
					})
				}
			}
		}
	}
	return out
}
