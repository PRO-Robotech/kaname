// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

const policyDiscoveryPage = 256
const policyDiscoveryRows = 100000
const policyDiscoveryGuards = 4096

var errPolicyDiscoveryBudget = errors.New("policy source discovery budget exceeded")

// Все поля private: это план замков, не bearer-proof полномочий. A может
// сформировать запрос в том же pg package и использовать собственную RR TX.
// owners содержат OLD/NEW ownerrefs; дополнительные account scopes из stage
// защищаются её собственным epoch token, не считаются здесь доказанными.
type policyWriteRequest struct {
	actor              domain.Subject
	kind               kaname.AuthorityOperation
	owners             []kaname.AuthorityOwnerRef
	roleID             domain.RoleID
	groupID            domain.GroupID
	mutationSubjects   []domain.Subject
	readRoles          []domain.RoleID
	additionalAccounts []domain.AccountID
	global             bool
	nativeQuestions    *nativePolicyQuestions
	consumedReads      int
	roleNative         *roleNativeRequest
	groupNative        *groupAdditionNativeRequest
}

type policyPlan struct {
	request        policyWriteRequest
	accounts       map[string]bool
	guards         map[string]bool
	exclusive      map[string]bool
	global         bool
	rows           int
	epochs         json.RawMessage
	native         *nativeReadBoundary
	nativeBudget   *relverdict.AdministrativeReadBudget
	producers      *producerPopulationCapture
	groupReference *groupAdditionReferenceWitness
}

func (p *policyPlan) add(account, guard string, global bool) {
	if account != "" {
		p.accounts[account] = true
		p.guards["scope:"+account] = true
	}
	if guard != "" {
		p.guards[guard] = true
	}
	p.global = p.global || global || len(p.accounts) > kaname.MaxAuthorityFenceAccounts || len(p.guards) > policyDiscoveryGuards
}
func (p *policyPlan) write(key string) {
	if key == "" {
		return
	}
	if p.exclusive == nil {
		p.exclusive = map[string]bool{}
	}
	p.exclusive[key] = true
	p.guards[key] = true
	p.global = p.global || len(p.guards) > policyDiscoveryGuards
}

// accountOwners сохраняет реальные OLD/NEW refs и дополняет их account anchors
// всего source footprint. SQL entry проверяет discover(refs) == Plan.Accounts;
// одних mutation refs недостаточно для foreign actor/native/receipt sources.
func (p *policyPlan) accountOwners() ([]kaname.AuthorityOwnerRef, bool) {
	owners := make([]kaname.AuthorityOwnerRef, 0, len(p.request.owners)+len(p.accounts))
	seen := make(map[kaname.AuthorityOwnerRef]bool)
	for _, ref := range p.request.owners {
		if !seen[ref] {
			owners = append(owners, ref)
			seen[ref] = true
		}
	}
	accounts := make([]string, 0, len(p.accounts))
	for account := range p.accounts {
		accounts = append(accounts, account)
	}
	slices.Sort(accounts)
	for _, account := range accounts {
		ref := kaname.AuthorityOwnerRef{Kind: "account", ID: account}
		if !seen[ref] {
			owners = append(owners, ref)
			seen[ref] = true
		}
	}
	return owners, len(owners) <= kaname.MaxAuthorityOwnershipRefs
}

// Вызывается до чтения epoch token и до любого fence. Overflow требует именно
// global root token; нельзя повысить только coordinator mode после discovery.
func (p *policyPlan) finishClassification() {
	_, fits := p.accountOwners()
	p.global = p.global || len(p.accounts) == 0 || !fits
}

func (p *policyPlan) intent(bundle *granteffect.Bundle) kaname.AuthorityWriteIntent {
	in := kaname.AuthorityWriteIntent{Kind: p.request.kind, Owners: append([]kaname.AuthorityOwnerRef{}, p.request.owners...), Bundle: bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	owners, fits := p.accountOwners()
	if !p.global && len(p.accounts) > 0 && fits {
		in.Owners = owners
		in.Plan.Mode = kaname.AuthorityFenceAccounts
		for a := range p.accounts {
			in.Plan.Accounts = append(in.Plan.Accounts, domain.AccountID(a))
		}
		slices.Sort(in.Plan.Accounts)
	}
	return in
}
func subjectPolicyKey(s domain.Subject) string { return string(s.Type) + ":" + string(s.ID) }

// scan не прекращает census при global classification: late SQL error, cancel
// и превышение физически прочитанных строк всегда возвращаются вызывающему.
func (p *policyPlan) scan(ctx context.Context, tx pgx.Tx, query string, args ...any) error {
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
}

// discoverPolicyPlan читает полный ограниченный census до любого fence.
// RR обязателен: набор guard keys и их поколения относятся к одному snapshot.
// Не использует native allow и не меняет original collector completeness.
func (p *GrantPolicyWriters) discoverPolicyPlan(ctx context.Context, tx pgx.Tx, in policyWriteRequest) (*policyPlan, error) {
	return p.discoverPolicyPlanWithRows(ctx, tx, in, 0)
}

// Составной caller/creator census делит один физический бюджет строк.
// Проверка consumed предшествует первому запросу; scan останавливается на
// первой лишней строке, а не после второго полного inventory.
func (p *GrantPolicyWriters) discoverPolicyPlanWithRows(ctx context.Context, tx pgx.Tx, in policyWriteRequest, consumed int) (*policyPlan, error) {
	if consumed < 0 || consumed > policyDiscoveryRows || in.consumedReads < 0 || in.consumedReads > 4096 {
		return nil, errPolicyDiscoveryBudget
	}
	if p == nil || p.repo == nil || tx == nil || in.actor.Validate() != nil || in.actor.ID == "*" || (in.actor.Type != domain.SubjectTypeUser && in.actor.Type != domain.SubjectTypeServiceAccount) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if len(in.readRoles) > kaname.MaxAuthorityOwnershipRefs || len(in.owners) > kaname.MaxAuthorityOwnershipRefs || len(in.mutationSubjects) > policyDiscoveryGuards || len(in.additionalAccounts) > kaname.MaxAuthorityFenceAccounts {
		return nil, errPolicyDiscoveryBudget
	}
	// Предыдущие RR reads входят в тот же бюджет до следующего SQL. У старых
	// callers consumedReads=0; два прежних initial reads считаются как раньше.
	var nativeBudget *relverdict.AdministrativeReadBudget
	if p.captureProducers || in.nativeQuestions != nil || in.roleNative != nil || in.groupNative != nil {
		nativeBudget = &relverdict.AdministrativeReadBudget{}
		if err := chargeNativePolicyBudget(nativeBudget, consumed, 2+in.consumedReads); err != nil {
			return nil, err
		}
	}
	var isolation string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&isolation); err != nil {
		return nil, err
	}
	if isolation != "repeatable read" {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	// ROLE census раскрывает весь carrier scope set в том же RR. Ошибки не
	// превращаются в GLOBAL fallback; cap/late page/cancel завершают попытку.
	if in.roleNative != nil {
		if in.kind != kaname.AuthorityRole || in.nativeQuestions != nil || in.groupNative != nil {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
		questions, rows, err := discoverRoleNativeQuestions(ctx, tx, in.actor, *in.roleNative, nativeBudget)
		if err != nil {
			return nil, err
		}
		in.nativeQuestions = questions
		consumed += rows // уже charged helper-ом; второй charge здесь запрещён.
	}
	// Только полный typed GroupAddition request раскрывает carrier-вопросы.
	// Другие GROUP participant callers не объявляются semantic-bound.
	if in.groupNative != nil {
		if in.kind != kaname.AuthorityGroup || in.nativeQuestions != nil || in.roleNative != nil || in.groupID != in.groupNative.member.GroupID {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
		questions, rows, err := discoverGroupNativeQuestions(ctx, tx, in.actor, *in.groupNative, nativeBudget)
		if err != nil {
			return nil, err
		}
		in.nativeQuestions = questions
		consumed += rows // helper уже начислил эти строки общему budget.
	}
	in, groupReference, referenceRows, err := discoverGroupAdditionReference(ctx, tx, in, nativeBudget)
	if err != nil {
		return nil, err
	}
	consumed += referenceRows // Точное чтение уже начислено helper-ом общему budget.
	plan := &policyPlan{request: in, accounts: map[string]bool{}, guards: map[string]bool{"*": true, subjectPolicyKey(in.actor): true}, global: in.global, rows: consumed, nativeBudget: nativeBudget}
	plan.groupReference = groupReference
	plan.request.owners = slices.Clone(in.owners)
	for _, s := range in.mutationSubjects {
		if s.Validate() != nil {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
		if s.ID == "*" || s.Type == domain.SubjectTypeSystemClass {
			plan.global = true
			continue
		}
		plan.add("", subjectPolicyKey(s), false)
		plan.write(subjectPolicyKey(s))
	}
	for _, a := range in.additionalAccounts {
		if a == "" {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
		plan.add(string(a), "", false)
		plan.write("scope:" + string(a))
	}
	raw, err := json.Marshal(append([]kaname.AuthorityOwnerRef{}, in.owners...))
	if err != nil {
		return nil, err
	}
	var accounts []string
	var global bool
	if err = tx.QueryRow(ctx, `SELECT accounts,global_scope FROM kaname.authority_protocol_discover($1::jsonb)`, raw).Scan(&accounts, &global); err != nil {
		return nil, err
	}
	plan.global = plan.global || global
	for _, a := range accounts {
		plan.add(a, "", false)
		plan.write("scope:" + a)
	}
	// Группа actor и её account сохраняются до конца TX отдельными keys. Новая
	// membership меняет actor key, новый grant текущей группе — group key.
	err = plan.scan(ctx, tx, `SELECT g.id, g.account_id, 'group:'||g.id, false
 FROM kaname.group_members m JOIN kaname.groups g ON g.id=m.group_id
 WHERE m.member_type=$3 AND m.member_id=$4 AND g.id COLLATE "C">$1 COLLATE "C" ORDER BY g.id COLLATE "C" LIMIT $2`, string(in.actor.Type), string(in.actor.ID))
	if err != nil {
		return nil, err
	}
	subjects := []string{subjectPolicyKey(in.actor)}
	for k := range plan.guards {
		if len(k) > 6 && k[:6] == "group:" {
			subjects = append(subjects, k)
		}
	}
	slices.Sort(subjects)
	if err = plan.scan(ctx, tx, policyActorSources, subjects, string(in.actor.Type), string(in.actor.ID)); err != nil {
		return nil, err
	}
	if err = plan.scan(ctx, tx, policyProducerScopes, string(in.actor.Type), string(in.actor.ID)); err != nil {
		return nil, err
	}
	nativeSubjects := slices.Clone(subjects)
	for _, s := range subjects {
		if len(s) > 6 && s[:6] == "group:" {
			nativeSubjects = append(nativeSubjects, "iam_group:"+s[6:]+"#member", s+"#member")
		}
	}
	if err = plan.scan(ctx, tx, policyNativeSources, nativeSubjects, subjects); err != nil {
		return nil, err
	}
	// OLD carrier population, включая pending/revoked/expired, читается целиком:
	// eligibility зависит от будущего decision_at и не может сузить fence план.
	if in.roleID != "" {
		plan.add("", "role:"+string(in.roleID), false)
		plan.write("role:" + string(in.roleID))
		plan.write("carrier_latch:role:" + string(in.roleID))
		plan.write("carriers:role:" + string(in.roleID))
	}
	if in.groupID != "" {
		plan.add("", "group:"+string(in.groupID), false)
		plan.write("group:" + string(in.groupID))
	}
	if in.roleID != "" || in.groupID != "" {
		if err = plan.scan(ctx, tx, policyMutationCarriers, string(in.roleID), string(in.groupID)); err != nil {
			return nil, err
		}
	}
	// Read role не является mutation ownerref: общая system role защищается
	// shared definition guard, не превращая обычную account mutation в GLOBAL.
	readIDs := make([]string, len(in.readRoles))
	for i, id := range in.readRoles {
		if id == "" {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
		readIDs[i] = string(id)
	}
	slices.Sort(readIDs)
	readIDs = slices.Compact(readIDs)
	if len(readIDs) > 0 {
		before := plan.rows
		if in.kind == kaname.AuthorityBinding {
			for _, id := range readIDs {
				plan.add("", "carrier_latch:role:"+id, false)
			}
		}
		if err = plan.scan(ctx, tx, policyReadRoles, readIDs); err != nil {
			return nil, err
		}
		if plan.rows-before != len(readIDs) {
			return nil, kaname.ErrAuthorityClassificationChanged
		}
	}
	// Binding OLD carriers включаются даже если caller передал только NEW subjects.
	for _, o := range in.owners {
		if o.Kind == "binding" {
			if err = plan.scan(ctx, tx, policyOldBindingSubjects, o.ID); err != nil {
				return nil, err
			}
		}
	}
	// Полный native census выполняется в том же RR до единого epoch token.
	if in.nativeQuestions != nil {
		budget := &nativeReadBudget{shared: plan.nativeBudget}
		boundary, err := captureNativeReadBoundary(ctx, p.bundle, in.nativeQuestions, nativePolicyReadSnapshot{tx}, budget)
		if err != nil {
			return nil, err
		}
		plan.native = boundary
		plan.rows += budget.rows
		plan.global = plan.global || boundary.global()
		for account := range boundary.accounts {
			plan.add(account, "", false)
		}
		for guard := range boundary.guards {
			plan.add("", guard, false)
		}
	}
	if p.captureProducers {
		plan.producers, err = captureProducerPopulation(ctx, tx, p.bundle, in.actor, plan.nativeBudget)
		if err != nil {
			return nil, err
		}
	}
	plan.finishClassification()
	keys := []string{"*"}
	// Новая отсутствующая ссылка не отменяет версии остальных RR sources.
	// GLOBAL исключает будущие записи, token обнаруживает уже завершённые.
	if !plan.global || plan.groupReference != nil {
		for k := range plan.guards {
			if k != "*" && !plan.groupReference.excludes(k) {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
	} else if in.groupNative != nil {
		// GLOBAL закрывает будущие записи, но обычный binding не меняет root.
		// Epoch группы связывает RR carrier/questions census с новой RC TX.
		keys = append(keys, "group:"+string(in.groupID))
	}
	if len(keys) > policyDiscoveryGuards {
		return nil, kaname.ErrSourceReadLimit
	}
	// После entry GLOBAL держит root эксклюзивно; group epoch дополнительно
	// обнаруживает изменение population между RR discovery и этим entry.
	if plan.nativeBudget != nil {
		if err = chargeNativePolicyBudget(plan.nativeBudget, len(keys), 1); err != nil {
			return nil, err
		}
	}
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, keys).Scan(&plan.epochs); err != nil {
		return nil, err
	}
	return plan, ctx.Err()
}

// protectPolicyPlan не обнаруживает inventory и не повышает режим. Его можно
// повторить после legacy waits: тот же held guard set и новый decision_at.
func (p *GrantPolicyWriters) protectPolicyPlan(ctx context.Context, w *authorityWriteTx, plan *policyPlan) error {
	if p == nil || w == nil || plan == nil || len(plan.epochs) == 0 {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	want := plan.intent(p.bundle).Plan
	if w.fence.mode != want.Mode || !slices.Equal(w.fence.accounts, want.Accounts) {
		return kaname.ErrAuthorityClassificationChanged
	}
	writes := []string{}
	if !plan.global {
		for k := range plan.exclusive {
			writes = append(writes, k)
		}
		slices.Sort(writes)
	}
	var at time.Time
	if err := w.tx.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_lock_for_write($1::jsonb,$2::text[])`, []byte(plan.epochs), writes).Scan(&at); err != nil {
		return err
	}
	if err := plan.groupReference.recheck(ctx, w, plan.nativeBudget); err != nil {
		return err
	}
	w.fence.decisionAt = at.UTC()
	if plan.producers != nil {
		if err := plan.producers.bind(w, p.bundle, plan.nativeBudget); err != nil {
			return err
		}
	}
	// Captured boundary устанавливается только ПОСЛЕ успешной защиты общего token.
	if plan.native != nil {
		w.nativeRead = &protectedNativeRead{boundary: plan.native, global: plan.global, budget: plan.nativeBudget}
	}
	return ctx.Err()
}

const policyActorSources = `WITH carriers AS (
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
) SELECT key,account,guard,coalesce(global,true) FROM source_rows WHERE key COLLATE "C">$1 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $2`

const policyMutationCarriers = `WITH carriers AS (
 SELECT b.* FROM kaname.access_bindings b WHERE ($3<>'' AND b.role_id=$3) OR ($4<>'' AND
 ((b.subject_type='group' AND b.subject_id=$4) OR EXISTS(SELECT 1 FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id AND s.subject_type='group' AND s.subject_id=$4)))
), source_rows AS (
 SELECT 'write:binding:'||b.id key,coalesce(kaname.authority_protocol_row_account('access_bindings',to_jsonb(b)),'') account,
 b.subject_type||':'||b.subject_id guard,kaname.authority_protocol_row_account('access_bindings',to_jsonb(b)) IS NULL OR b.resource_type NOT IN ('account','project') OR b.subject_id='*' global FROM carriers b
 UNION ALL SELECT 'write:subject:'||s.binding_id||':'||s.subject_type||':'||s.subject_id,'',s.subject_type||':'||s.subject_id,false FROM kaname.access_binding_subjects s JOIN carriers b ON b.id=s.binding_id
 UNION ALL SELECT 'role:'||b.id,coalesce(kaname.authority_protocol_row_account('roles',to_jsonb(r)),''),'role:'||r.id,r.id IS NULL
 OR EXISTS(SELECT 1 FROM kaname.role_rule_selectors s WHERE s.role_id=r.id AND (s.arm<>'anchor' OR s.container_type IS NOT NULL)) FROM carriers b LEFT JOIN kaname.roles r ON r.id=b.role_id
) SELECT key,account,coalesce(guard,''),coalesce(global,true) FROM source_rows WHERE key COLLATE "C">$1 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $2`

const policyOldBindingSubjects = `WITH source_rows AS (
 SELECT 'write:primary:'||id key,''::text account,subject_type||':'||subject_id guard,subject_id='*' global FROM kaname.access_bindings WHERE id=$3
 UNION ALL SELECT 'write:secondary:'||subject_type||':'||subject_id,'',subject_type||':'||subject_id,false FROM kaname.access_binding_subjects WHERE binding_id=$3
 UNION ALL SELECT 'carrier:'||role_id,'','carrier_latch:role:'||role_id,false FROM kaname.access_bindings WHERE id=$3 AND role_id IS NOT NULL
 UNION ALL SELECT 'role:'||role_id,'','role:'||role_id,false FROM kaname.access_bindings WHERE id=$3 AND role_id IS NOT NULL
) SELECT key,account,guard,global FROM source_rows WHERE key COLLATE "C">$1 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $2`

// Нативные факты не становятся authority proof. Их footprint защищает также
// отрицательные/native method obligations; произвольные usersets → GLOBAL.
const policyNativeSources = `WITH source_rows AS (
 SELECT jsonb_build_array(f.object_type,f.object_id,f.relation,f.subject,f.condition_name,f.condition_params)::text key,
 coalesce(kaname.authority_policy_object_account(f.object_type,f.object_id),'') account,
 CASE WHEN f.object_type IN ('group','iam_group') THEN 'group:'||f.object_id ELSE '' END guard,
 (kaname.authority_policy_object_account(f.object_type,f.object_id) IS NULL AND f.object_type NOT IN ('iam_user','cluster'))
 OR (f.object_type IN ('group','iam_group') AND f.relation='member' AND NOT ('group:'||f.object_id=ANY($4::text[]))) global
 FROM kaname.relation_fact f WHERE f.subject=ANY($3::text[]) OR f.subject='user:*' OR f.subject LIKE 'system_class:%'
) SELECT key,account,guard,global FROM source_rows WHERE key COLLATE "C">$1 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $2`

const policyReadRoles = `SELECT r.id,coalesce(kaname.authority_protocol_row_account('roles',to_jsonb(r)),''),'role:'||r.id,
 (NOT r.is_system AND kaname.authority_protocol_row_account('roles',to_jsonb(r)) IS NULL)
 FROM kaname.roles r WHERE r.id=ANY($3::text[]) AND r.id COLLATE "C">$1 COLLATE "C" ORDER BY r.id COLLATE "C" LIMIT $2`

// Saved и current producer scopes читаются полностью и отдельно заряжаются в
// общий row budget. Root SHARE удерживает receipt/catalog/mirror/publication
// provenance; snapshot не объявляет её complete либо действующей authority.
const policyProducerScopes = `WITH receipts AS (
 SELECT r.*,jsonb_build_array(r.kind,r.module,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id)::text receipt_key
 FROM kaname.producer_source_receipt r WHERE r.active AND ((r.kind='registration_owner' AND r.subject_type=$3 AND r.subject_id=$4) OR r.kind='publication')
), source_rows AS (
 SELECT 'saved:'||r.receipt_key||':'||lpad(s.ordinality::text,20,'0') key,coalesce(a.id,'') account,''::text guard,
 (a.id IS NULL OR s.value->>'Registered' IS DISTINCT FROM 'true' OR (coalesce(s.value->>'ProjectID','')<>'' AND p.account_id IS DISTINCT FROM a.id)) global
 FROM receipts r CROSS JOIN LATERAL jsonb_array_elements(r.scopes) WITH ORDINALITY s(value,ordinality)
 LEFT JOIN kaname.accounts a ON a.id=s.value->>'AccountID' LEFT JOIN kaname.projects p ON p.id=s.value->>'ProjectID'
 UNION ALL SELECT 'current:'||r.receipt_key||':'||jsonb_build_array(s.project_id,s.account_id)::text,coalesce(a.id,''),'',
 a.id IS NULL OR (s.project_id<>'' AND p.account_id IS DISTINCT FROM a.id)
 FROM receipts r LEFT JOIN kaname.resource_registration_scope s ON s.object_type=r.object_type AND s.object_id=r.object_id
 LEFT JOIN kaname.accounts a ON a.id=s.account_id LEFT JOIN kaname.projects p ON p.id=s.project_id
) SELECT key,account,guard,global FROM source_rows WHERE key COLLATE "C">$1 COLLATE "C" ORDER BY key COLLATE "C" LIMIT $2`
