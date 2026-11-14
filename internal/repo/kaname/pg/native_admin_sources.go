// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Узкий wrapper не экспортирует обратные методы embedded native form. Public
// read, admission и модель прежние; только административные direct основания
// mutation-вопроса требуют текущего источника. Время читается при каждом Check.
type liveAdministrativeChecker struct {
	inner kaname.RelationChecker
	w     *authorityWriteTx
}

func (c *liveAdministrativeChecker) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	if c == nil || c.w == nil || c.w.tx == nil || c.inner == nil {
		return false, kaname.ErrSourceUnconfirmed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Вопрос проверяется до existence/admission и до любого native dispatch.
	if c.w.nativeRead != nil {
		if err := c.w.nativeRead.boundary.requireQuestion(c.w.nativeRead.boundary.bundle, subject, relation, object); err != nil {
			return false, err
		}
	}
	budget := c.w.producerBudget
	if c.w.nativeRead != nil {
		budget = c.w.nativeRead.budget
	}
	if budget != nil {
		if err := chargeNativePolicyBudget(budget, 2, 2); err != nil {
			return false, err
		}
	}
	typ, id, ok := strings.Cut(subject, ":")
	if ok && id != "*" && (typ == "user" || typ == "service_account") {
		var live bool
		if err := c.w.tx.QueryRow(ctx, `SELECT CASE $1 WHEN 'user' THEN EXISTS(SELECT 1 FROM kaname.users WHERE id=$2) WHEN 'service_account' THEN EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$2) ELSE false END`, typ, id).Scan(&live); err != nil {
			return false, err
		}
		if !live {
			return false, nil
		}
	}
	allowed, err := c.inner.Check(ctx, subject, relation, object)
	if errors.Is(err, relverdict.ErrAdministrativeSourceUnconfirmed) {
		return false, kaname.ErrSourceUnconfirmed
	}
	if errors.Is(err, relverdict.ErrAdministrativeSourceLimit) {
		return false, kaname.ErrSourceReadLimit
	}
	return allowed, err
}
func newLiveAdministrativeChecker(w *authorityWriteTx, bundle *granteffect.Bundle) kaname.RelationChecker {
	if w == nil || w.tx == nil || bundle.Validate() != nil {
		return &liveAdministrativeChecker{}
	}
	sources := &nativeAdministrativeSources{w: w, bundle: bundle}
	form := relverdict.NewAdministrativeAsker(w.tx, bundle, func() time.Time { return w.fence.decisionAt }, sources.verify)
	if w.nativeRead != nil {
		form.BindReadBoundary(w.nativeRead, w.nativeRead.budget)
	} else if w.producerBudget != nil {
		// Общий бюджет не объявляет captured scopes полной областью чтения.
		form.BindReadBudget(w.producerBudget)
	}
	return &liveAdministrativeChecker{w: w, inner: authzcascade.WrapAdmitted(form, personmarks.NewTransaction(w.tx))}
}

type nativeAdministrativeSources struct {
	w      *authorityWriteTx
	bundle *granteffect.Bundle
}

func administrativeRelation(relation string) bool {
	switch relation {
	case "admin", "owner", "system_admin", "any_admin":
		return true
	}
	return false
}

// Только закрытая таблица типов producer и канонический cluster. Имя
// admin у iam_role — tier объекта, но его source проверяется тем же producer,
// а не принимается как account-admin и не отвергается из-за одного префикса.
func administrativeObjectType(typ string) bool {
	if typ == "cluster" {
		return true
	}
	dotted, ok := authzmap.DottedType(typ)
	if !ok {
		return false
	}
	return dotted != ""
}

func (s *nativeAdministrativeSources) verify(ctx context.Context, f relverdict.AdministrativeFact, budget *relverdict.AdministrativeReadBudget) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Ordinary direct verb/subject/registration факты сохраняют native semantics.
	// Административный leaf, в том числе в каскаде v_update, не обходит проверку.
	if !administrativeRelation(f.Relation) {
		if administrativeRelation(f.QuestionRelation) {
			return false, relverdict.ErrAdministrativeSourceUnconfirmed
		}
		return true, nil
	}
	if !administrativeObjectType(f.ObjectType) {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	if f.ConditionName != "" || len(f.ConditionParameters) != 0 {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	typ, id, ok := strings.Cut(strings.TrimSuffix(f.Subject, "#member"), ":")
	if !ok {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	actor := domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}
	if actor.Validate() != nil || domain.FGASubjectRef(typ, id) != f.Subject {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	if err := budget.Charge(1, 1); err != nil {
		return false, err
	}
	var exists bool
	err := s.w.tx.QueryRow(ctx, `SELECT CASE $1 WHEN 'user' THEN EXISTS(SELECT 1 FROM kaname.users WHERE id=$2) WHEN 'service_account' THEN EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$2) WHEN 'group' THEN EXISTS(SELECT 1 FROM kaname.groups WHERE id=$2) ELSE false END`, typ, id).Scan(&exists)
	if err != nil || !exists {
		return false, err
	}
	// Живой anchor и account partition проверяются до любого carrier: в том
	// числе roleless системная выдача не оживляет удалённую область.
	if err = budget.Charge(1, 1); err != nil {
		return false, err
	}
	var account string
	switch f.ObjectType {
	case "account":
		err = s.w.tx.QueryRow(ctx, `SELECT id FROM kaname.accounts WHERE id=$1`, f.ObjectID).Scan(&account)
	case "project":
		err = s.w.tx.QueryRow(ctx, `SELECT account_id FROM kaname.projects WHERE id=$1`, f.ObjectID).Scan(&account)
	case "cluster":
		err = s.w.tx.QueryRow(ctx, `SELECT ''::text FROM kaname.clusters WHERE id=$1`, f.ObjectID).Scan(&account)
	default:
		dotted, _ := authzmap.DottedType(f.ObjectType)
		store := &reconcileStore{tx: s.w.tx, decisionAt: s.w.fence.decisionAt}
		object, found, readErr := s.currentObject(ctx, store, dotted, f.ObjectID, budget)
		if readErr != nil || !found {
			return false, readErr
		}
		for _, parent := range object.ParentAccountIDs {
			if err = s.w.canonicalCoverage(domain.AccountID(parent)); err != nil {
				return false, err
			}
		}
		// Все родители проверены отдельно: пустая строка ниже не подменяет
		// account ownership нового типа выдуманным scope anchor.
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err = s.w.canonicalCoverage(domain.AccountID(account)); err != nil {
		return false, err
	}
	known := false
	if f.ObjectType == "account" {
		if err = s.w.canonicalCoverage(domain.AccountID(f.ObjectID)); err != nil {
			return false, err
		}
		if f.Relation == "owner" {
			if err = budget.Charge(1, 1); err != nil {
				return false, err
			}
			var live bool
			err = s.w.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.accounts a JOIN kaname.users u ON u.id=a.owner_user_id WHERE a.id=$1 AND $2='user' AND a.owner_user_id=$3)`, f.ObjectID, typ, id).Scan(&live)
			if err != nil || live {
				return live, err
			}
			known = true
		}
	}
	if f.ObjectType == "cluster" && f.Relation == "system_admin" {
		if err = budget.Charge(1, 1); err != nil {
			return false, err
		}
		var live bool
		err = s.w.tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.cluster_admin_grants WHERE cluster_id=$1 AND subject_type=$2 AND subject_id=$3 AND (granted_until IS NULL OR granted_until>$4))`, f.ObjectID, typ, id, s.w.fence.decisionAt).Scan(&live)
		if err != nil || live {
			return live, err
		}
		known = true
	}
	// Ledger — только индекс кандидатов. Каждая физическая строка учитывается;
	// ни source='member', ни сам ledger не подтверждают право без текущего вывода.
	var cursor [3]string
	var unconfirmed bool
	for {
		if err = ctx.Err(); err != nil {
			return false, err
		}
		if err = budget.Charge(0, 1); err != nil {
			return false, err
		}
		rows, e := s.w.tx.Query(ctx, `SELECT binding_id,member_object_type,member_object_id FROM kaname.access_binding_emitted_tuples WHERE fga_user=$1 AND relation=$2 AND object=$3 AND (binding_id COLLATE "C",member_object_type COLLATE "C",member_object_id COLLATE "C")>($4::text COLLATE "C",$5::text COLLATE "C",$6::text COLLATE "C") ORDER BY binding_id COLLATE "C",member_object_type COLLATE "C",member_object_id COLLATE "C" LIMIT 256`, f.Subject, f.Relation, f.ObjectType+":"+f.ObjectID, cursor[0], cursor[1], cursor[2])
		if e != nil {
			return false, e
		}
		page := make([][3]string, 0, 256)
		for rows.Next() {
			var key [3]string
			if e = rows.Scan(&key[0], &key[1], &key[2]); e != nil {
				break
			}
			page = append(page, key)
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return false, e
		}
		if err = budget.Charge(len(page), 0); err != nil {
			return false, err
		}
		for _, key := range page {
			known = true
			live, e := s.bindingProduces(ctx, domain.AccessBindingID(key[0]), f, budget)
			if errors.Is(e, relverdict.ErrAdministrativeSourceUnconfirmed) {
				unconfirmed = true
				continue
			}
			if e != nil {
				return false, e
			}
			if live {
				return true, nil
			}
		}
		if len(page) < 256 {
			break
		}
		cursor = page[len(page)-1]
	}
	if !known || unconfirmed {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	return false, nil
}

func (s *nativeAdministrativeSources) bindingProduces(ctx context.Context, id domain.AccessBindingID, f relverdict.AdministrativeFact, budget *relverdict.AdministrativeReadBudget) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := budget.Charge(1, 1); err != nil {
		return false, err
	}
	b, err := scanAB(s.w.tx.QueryRow(ctx, `SELECT `+abCols+` FROM kaname.access_bindings WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if b.Status != domain.AccessBindingStatusActive || b.RevokedAt != nil || (b.ExpiresAt != nil && !b.ExpiresAt.After(s.w.fence.decisionAt)) {
		return false, nil
	}
	if err = budget.Charge(0, 1); err != nil {
		return false, err
	}
	rows, err := s.w.tx.Query(ctx, `SELECT subject_type,subject_id FROM kaname.access_binding_subjects WHERE binding_id=$1 ORDER BY subject_type,subject_id LIMIT 33`, id)
	if err != nil {
		return false, err
	}
	matches := false
	for rows.Next() {
		var sub domain.Subject
		if err = rows.Scan(&sub.Type, &sub.ID); err != nil {
			break
		}
		b.Subjects = append(b.Subjects, sub)
		if domain.FGASubjectRef(string(sub.Type), string(sub.ID)) == f.Subject {
			matches = true
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return false, err
	}
	if err = budget.Charge(len(b.Subjects), 0); err != nil {
		return false, err
	}
	if len(b.Subjects) > domain.MaxSubjectsPerBinding {
		return false, relverdict.ErrAdministrativeSourceLimit
	}
	if !matches {
		return false, nil
	}
	if b.RoleID == "" {
		return b.System && b.GrantedRelation == f.Relation && string(b.ResourceType) == f.ObjectType && b.ResourceID == f.ObjectID && len(b.Target.Resources) == 0, nil
	}
	if err = budget.Charge(1, 1); err != nil {
		return false, err
	}
	var live bool
	role, err := scanRoleWithTrailing(s.w.tx.QueryRow(ctx, `SELECT `+roleCols+`,live FROM kaname.roles WHERE id=$1`, b.RoleID), &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !live {
		return false, nil
	}
	role.Lifecycle.State = domain.RoleLifecycleDeclared
	proof := &semanticAuthorityWriteTx{authorityWriteTx: s.w, bundle: s.bundle}
	checkpoint, cost, err := proof.RoleProjectionCheckpoint(ctx, role.ID)
	if charge := budget.Charge(cost.Rows, cost.Reads); charge != nil {
		return false, charge
	}
	if errors.Is(err, kaname.ErrSourceUnconfirmed) {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	if errors.Is(err, kaname.ErrSourceReadLimit) {
		return false, relverdict.ErrAdministrativeSourceLimit
	}
	if err != nil {
		return false, err
	}
	expected, err := s.bundle.Projection(role)
	if err != nil || expected.Checkpoint != checkpoint {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	if len(role.Rules) == 0 {
		if string(b.ResourceType) != f.ObjectType || b.ResourceID != f.ObjectID || len(b.Target.Resources) != 0 {
			return false, nil
		}
		for _, relation := range authzmap.BindingScopeRelations(string(b.ResourceType), role) {
			if string(relation) == f.Relation {
				return true, nil
			}
		}
		return false, nil
	}
	var halves catalog.Halves
	if err = json.Unmarshal(s.bundle.CanonicalCatalog(), &halves); err != nil {
		return false, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return false, err
	}
	if f.ObjectType == "cluster" {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	if err = budget.Charge(1, 1); err != nil {
		return false, err
	}
	store := &reconcileStore{tx: s.w.tx, cat: facts, decisionAt: s.w.fence.decisionAt}
	dotted, ok := authzmap.DottedType(f.ObjectType)
	if !ok {
		return false, relverdict.ErrAdministrativeSourceUnconfirmed
	}
	object, exists, err := s.currentObject(ctx, store, dotted, f.ObjectID, budget)
	if err != nil || !exists {
		return false, err
	}
	for _, account := range object.ParentAccountIDs {
		if err = s.w.canonicalCoverage(domain.AccountID(account)); err != nil {
			return false, err
		}
	}
	ancestors, err := s.currentAncestors(ctx, dotted, f.ObjectID, budget)
	if err != nil {
		return false, err
	}
	bs := bindingScopeFrom(facts, b, role)
	return reconcile.ProducesObjectTuple(facts, bs, object, ancestors, domain.MembershipTuple{User: f.Subject, Relation: f.Relation, Object: f.ObjectType + ":" + f.ObjectID}), nil
}

// IAM берётся из собственной таблицы; внешний тип — из текущего mirror,
// ровно как в object producer. Тип обязательно разрешён закрытой моделью.
func (s *nativeAdministrativeSources) currentObject(ctx context.Context, store *reconcileStore, dotted, id string, budget *relverdict.AdministrativeReadBudget) (domain.MirrorObject, bool, error) {
	if dotted == "iam.user" {
		return s.currentUserObject(ctx, id, budget)
	}
	if _, direct := iamDirectScanSpecs[dotted]; direct {
		return store.GetIAMDirectObject(ctx, dotted, id)
	}
	return store.GetMirrorObject(ctx, dotted, id)
}

// Те же catalog/edge/mirror JOIN, что у AncestorsSnapshot. Полный bounded
// keyset не берёт дополнительные row locks и не использует SKIP LOCKED:
// пропущенный живой контейнер не превращается в доказанное отсутствие.
func (s *nativeAdministrativeSources) currentAncestors(ctx context.Context, dotted, id string, budget *relverdict.AdministrativeReadBudget) ([]domain.MirrorObject, error) {
	// Точный паритет с reconcile.ancestorsOf: IAM-direct не получает
	// контейнерных родителей из mirror, даже если там существует одноимённый edge.
	if domain.FeedSourceForType(dotted) == domain.FeedIAMDirect {
		return nil, ctx.Err()
	}
	var out []domain.MirrorObject
	depth, typ, key := -1, "", ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := budget.Charge(0, 1); err != nil {
			return nil, err
		}
		rows, err := s.w.tx.Query(ctx, `SELECT pe.depth,m.object_type,m.object_id,m.parent_project_id,
 COALESCE(NULLIF(m.parent_account_id,''),pj.account_id,''),m.labels
 FROM kaname.catalog_resource co
 JOIN kaname.resource_parent_edge pe ON pe.object_type=co.object_type AND pe.object_id=$2
 JOIN kaname.catalog_resource cp ON cp.object_type=pe.parent_type AND cp.live
 JOIN kaname.resource_mirror m ON m.object_type=cp.dotted AND m.object_id=pe.parent_id
 LEFT JOIN kaname.projects pj ON pj.id=m.parent_project_id
 WHERE co.dotted=$1 AND co.live
 AND (pe.depth,m.object_type COLLATE "C",m.object_id COLLATE "C")>($3::int,$4::text COLLATE "C",$5::text COLLATE "C")
 ORDER BY pe.depth,m.object_type COLLATE "C",m.object_id COLLATE "C" LIMIT 256`, dotted, id, depth, typ, key)
		if err != nil {
			return nil, err
		}
		n := 0
		for rows.Next() {
			var o domain.MirrorObject
			var account string
			var labels []byte
			if err = rows.Scan(&depth, &o.ObjectType, &o.ObjectID, &o.ParentProjectID, &account, &labels); err != nil {
				break
			}
			if err = budget.Charge(1, 0); err != nil {
				break
			}
			if err = json.Unmarshal(labels, &o.Labels); err != nil {
				break
			}
			if account != "" {
				o.ParentAccountIDs = []string{account}
			}
			if err = s.w.canonicalCoverage(domain.AccountID(account)); err != nil {
				break
			}
			typ, key = o.ObjectType, o.ObjectID
			out = append(out, o)
			n++
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return nil, err
		}
		if n < 256 {
			return out, nil
		}
	}
}

// GetIAMDirectObject(iam.user) агрегирует все memberships в массив. Здесь
// сохраняем ту же семантику (включая PENDING), но заряжаем физические строки
// до накопления, а не после неограниченного ARRAY в единственной SQL-строке.
func (s *nativeAdministrativeSources) currentUserObject(ctx context.Context, id string, budget *relverdict.AdministrativeReadBudget) (domain.MirrorObject, bool, error) {
	o := domain.MirrorObject{ObjectType: "iam.user", ObjectID: id}
	var labels []byte
	err := s.w.tx.QueryRow(ctx, `SELECT labels FROM kaname.users WHERE id=$1`, id).Scan(&labels)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, false, nil
	}
	if err != nil {
		return o, false, err
	}
	if err = json.Unmarshal(labels, &o.Labels); err != nil {
		return o, false, err
	}
	cursor := ""
	for {
		if err = ctx.Err(); err != nil {
			return o, false, err
		}
		if err = budget.Charge(0, 1); err != nil {
			return o, false, err
		}
		rows, e := s.w.tx.Query(ctx, `SELECT account_id FROM kaname.memberships WHERE user_id=$1 AND COALESCE(account_id,'')<>'' AND account_id COLLATE "C">$2 COLLATE "C" ORDER BY account_id COLLATE "C" LIMIT 256`, id, cursor)
		if e != nil {
			return o, false, e
		}
		n := 0
		for rows.Next() {
			if err = rows.Scan(&cursor); err != nil {
				break
			}
			if err = budget.Charge(1, 0); err != nil {
				break
			}
			o.ParentAccountIDs = append(o.ParentAccountIDs, cursor)
			n++
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return o, false, err
		}
		if n < 256 {
			return o, true, nil
		}
	}
}
