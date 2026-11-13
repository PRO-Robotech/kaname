// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/admission"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/jackc/pgx/v5/pgtype"
)

type sourceMarks struct {
	w    *semanticAuthorityWriteTx
	cost kaname.SourceReadCost
}

func (m *sourceMarks) PersonMarks(ctx context.Context, ids []string) (map[string]bool, error) {
	m.cost.Reads++
	out, err := personmarks.Read(ctx, m.w.tx, ids)
	m.cost.Rows += len(out)
	return out, err
}

func (w *semanticAuthorityWriteTx) AdmitSourceActor(ctx context.Context, actor domain.Subject) (kaname.SourceReadCost, error) {
	if actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return kaname.SourceReadCost{}, kaname.ErrCanonicalSourceInvalid
	}
	cost := kaname.SourceReadCost{Reads: 1}
	var exists bool
	if err := w.tx.QueryRow(ctx, "SELECT "+sourceActorExistsSQL, string(actor.Type), string(actor.ID)).Scan(&exists); err != nil {
		return cost, err
	}
	if !exists {
		return cost, kaname.ErrSourceUnconfirmed
	}
	cost.Rows++
	// Тот же канонический допуск, что native checker, без независимой проверки
	// токена/boolean. Чтение текущей отметки выполняется на w.tx.
	marks := &sourceMarks{w: w}
	ok, err := admission.Subject(ctx, marks, string(actor.Type)+":"+string(actor.ID))
	cost.Reads += marks.cost.Reads
	cost.Rows += marks.cost.Rows
	if err != nil {
		return cost, err
	}
	if !ok {
		return cost, kaname.ErrSourceUnconfirmed
	}
	return cost, nil
}

// ProducerSources читает receipt и все подтверждающие строки одним SQL snapshot.
// Источник владельца — accepted typed receipt; relation_fact не является входом.
func (w *semanticAuthorityWriteTx) ProducerSources(ctx context.Context, f kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
	if _, err := canonicalPage(kaname.CanonicalSourceFilter{Actor: f.Actor, Limit: f.Limit}); err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	var cursor [7]string
	if f.After != "" {
		if len(f.After) > 4096 {
			return kaname.ProducerSourcePage{}, "", kaname.ErrCanonicalSourceInvalid
		}
		raw, e := base64.RawURLEncoding.DecodeString(f.After)
		if e != nil || json.Unmarshal(raw, &cursor) != nil || cursor[0] == "" {
			return kaname.ProducerSourcePage{}, "", kaname.ErrCanonicalSourceInvalid
		}
	}
	if err := w.canonicalCoverage(""); err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	public := slices.Contains(domain.SpeakerClasses(string(f.Actor.Type)+":"+string(f.Actor.ID)), domain.SpeakerAnonymous)
	rows, err := w.tx.Query(ctx, producerSourcesSQL, string(f.Actor.Type), string(f.Actor.ID), public, cursor[:], f.Limit)
	if err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	defer rows.Close()
	out := kaname.ProducerSourcePage{Cost: kaname.SourceReadCost{Reads: 1}}
	var halves catalog.Halves
	if err = json.Unmarshal(w.bundle.CanonicalCatalog(), &halves); err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	actorCharged := false
	for rows.Next() {
		// LEFT JOIN оставляет marker даже при пустой странице: отсутствие
		// typed actor не маскируется успешным пустым результатом.
		var exists bool
		marker := make([]any, 19)
		marker[0] = &exists
		if err = rows.Scan(marker...); err != nil {
			return kaname.ProducerSourcePage{}, "", err
		}
		if !exists {
			return kaname.ProducerSourcePage{}, "", kaname.ErrSourceUnconfirmed
		}
		if !actorCharged {
			out.Cost.Rows++
			actorCharged = true
		}
		if rows.RawValues()[1] == nil {
			continue
		}
		var s kaname.ProducerSource
		var scopes, currentScopes, resource, verbsRaw []byte
		var version pgtype.Timestamptz
		var problem string
		var cost int
		r := &s.Receipt
		if err = rows.Scan(&exists, &r.Kind, &r.Module, &r.CatalogType, &r.ObjectType, &r.ObjectID, &r.Relation, &r.Subject.Type, &r.Subject.ID, &r.ConditionName, &r.ConditionParameters, &scopes, &version, &s.Versionless, &currentScopes, &resource, &verbsRaw, &problem, &cost); err != nil {
			return kaname.ProducerSourcePage{}, "", err
		}
		out.Cost.Rows += cost
		if json.Unmarshal(scopes, &r.Scopes) != nil {
			return kaname.ProducerSourcePage{}, "", kaname.ErrCanonicalSourceInvalid
		}
		if version.InfinityModifier == pgtype.Finite {
			r.SourceVersion = version.Time
		} else if version.InfinityModifier != pgtype.NegativeInfinity {
			return kaname.ProducerSourcePage{}, "", kaname.ErrCanonicalSourceInvalid
		}
		if r.Validate() != nil {
			return kaname.ProducerSourcePage{}, "", kaname.ErrCanonicalSourceInvalid
		}
		for _, scope := range r.Scopes {
			if err = w.canonicalCoverage(domain.AccountID(scope.AccountID)); err != nil {
				return kaname.ProducerSourcePage{}, "", err
			}
		}
		var actual []domain.ContainerScope
		if json.Unmarshal(currentScopes, &actual) != nil {
			return kaname.ProducerSourcePage{}, "", kaname.ErrCanonicalSourceInvalid
		}
		for _, scope := range actual {
			if err = w.canonicalCoverage(domain.AccountID(scope.AccountID)); err != nil {
				return kaname.ProducerSourcePage{}, "", err
			}
		}
		scopeKey := func(s domain.ContainerScope) string { return s.AccountID + "\x00" + s.ProjectID }
		less := func(a, b domain.ContainerScope) int {
			if scopeKey(a) < scopeKey(b) {
				return -1
			}
			if scopeKey(a) > scopeKey(b) {
				return 1
			}
			return 0
		}
		saved := append([]domain.ContainerScope(nil), r.Scopes...)
		slices.SortFunc(saved, less)
		slices.SortFunc(actual, less)
		if !slices.Equal(saved, actual) {
			problem = "producer_scopes"
		}
		var got catalog.ResourceRow
		if json.Unmarshal(resource, &got) != nil {
			return kaname.ProducerSourcePage{}, "", kaname.ErrCanonicalSourceInvalid
		}
		found := false
		for _, expected := range halves.Live.Resources {
			if expected.Module == r.Module && expected.Module+"."+expected.Resource == r.CatalogType {
				a, _ := catalog.CanonicalJSON(catalog.Halves{Live: catalog.Rows{Resources: []catalog.ResourceRow{expected}}})
				b, _ := catalog.CanonicalJSON(catalog.Halves{Live: catalog.Rows{Resources: []catalog.ResourceRow{got}}})
				found = string(a) == string(b) && expected.ObjectType == r.ObjectType
				break
			}
		}
		if !found || !slices.Contains(halves.Live.Modules, r.Module) {
			problem = "producer_catalog"
		}
		var verbs []catalog.VerbRow
		if json.Unmarshal(verbsRaw, &verbs) != nil {
			return kaname.ProducerSourcePage{}, "", kaname.ErrCanonicalSourceInvalid
		}
		expectedVerbs := []catalog.VerbRow{}
		for _, v := range halves.Live.Verbs {
			if v.Module == got.Module && v.Resource == got.Resource {
				expectedVerbs = append(expectedVerbs, v)
			}
		}
		vc, e := catalog.CanonicalJSON(catalog.Halves{Live: catalog.Rows{Verbs: verbs}})
		if e != nil {
			return kaname.ProducerSourcePage{}, "", e
		}
		ve, e := catalog.CanonicalJSON(catalog.Halves{Live: catalog.Rows{Verbs: expectedVerbs}})
		if e != nil {
			return kaname.ProducerSourcePage{}, "", e
		}
		if string(vc) != string(ve) {
			problem = "producer_catalog"
		}
		s.Issue = problem
		s.Identity = w.bundle.Identity()
		out.Sources = append(out.Sources, s)
	}
	if err = rows.Err(); err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	next := ""
	// Без lookahead: полная страница всегда требует следующего запроса, даже
	// если он пуст. Никакие прочитанные сверх limit строки не теряются из бюджета.
	if len(out.Sources) == f.Limit {
		r := out.Sources[len(out.Sources)-1].Receipt
		raw, _ := json.Marshal([7]string{r.Kind, r.Module, r.ObjectType, r.ObjectID, r.Relation, string(r.Subject.Type), string(r.Subject.ID)})
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return out, next, nil
}

// Как speakerExistsSQL native checker: существование проверяется по типу,
// независимо от совпадающего ID другой учётки. Admission отметки остаётся отдельным.
const sourceActorExistsSQL = `(($1::text='user' AND EXISTS(SELECT 1 FROM kaname.users WHERE id=$2::text))
 OR ($1::text='service_account' AND EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$2::text)))`

const producerSourcesSQL = `WITH actor AS (SELECT ` + sourceActorExistsSQL + ` AS present), page AS (
 SELECT r.* FROM kaname.producer_source_receipt r
 WHERE (SELECT present FROM actor) AND r.active AND ((r.kind='registration_owner' AND r.subject_type=$1 AND r.subject_id=$2) OR (r.kind='publication' AND $3))
 AND (r.kind,r.module,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id)>(($4::text[])[1],($4::text[])[2],($4::text[])[3],($4::text[])[4],($4::text[])[5],($4::text[])[6],($4::text[])[7])
 ORDER BY r.kind,r.module,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id LIMIT $5
) SELECT actor.present,source.* FROM actor LEFT JOIN LATERAL (SELECT r.kind,r.module,r.catalog_type,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id,r.condition_name,r.condition_parameters,r.scopes,r.source_version,r.versionless,
 coalesce(sc.data,'[]'::jsonb),
 jsonb_build_object('Module',c.module,'Resource',c.resource,'ObjectType',c.object_type,'ParentTypes',c.parent_types,'ParentNames',c.parent_names,'Writes',c.writes,'PublicReadToChildren',c.public_read_to_children,'PermanentProject',c.permanent_project),
 coalesce(cv.data,'[]'::jsonb),
 CASE WHEN r.invalidation<>'' OR r.receipt_version<>1 THEN 'producer_receipt'
 WHEN c.dotted IS NULL OR NOT c.live OR NOT cm.live THEN 'producer_catalog'
 WHEN m.object_id IS NULL THEN 'producer_object'
 WHEN NOT r.versionless AND (NOT isfinite(r.source_version) OR (r.kind='registration_owner' AND m.source_version<r.source_version)) THEN 'producer_version'
 WHEN r.kind='publication' AND (p.object_id IS NULL OR NOT p.published OR p.source_version<>r.source_version) THEN 'publication_state'
 WHEN r.kind='registration_owner' AND retirement.n>0 THEN CASE WHEN r.versionless THEN 'versionless_retirement_action' ELSE 'producer_retirement' END
 WHEN sc.n>256 OR cv.n>256 THEN 'producer_scope_limit'
 ELSE '' END,
 1+coalesce(sc.n,0)*2+coalesce(cv.n,0)+retirement.n+CASE WHEN c.dotted IS NULL THEN 0 ELSE 1 END+CASE WHEN cm.module IS NULL THEN 0 ELSE 1 END+CASE WHEN m.object_id IS NULL THEN 0 ELSE 1 END+CASE WHEN p.object_id IS NULL THEN 0 ELSE 1 END
 FROM page r LEFT JOIN kaname.catalog_resource c ON c.dotted=r.catalog_type AND c.module=r.module AND c.object_type=r.object_type
 LEFT JOIN kaname.catalog_module cm ON cm.module=r.module
 LEFT JOIN kaname.resource_mirror m ON m.object_type=r.catalog_type AND m.object_id=r.object_id
 LEFT JOIN kaname.public_read_publication p ON p.object_type=r.object_type AND p.object_id=r.object_id
 LEFT JOIN LATERAL(SELECT count(*)::int n FROM kaname.resource_registration_retirement x WHERE x.object_type=r.object_type AND x.object_id=r.object_id AND x.relation=r.relation AND x.subject=r.subject_type||':'||r.subject_id AND x.delete_through>=r.source_version)retirement ON true
 LEFT JOIN LATERAL(SELECT count(*)::int n,jsonb_agg(jsonb_build_object('Module',v.module,'Resource',v.resource,'Verb',v.verb,'PerObject',v.per_object,'ContainerParent',coalesce(v.container_parent,''),'ContainerRelation',coalesce(v.container_relation,''))) data FROM (SELECT * FROM kaname.catalog_verb WHERE module=r.module AND resource=c.resource AND live LIMIT 257)v)cv ON true
 LEFT JOIN LATERAL(SELECT count(*)::int n,jsonb_agg(jsonb_build_object('Registered',true,'ProjectID',s.project_id,'AccountID',CASE WHEN s.project_id<>'' AND pr.account_id=s.account_id THEN pr.account_id WHEN s.project_id='' THEN coalesce(a.id,'') ELSE '' END)) data FROM (SELECT * FROM kaname.resource_registration_scope WHERE object_type=r.object_type AND object_id=r.object_id LIMIT 257) s LEFT JOIN kaname.projects pr ON pr.id=s.project_id LEFT JOIN kaname.accounts a ON a.id=s.account_id AND s.project_id='')sc ON true
 ) source ON actor.present
 ORDER BY source.kind,source.module,source.object_type,source.object_id,source.relation,source.subject_type,source.subject_id`

var _ kaname.SemanticSourceReader = (*semanticAuthorityWriteTx)(nil)
