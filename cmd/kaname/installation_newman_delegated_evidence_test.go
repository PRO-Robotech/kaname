// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Бизнес-семейства читаются по всей первичной БД без фильтров цели,
// участника, тенанта или нового выведенного ID. События неверной цели/лишнего семейства
// не могут исчезнуть из разницы. Прогресс транспорта не является бизнес-историей.
func rid03ReadBusinessAudit(t *testing.T, ctx context.Context, tx pgx.Tx) []rid09PrimaryRow {
	t.Helper()
	rows, err := tx.Query(ctx, `SELECT to_jsonb(r) FROM kaname.audit_outbox r
 WHERE starts_with(event_type,'iam.access_binding.') OR starts_with(event_type,'iam.grant_delegation.')
 ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	out := []rid09PrimaryRow{}
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var row rid09PrimaryRow
		require.NoError(t, json.Unmarshal(raw, &row))
		immutable, ok := rid03ImmutableBusinessAudit(row)
		require.True(t, ok, "FIXTURE_NOT_ACCEPTED: unknown audit schema or business family")
		out = append(out, immutable)
	}
	require.NoError(t, rows.Err())
	return out
}
func rid03ImmutableBusinessAudit(row rid09PrimaryRow) (rid09PrimaryRow, bool) {
	if !rid03Columns(row, "id event_type tenant_account_id event_payload status attempts created_at next_attempt_at sent_at last_error") {
		return nil, false
	}
	event := rid03S(row, "event_type")
	if !strings.HasPrefix(event, "iam.access_binding.") && !strings.HasPrefix(event, "iam.grant_delegation.") {
		return nil, false
	}
	out := rid09PrimaryRow{}
	// Ровно эти пять столбцов описывают бизнес-идентичность/историю. Другие пять
	// столбцов явно относятся только к транспорту и не стираются из необработанного SQL.
	for _, key := range []string{"id", "event_type", "tenant_account_id", "event_payload", "created_at"} {
		out[key] = append(json.RawMessage(nil), row[key]...)
	}
	return out, true
}
func rid03EvidenceHash(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func rid03NewEvidenceRows(before, after []rid09PrimaryRow) ([]rid09PrimaryRow, bool) {
	old := map[string]int{}
	for _, row := range before {
		old[rid03EvidenceHash(row)]++
	}
	fresh := []rid09PrimaryRow{}
	for _, row := range after {
		hash := rid03EvidenceHash(row)
		if hash == "" {
			return nil, false
		}
		if old[hash] > 0 {
			old[hash]--
			continue
		}
		fresh = append(fresh, row)
	}
	for _, n := range old {
		if n != 0 {
			return nil, false
		}
	}
	return fresh, true
}

var rid03AuditIDPattern = regexp.MustCompile(`^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$`)

func rid03AuditStringSet(value any) ([]string, bool) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var xs []string
	if json.Unmarshal(raw, &xs) != nil || len(xs) == 0 {
		return nil, false
	}
	sort.Strings(xs)
	for i, x := range xs {
		if x == "" || (i > 0 && xs[i-1] == x) {
			return nil, false
		}
	}
	return xs, true
}

// У ролей модуля этой фикстуры есть явный owner_module в первичном BEFORE.
// Ни обработчик/сценарий, ни нагрузка GD после ACT не подставляют ожидаемый модуль аудита.
func rid03DeclaredGDAuditAxes(e *rid03NewmanExpectation) (string, []string, []string, []string, bool) {
	roles, ok := rid03AuditStringSet(e.Request["roleIds"])
	if !ok {
		return "", nil, nil, nil, false
	}
	targets, ok := rid03AuditStringSet(e.Request["targetTypes"])
	if !ok {
		return "", nil, nil, nil, false
	}
	subjects, ok := rid03AuditStringSet(e.Request["subjectTypes"])
	if !ok {
		return "", nil, nil, nil, false
	}
	module := ""
	for _, id := range roles {
		found := false
		for _, role := range e.Snapshot.Raw["roles"] {
			if rid03S(role, "id") != id {
				continue
			}
			owner := rid03S(role, "owner_module")
			if found || owner == "" || (module != "" && owner != module) {
				return "", nil, nil, nil, false
			}
			module = owner
			found = true
		}
		if !found {
			return "", nil, nil, nil, false
		}
	}
	for _, target := range targets {
		if domain.ModuleOfCatalogType(target) != module {
			return "", nil, nil, nil, false
		}
	}
	normalized := []string{}
	for _, subject := range subjects {
		value, valid := domain.SubjectTypeOfPrincipal(subject)
		if !valid || !strings.HasPrefix(subject, "SUBJECT_TYPE_") {
			return "", nil, nil, nil, false
		}
		normalized = append(normalized, string(value))
	}
	sort.Strings(normalized)
	return module, roles, targets, normalized, true
}

// Этот чистый оракул использует лишь исходно заявленные запрос/участника и независимый
// ID нового первичного ресурса. Новые бизнес-нагрузки имеют замкнутую точную форму.
func rid03BusinessAuditDelta(e *rid03NewmanExpectation, newID string, before, after []rid09PrimaryRow, start, end time.Time) ([]rid09PrimaryRow, bool) {
	seen := map[string]bool{}
	for _, row := range after {
		if !rid03Columns(row, "id event_type tenant_account_id event_payload created_at") || !rid03AuditIDPattern.MatchString(rid03S(row, "id")) || seen[rid03S(row, "id")] {
			return nil, false
		}
		seen[rid03S(row, "id")] = true
	}
	fresh, ok := rid03NewEvidenceRows(before, after)
	if !ok {
		return nil, false
	}
	if e.Phase != "ACT" || e.Denied {
		return fresh, len(fresh) == 0
	}
	if len(fresh) != 1 || newID == "" {
		return nil, false
	}
	row := fresh[0]
	at, ok := rid03Cell[time.Time](row, "created_at")
	if !ok || at.Before(start) || at.After(end) {
		return nil, false
	}
	event, tenant := "iam.access_binding.granted", e.Tenant
	var payload map[string]any
	if e.Path == "/iam/v1/accessBindings" {
		payload = map[string]any{"actor": e.Actor, "subject_type": e.Request["subjectType"], "subject_id": e.Request["subjectId"], "resource_type": "account", "resource_id": e.Tenant, "role_id": e.Request["roleId"], "binding_id": newID, "delegation_id": e.InstallationGD}
	} else if e.Path == "/iam/v1/grantDelegations" {
		event = "iam.grant_delegation.created"
		var valid bool
		tenant, valid = e.Request["accountId"].(string)
		delegate, delegateOK := e.Request["delegate"].(map[string]any)
		if !valid || !delegateOK {
			return nil, false
		}
		module, roles, targets, subjects, axesOK := rid03DeclaredGDAuditAxes(e)
		if !axesOK {
			return nil, false
		}
		payload = map[string]any{"actor": e.Actor, "delegation_id": newID, "account_id": tenant, "delegate": delegate["id"], "module": module, "role_ids": roles, "target_types": targets, "subject_types": subjects}
	} else {
		return nil, false
	}
	return fresh, rid03S(row, "event_type") == event && rid03S(row, "tenant_account_id") == tenant && rid03SameCell(row, "event_payload", payload)
}

type rid03EvidenceTuple struct {
	Subject    string `json:"subject"`
	Relation   string `json:"relation"`
	ObjectType string `json:"objectType"`
	ObjectID   string `json:"objectId"`
}

func rid03EvidenceTupleOf(tuple rid03Tuple) rid03EvidenceTuple {
	return rid03EvidenceTuple{tuple.Subject, tuple.Relation, tuple.Type, tuple.ID}
}
func rid03OrderedEvidenceTuples(tuples map[rid03Tuple]bool) []rid03EvidenceTuple {
	out := []rid03EvidenceTuple{}
	for tuple := range tuples {
		out = append(out, rid03EvidenceTupleOf(tuple))
	}
	sort.Slice(out, func(i, j int) bool { return rid03EvidenceHash(out[i]) < rid03EvidenceHash(out[j]) })
	return out
}

type rid03ProducerEvidence struct {
	ID            int64                `json:"id"`
	Event         string               `json:"event"`
	CreatedAt     time.Time            `json:"createdAt"`
	PayloadShape  string               `json:"payloadShape"`
	ScalarEcho    string               `json:"scalarEcho"`
	Tuples        []rid03EvidenceTuple `json:"tuples"`
	FullRowSHA256 string               `json:"fullRowSHA256"`
}
type rid03FactEvidence struct {
	Tuple                    rid03EvidenceTuple `json:"tuple"`
	SourceVersion            time.Time          `json:"sourceVersion"`
	CreatedAt                time.Time          `json:"createdAt"`
	MatchingProducerClocks   []time.Time        `json:"matchingProducerClocks"`
	ExpectedMaxSourceVersion time.Time          `json:"expectedMaxSourceVersion"`
	ConditionName            string             `json:"conditionName"`
	ConditionParameters      map[string]string  `json:"conditionParameters"`
	FullRowSHA256            string             `json:"fullRowSHA256"`
}
type rid03BusinessEventEvidence struct {
	ID           string    `json:"id"`
	Event        string    `json:"event"`
	Tenant       string    `json:"tenant"`
	CreatedAt    time.Time `json:"createdAt"`
	Actor        string    `json:"actor"`
	BindingID    string    `json:"bindingId,omitempty"`
	DelegationID string    `json:"delegationId"`
	// Нагрузка намеренно является дайджестом, без произвольных необработанных данных аудита/удостоверений.
	PayloadSHA256 string `json:"payloadSHA256"`
}
type rid03TechnicalReceipt struct {
	Version                     int                          `json:"version"`
	CaseID                      string                       `json:"caseId"`
	Phase                       string                       `json:"phase"`
	Denied                      bool                         `json:"denied"`
	PrimaryLowerBound           time.Time                    `json:"primaryLowerBound"`
	PrimaryUpperBound           time.Time                    `json:"primaryUpperBound"`
	NewProducerRows             int                          `json:"newProducerRows"`
	NewDirectFactRows           int                          `json:"newDirectFactRows"`
	NewBusinessEvents           int                          `json:"newBusinessEvents"`
	Producers                   []rid03ProducerEvidence      `json:"producers"`
	DirectFacts                 []rid03FactEvidence          `json:"directFacts"`
	ExpectedEmittedUnion        []rid03EvidenceTuple         `json:"expectedEmittedUnion"`
	ActualEmittedUnion          []rid03EvidenceTuple         `json:"actualEmittedUnion"`
	ExpectedDirectUnion         []rid03EvidenceTuple         `json:"expectedDirectUnion"`
	ActualDirectUnion           []rid03EvidenceTuple         `json:"actualDirectUnion"`
	BusinessEvents              []rid03BusinessEventEvidence `json:"businessEvents"`
	BeforeProducerRowsSHA256    string                       `json:"beforeProducerRowsSHA256"`
	AfterProducerRowsSHA256     string                       `json:"afterProducerRowsSHA256"`
	BeforeFactsSHA256           string                       `json:"beforeFactsSHA256"`
	AfterFactsSHA256            string                       `json:"afterFactsSHA256"`
	BeforeBusinessHistorySHA256 string                       `json:"beforeBusinessHistorySHA256"`
	AfterBusinessHistorySHA256  string                       `json:"afterBusinessHistorySHA256"`
	CoordinateClockProofPassed  bool                         `json:"coordinateClockProofPassed"`
	PhaseRuntimeChecksPassed    bool                         `json:"phaseRuntimeChecksPassed"`
	WholeDoDAccepted            bool                         `json:"wholeDoDAccepted"`
}

// Вызывается только после строгих полных первичных проверок/проверок действия. Он вновь проверяет собственные
// выбранные поля до возврата замкнутой несекретной квитанции. Вызывающие
// пишут только после проверки наблюдения ACT (либо строгих скобок VERIFY/отказа).
func rid03BuildTechnicalReceipt(e *rid03NewmanExpectation, a, b rid03NewmanSnapshot, p *rid03DeltaPolicy) (rid03TechnicalReceipt, bool) {
	if _, ok := rid03NewmanActor(e.CaseID); !ok || !strings.HasSuffix(e.CaseID, "-"+e.Phase) || (e.Phase != "ACT" && e.Phase != "VERIFY") {
		return ridNewmanInitialTechnicalReceipt(e, a, b), false
	}
	return ridNewmanBuildClosedTechnicalReceipt(e, a, b, p)
}

func ridNewmanInitialTechnicalReceipt(e *rid03NewmanExpectation, a, b rid03NewmanSnapshot) rid03TechnicalReceipt {
	return rid03TechnicalReceipt{Version: 1, CaseID: e.CaseID, Phase: e.Phase, Denied: e.Denied, PrimaryLowerBound: a.Whole.PrimaryFinishedAt, PrimaryUpperBound: b.Whole.PrimaryStartedAt, Producers: []rid03ProducerEvidence{}, DirectFacts: []rid03FactEvidence{}, BusinessEvents: []rid03BusinessEventEvidence{}, ExpectedEmittedUnion: []rid03EvidenceTuple{}, ActualEmittedUnion: []rid03EvidenceTuple{}, ExpectedDirectUnion: []rid03EvidenceTuple{}, ActualDirectUnion: []rid03EvidenceTuple{}}
}

// Чистое тело: каждый вызывающий сначала проверяет собственное замкнутое литеральное соответствие случая/фазы.
func ridNewmanBuildClosedTechnicalReceipt(e *rid03NewmanExpectation, a, b rid03NewmanSnapshot, p *rid03DeltaPolicy) (rid03TechnicalReceipt, bool) {
	out := ridNewmanInitialTechnicalReceipt(e, a, b)
	if (e.Phase != "ACT" && e.Phase != "VERIFY" && e.Phase != "READ") || out.PrimaryUpperBound.Before(out.PrimaryLowerBound) {
		return out, false
	}
	producers, ok := rid03NewEvidenceRows(a.Raw["fga_outbox"], b.Raw["fga_outbox"])
	if !ok {
		return out, false
	}
	facts, ok := rid03NewEvidenceRows(a.Raw["relation_fact"], b.Raw["relation_fact"])
	if !ok {
		return out, false
	}
	newID := ""
	if p != nil {
		newID = p.NewID
	}
	events, ok := rid03BusinessAuditDelta(e, newID, a.BusinessAudit, b.BusinessAudit, out.PrimaryLowerBound, out.PrimaryUpperBound)
	if !ok {
		return out, false
	}
	if p == nil {
		if len(producers) != 0 || len(facts) != 0 || (e.Phase == "ACT" && !e.Denied) {
			return out, false
		}
	} else {
		if e.Phase != "ACT" || e.Denied || p.Start != out.PrimaryLowerBound || p.End != out.PrimaryUpperBound {
			return out, false
		}
		if p.Path == "/iam/v1/accessBindings" {
			if !p.bindProducers(producers) {
				return out, false
			}
		} else if len(producers) != 0 || len(facts) != 0 {
			return out, false
		}
		actualUnion := map[rid03Tuple]bool{}
		actualDirect := map[rid03Tuple]bool{}
		for _, row := range producers {
			_, tuples, valid := p.producer(row)
			if !valid {
				return out, false
			}
			id, _ := rid03Cell[int64](row, "id")
			at, _ := rid03Cell[time.Time](row, "created_at")
			var payload rid09PrimaryRow
			if json.Unmarshal(row["payload"], &payload) != nil {
				return out, false
			}
			shape := "singleton"
			if len(payload) == 4 {
				shape = "grouped"
			}
			entry := rid03ProducerEvidence{ID: id, Event: rid03S(row, "event_type"), CreatedAt: at, PayloadShape: shape, ScalarEcho: rid03S(payload, "relation"), Tuples: []rid03EvidenceTuple{}, FullRowSHA256: rid03EvidenceHash(row)}
			for _, tuple := range tuples {
				actualUnion[tuple] = true
				entry.Tuples = append(entry.Tuples, rid03EvidenceTupleOf(tuple))
			}
			out.Producers = append(out.Producers, entry)
		}
		for _, row := range facts {
			if !p.allows("relation_fact", row) {
				return out, false
			}
			tuple := rid03Tuple{rid03S(row, "subject"), rid03S(row, "relation"), rid03S(row, "object_type"), rid03S(row, "object_id")}
			if actualDirect[tuple] {
				return out, false
			}
			actualDirect[tuple] = true
			version, _ := rid03Cell[time.Time](row, "source_version")
			at, _ := rid03Cell[time.Time](row, "created_at")
			clocks := append([]time.Time(nil), p.FactCreated[tuple]...)
			out.DirectFacts = append(out.DirectFacts, rid03FactEvidence{Tuple: rid03EvidenceTupleOf(tuple), SourceVersion: version, CreatedAt: at, MatchingProducerClocks: clocks, ExpectedMaxSourceVersion: p.FactVersions[tuple], ConditionName: "", ConditionParameters: map[string]string{}, FullRowSHA256: rid03EvidenceHash(row)})
		}
		expectedDirect := map[rid03Tuple]bool{}
		for tuple := range p.DirectTuples {
			expectedDirect[tuple] = true
		}
		for _, row := range a.Raw["relation_fact"] {
			delete(expectedDirect, rid03Tuple{rid03S(row, "subject"), rid03S(row, "relation"), rid03S(row, "object_type"), rid03S(row, "object_id")})
		}
		if !reflect.DeepEqual(expectedDirect, actualDirect) || (p.Path == "/iam/v1/accessBindings" && !reflect.DeepEqual(p.Tuples, actualUnion)) {
			return out, false
		}
		out.ExpectedEmittedUnion = rid03OrderedEvidenceTuples(p.Tuples)
		out.ActualEmittedUnion = rid03OrderedEvidenceTuples(actualUnion)
		out.ExpectedDirectUnion = rid03OrderedEvidenceTuples(expectedDirect)
		out.ActualDirectUnion = rid03OrderedEvidenceTuples(actualDirect)
	}
	for _, row := range events {
		var payload rid09PrimaryRow
		if json.Unmarshal(row["event_payload"], &payload) != nil {
			return out, false
		}
		at, _ := rid03Cell[time.Time](row, "created_at")
		out.BusinessEvents = append(out.BusinessEvents, rid03BusinessEventEvidence{ID: rid03S(row, "id"), Event: rid03S(row, "event_type"), Tenant: rid03S(row, "tenant_account_id"), CreatedAt: at, Actor: rid03S(payload, "actor"), BindingID: rid03S(payload, "binding_id"), DelegationID: rid03S(payload, "delegation_id"), PayloadSHA256: rid03EvidenceHash(payload)})
	}
	out.NewProducerRows = len(producers)
	out.NewDirectFactRows = len(facts)
	out.NewBusinessEvents = len(events)
	out.BeforeProducerRowsSHA256 = rid03EvidenceHash(a.Raw["fga_outbox"])
	out.AfterProducerRowsSHA256 = rid03EvidenceHash(b.Raw["fga_outbox"])
	out.BeforeFactsSHA256 = rid03EvidenceHash(a.Raw["relation_fact"])
	out.AfterFactsSHA256 = rid03EvidenceHash(b.Raw["relation_fact"])
	out.BeforeBusinessHistorySHA256 = rid03EvidenceHash(a.BusinessAudit)
	out.AfterBusinessHistorySHA256 = rid03EvidenceHash(b.BusinessAudit)
	out.CoordinateClockProofPassed = true
	return out, true
}
