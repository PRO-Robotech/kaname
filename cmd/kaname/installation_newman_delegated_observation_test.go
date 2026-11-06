// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type rid03ActGetObservation struct {
	Version        int    `json:"version"`
	CaseID         string `json:"caseId"`
	RequestName    string `json:"requestName"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	ResourceID     string `json:"resourceId"`
	MaterializedAt string `json:"materializedAt"`
	CreatedAt      string `json:"createdAt"`
	DelegationID   string `json:"delegationId"`
	SubjectType    string `json:"subjectType"`
	SubjectID      string `json:"subjectId"`
	RoleID         string `json:"roleId"`
	ScopeType      string `json:"scopeType"`
	ScopeID        string `json:"scopeId"`
	TargetType     string `json:"targetType"`
	TargetID       string `json:"targetId"`
	StartedAt      string `json:"startedAt"`
	CompletedAt    string `json:"completedAt"`
}

var rid03ObservedCases = map[string]bool{
	"registry-installation-rid03-S1-GRANT-ACT": true, "registry-installation-rid03-S1-ROLE-TWIN-ACT": true, "registry-installation-rid03-S1-TARGET-TWIN-ACT": true, "registry-installation-rid03-S1-SUBJECT-TWIN-ACT": true, "registry-installation-rid03-S1-ANONYMOUS-TWIN-ACT": true,
	"registry-installation-rid03-S2-GRANT-ACT": true, "registry-installation-rid03-S2-ROLE-TWIN-ACT": true, "registry-installation-rid03-S2-TARGET-TWIN-ACT": true, "registry-installation-rid03-S2-SUBJECT-TWIN-ACT": true, "registry-installation-rid03-S2-ANONYMOUS-TWIN-ACT": true,
}

// Строгий замкнутый необязательный объект метаданных: без повторных ключей, неизвестных полей,
// последующих значений, слотов секретов/тела/заголовков, массивов или неограниченных строк.
func (o *rid03ActGetObservation) UnmarshalJSON(raw []byte) error {
	fail := errors.New("invalid RID03 actual Get observation")
	if len(raw) > 4096 {
		return fail
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fail
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return fail
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return fail
		}
		seen[name] = true
		var discard json.RawMessage
		if d.Decode(&discard) != nil {
			return fail
		}
	}
	if _, err = d.Token(); err != nil {
		return fail
	}
	if _, err = d.Token(); err != io.EOF {
		return fail
	}
	type plain rid03ActGetObservation
	var value plain
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil || len(seen) != 18 {
		return fail
	}
	*o = rid03ActGetObservation(value)
	return rid03ValidateReceiptObservation(o.CaseID, o)
}
func rid03ValidateReceiptObservation(caseID string, o *rid03ActGetObservation) error {
	fail := errors.New("invalid RID03 actual Get observation")
	if !rid03ObservedCases[caseID] {
		if o != nil {
			return fail
		}
		return nil
	}
	if o == nil || o.Version != 1 || o.CaseID != caseID || o.RequestName != caseID+" :: actual-action-resource-Get" || o.Method != "GET" || o.Path != "/iam/v1/accessBindings/"+o.ResourceID {
		return fail
	}
	id := regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	for _, v := range []string{o.ResourceID, o.DelegationID, o.SubjectID, o.RoleID, o.ScopeID, o.TargetID} {
		if !id.MatchString(v) {
			return fail
		}
	}
	if (o.SubjectType != "service_account" && o.SubjectType != "system_class") || o.ScopeType != "iam.account" || o.TargetType != "registry.registries" {
		return fail
	}
	mat, e := time.Parse(time.RFC3339Nano, o.MaterializedAt)
	if e != nil || mat.Nanosecond() != 0 {
		return fail
	}
	created, e := time.Parse(time.RFC3339Nano, o.CreatedAt)
	if e != nil || created.Nanosecond() != 0 {
		return fail
	}
	start, e := time.Parse(time.RFC3339Nano, o.StartedAt)
	if e != nil {
		return fail
	}
	end, e := time.Parse(time.RFC3339Nano, o.CompletedAt)
	if e != nil || end.Before(start) || end.Sub(start) > 5*time.Second || mat.Before(created) || mat.After(end) {
		return fail
	}
	return nil
}

// Идентичность возвращённого ответа остаётся НАБЛЮДЕНИЕМ, пока эта независимая
// первичная разница не предоставит настоящий новый ID и точный журнал материализации.
func rid03MatchActObservation(e *rid03NewmanExpectation, o *rid03ActGetObservation, before, after rid03NewmanSnapshot) error {
	fail := errors.New("FIXTURE_NOT_ACCEPTED: actual Get and independent primary observation differ")
	if rid03ValidateReceiptObservation(e.CaseID, o) != nil {
		return fail
	}
	if !rid03ObservedCases[e.CaseID] {
		return nil
	}
	if e.Path != "/iam/v1/accessBindings" || e.Denied || e.Phase != "ACT" {
		return fail
	}
	if o.ResourceID != e.Resource["id"] || o.MaterializedAt != e.Resource["materializedAt"] || o.CreatedAt != e.Resource["createdAt"] || o.DelegationID != e.Resource["delegationId"] {
		return fail
	}
	target := e.Request["target"].(map[string]any)["resources"].(map[string]any)["resources"].([]any)[0].(map[string]any)
	if o.SubjectType != e.Request["subjectType"] || o.SubjectID != e.Request["subjectId"] || o.RoleID != e.Request["roleId"] || o.ScopeType != e.Request["scopeType"] || o.ScopeID != e.Request["scopeId"] || o.TargetType != target["type"] || o.TargetID != target["id"] {
		return fail
	}
	start, err := time.Parse(time.RFC3339Nano, o.StartedAt)
	if err != nil {
		return fail
	}
	end, err := time.Parse(time.RFC3339Nano, o.CompletedAt)
	if err != nil || start.Before(before.Whole.PrimaryFinishedAt) || end.After(after.Whole.PrimaryStartedAt) {
		return fail
	}
	return nil
}
func rid03RequireActObservation(t *testing.T, e *rid03NewmanExpectation, o *rid03ActGetObservation, before, after rid03NewmanSnapshot) {
	t.Helper()
	require.NoError(t, rid03MatchActObservation(e, o, before, after))
}

func rid03DecodeReceiptObservation(caseID string, raw json.RawMessage) (*rid03ActGetObservation, error) {
	if len(raw) == 0 {
		return nil, rid03ValidateReceiptObservation(caseID, nil)
	}
	var o rid03ActGetObservation
	if json.Unmarshal(raw, &o) != nil || rid03ValidateReceiptObservation(caseID, &o) != nil {
		return nil, errors.New("invalid RID03 actual Get observation")
	}
	return &o, nil
}

// Сохраняем прежнюю схему отчёта, но отклоняем повторные/новые неизвестные слоты наблюдения RID03
// до того, как штатный декодер квитанции сможет их отбросить.
func rid03CheckReceiptObservationField(raw []byte) error {
	fail := errors.New("invalid RID03 actual Get observation")
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fail
	}
	seen := false
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return fail
		}
		name, ok := key.(string)
		if !ok {
			return fail
		}
		if strings.HasPrefix(name, "rid03") {
			if name != "rid03ActGet" || seen {
				return fail
			}
			seen = true
		}
		var discard json.RawMessage
		if d.Decode(&discard) != nil {
			return fail
		}
	}
	if _, err = d.Token(); err != nil {
		return fail
	}
	if _, err = d.Token(); err != io.EOF {
		return fail
	}
	return nil
}
