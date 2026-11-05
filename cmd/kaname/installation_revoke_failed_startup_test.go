// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

const rid06OperationColumns = "id description created_at created_by principal_type principal_id principal_display_name modified_at done metadata_type metadata_data resource_id error_code error_message error_details response_type response_data account_id"

type rid06FailedStartupExpected struct {
	CaseID               string    `json:"caseId"`
	RunID                string    `json:"runId"`
	TestExecutableSHA256 string    `json:"testExecutableSHA256"`
	ClientSHA256         string    `json:"clientSHA256"`
	CredentialExpiresAt  time.Time `json:"credentialExpiresAt"`
	CreatorID            string    `json:"creatorId"`
	TenantID             string    `json:"tenantId"`
	DelegateID           string    `json:"delegateId"`
	OldDelegationID      string    `json:"oldDelegationId"`
	Accounts             []string  `json:"accounts"`
}

type rid06FailedStartupLogs struct {
	ProcessDir   string                     `json:"processDir"`
	BinarySHA256 string                     `json:"binarySHA256"`
	StdoutSHA256 string                     `json:"stdoutSHA256"`
	StderrSHA256 string                     `json:"stderrSHA256"`
	AcceptedAt   time.Time                  `json:"acceptedAt"`
	Event        installationAssertionInput `json:"event"`
}

type rid06ReplayWitness struct {
	RowSHA256       string    `json:"rowSHA256"`
	ClientSHA256    string    `json:"clientSHA256"`
	AssertionSHA256 string    `json:"assertionSHA256"`
	ExpiresAt       time.Time `json:"expiresAt"`
	RedeemedAt      time.Time `json:"redeemedAt"`
}

type rid06FailedOperationWitness struct {
	RowSHA256  string    `json:"rowSHA256"`
	ID         string    `json:"id"`
	AccountID  string    `json:"accountId"`
	ResourceID string    `json:"resourceId"`
	CreatorID  string    `json:"creatorId"`
	CreatedAt  time.Time `json:"createdAt"`
	ModifiedAt time.Time `json:"modifiedAt"`
	ErrorCode  int32     `json:"errorCode"`
	ResponseID string    `json:"responseId"`
}

type rid06FailedStartupProof struct {
	Expected         rid06FailedStartupExpected    `json:"expected"`
	Logs             rid06FailedStartupLogs        `json:"logs"`
	Replay           rid06ReplayWitness            `json:"replay"`
	Operations       []rid06FailedOperationWitness `json:"operations"`
	BeforeStartedAt  time.Time                     `json:"beforePrimaryStartedAt"`
	BeforeFinishedAt time.Time                     `json:"beforePrimaryFinishedAt"`
	AfterStartedAt   time.Time                     `json:"afterPrimaryStartedAt"`
	AfterFinishedAt  time.Time                     `json:"afterPrimaryFinishedAt"`
}

func rid06FailedStartupCase(id string) bool {
	return id == "registry-installation-rid06-S1-SEQUENTIAL-FAILED-STARTUP" || id == "registry-installation-rid06-S2-SEQUENTIAL-FAILED-STARTUP"
}

// Закрытый разбор не принимает повтор ключа даже с совпадающим значением.
func rid06FailedObject(raw []byte) (rid09PrimaryRow, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, false
	}
	row := rid09PrimaryRow{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || row[name] != nil {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		row[name] = value
	}
	last, err := d.Token()
	var extra any
	if err != nil || last != json.Delim('}') || d.Decode(&extra) != io.EOF {
		return nil, false
	}
	return row, true
}

func rid06FailedTime(raw json.RawMessage) (time.Time, bool) {
	var value string
	if json.Unmarshal(raw, &value) != nil || !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`).MatchString(value) {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, value)
	return at, err == nil && !at.IsZero()
}

// Две частные таблицы берутся из тех же SQL-байтов и той же TX, что Whole.
func rid06FailedBoundRows(s ridWholeDeliverySnapshot, table string) (map[string]rid09PrimaryRow, map[string]string, bool) {
	var rawRows [][]byte
	var columns, key string
	switch table {
	case "client_assertion_replay":
		rawRows, columns, key = s.replaySQLRows, rid11AuthnColumns[table], "assertion_id"
	case "operations":
		rawRows, columns, key = s.operationSQLRows, rid06OperationColumns, "id"
	default:
		return nil, nil, false
	}
	entry, exists := s.Bookkeeping[table]
	if !exists || !rid11SameColumns(entry.Columns, columns) || len(entry.Rows) != len(rawRows) {
		return nil, nil, false
	}
	rows, hashes, all := map[string]rid09PrimaryRow{}, map[string]string{}, []string{}
	for _, raw := range rawRows {
		row, ok := rid06FailedObject(raw)
		if !ok || !rid03Columns(row, columns) {
			return nil, nil, false
		}
		id := rid03S(row, key)
		if table == "client_assertion_replay" {
			id = rid03S(row, "client_id") + "\x00" + id
		}
		if id == "" || strings.HasPrefix(id, "\x00") || strings.HasSuffix(id, "\x00") || rows[id] != nil {
			return nil, nil, false
		}
		rows[id], hashes[id] = row, rid06ByteSHA(raw)
		all = append(all, hashes[id])
	}
	sort.Strings(all)
	if !reflect.DeepEqual(all, entry.Rows) {
		return nil, nil, false
	}
	return rows, hashes, true
}

func rid06FailedLogEvent(stdout, stderr []byte) (installationAssertionInput, time.Time, bool) {
	var event installationAssertionInput
	var accepted time.Time
	count := 0
	for _, stream := range [][]byte{stdout, stderr} {
		for _, line := range bytes.Split(stream, []byte{'\n'}) {
			var outer map[string]json.RawMessage
			if json.Unmarshal(line, &outer) != nil || outer["installationAuthentication"] == nil {
				continue
			}
			closed, ok := rid06FailedObject(line)
			if !ok || !rid03Columns(closed, "time level msg installationAuthentication") || rid03S(closed, "level") != "DEBUG" || rid03S(closed, "msg") != "installation authentication accepted" {
				return event, accepted, false
			}
			accepted, ok = rid06FailedTime(closed["time"])
			if !ok {
				return event, accepted, false
			}
			inner, ok := rid06FailedObject(closed["installationAuthentication"])
			if !ok || !rid03Columns(inner, "clientSHA256 assertionSHA256 issuedAt expiresAt") || json.Unmarshal(closed["installationAuthentication"], &event) != nil {
				return event, accepted, false
			}
			for _, key := range []string{"clientSHA256", "assertionSHA256"} {
				if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(rid03S(inner, key)) {
					return event, accepted, false
				}
			}
			for _, key := range []string{"issuedAt", "expiresAt"} {
				if _, ok := rid06FailedTime(inner[key]); !ok {
					return event, accepted, false
				}
			}
			count++
		}
	}
	return event, accepted, count == 1
}

func rid06ReadFailedLogs(t *testing.T, root string, p *installruntime.Process) rid06FailedStartupLogs {
	t.Helper()
	out, err := os.ReadFile(p.StdoutPath)
	require.NoError(t, err)
	errout, err := os.ReadFile(p.StderrPath)
	require.NoError(t, err)
	event, accepted, ok := rid06FailedLogEvent(out, errout)
	require.True(t, ok, "exactly one closed actual authentication event required")
	dir, err := filepath.Rel(root, filepath.Dir(p.StdoutPath))
	require.NoError(t, err)
	require.False(t, filepath.IsAbs(dir) || strings.HasPrefix(dir, ".."))
	return rid06FailedStartupLogs{ProcessDir: filepath.ToSlash(dir), BinarySHA256: p.BinarySHA256, StdoutSHA256: rid06ByteSHA(out), StderrSHA256: rid06ByteSHA(errout), AcceptedAt: accepted, Event: event}
}

func rid06BuildFailedStartup(caseID, runID, executableSHA string, e rid06FailedStartupExpected, logs rid06FailedStartupLogs, a, b rid03NewmanSnapshot) (rid06FailedStartupProof, bool) {
	proof, ok, _ := rid06BuildFailedStartupWithReason(caseID, runID, executableSHA, e, logs, a, b)
	return proof, ok
}

// Закрытый код описывает только отвергнутый предикат, без частных значений.
func rid06BuildFailedStartupWithReason(caseID, runID, executableSHA string, e rid06FailedStartupExpected, logs rid06FailedStartupLogs, a, b rid03NewmanSnapshot) (rid06FailedStartupProof, bool, string) {
	fail := func(reason string) (rid06FailedStartupProof, bool, string) {
		return rid06FailedStartupProof{}, false, reason
	}
	sha := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if e.CaseID != caseID || e.RunID != runID || e.TestExecutableSHA256 != executableSHA || !rid06FailedStartupCase(e.CaseID) || !regexp.MustCompile(`^[A-Za-z0-9-]{16,80}$`).MatchString(e.RunID) || !sha.MatchString(e.TestExecutableSHA256) || !sha.MatchString(e.ClientSHA256) || e.CreatorID == "" || e.TenantID == "" || e.DelegateID == "" || e.OldDelegationID == "" || e.CredentialExpiresAt.IsZero() || len(e.Accounts) == 0 {
		return fail("RID06_EXPECTED_IDENTITY")
	}
	if !sha.MatchString(logs.BinarySHA256) || !sha.MatchString(logs.StdoutSHA256) || !sha.MatchString(logs.StderrSHA256) || logs.ProcessDir == "" || filepath.IsAbs(logs.ProcessDir) || filepath.Clean(logs.ProcessDir) != logs.ProcessDir || strings.HasPrefix(logs.ProcessDir, "..") {
		return fail("RID06_LOG_BINDING")
	}
	if !rid06PrimaryBounds(a.Whole, b.Whole) {
		return fail("RID06_PRIMARY_BOUNDS")
	}
	if !rid06HistoryOwnCeilingsValid(a.Whole, b.Whole) {
		return fail("RID06_HISTORY_CEILINGS")
	}
	if !rid06FailedDeliveryEqual(a, b) {
		return fail("RID06_DELIVERY_RAW_BUSINESS")
	}
	if !reflect.DeepEqual(a.Whole.Delivery, b.Whole.Delivery) {
		return fail("RID06_WHOLE_DELIVERY")
	}
	if !reflect.DeepEqual(a.Whole.Separation, ridWholeBookkeeping) {
		return fail("RID06_EXPECTED_SEPARATION")
	}
	if !reflect.DeepEqual(a.Whole.Separation, b.Whole.Separation) {
		return fail("RID06_SEPARATION_STABLE")
	}
	if len(a.Whole.Bookkeeping) != len(ridWholeBookkeeping) {
		return fail("RID06_BOOKKEEPING_BEFORE_COUNT")
	}
	if len(b.Whole.Bookkeeping) != len(ridWholeBookkeeping) {
		return fail("RID06_BOOKKEEPING_AFTER_COUNT")
	}
	for table := range ridWholeBookkeeping {
		old, found := a.Whole.Bookkeeping[table]
		now, exists := b.Whole.Bookkeeping[table]
		if !found || !exists || !reflect.DeepEqual(old.Columns, now.Columns) || (table != "operations" && table != "client_assertion_replay" && !reflect.DeepEqual(old, now)) {
			return fail("RID06_BOOKKEEPING_CLOSURE")
		}
	}
	old, oldHash, ok := rid06FailedBoundRows(a.Whole, "client_assertion_replay")
	if !ok {
		return fail("RID06_BEFORE_REPLAY_BOUND")
	}
	now, nowHash, ok := rid06FailedBoundRows(b.Whole, "client_assertion_replay")
	if !ok || len(now) != len(old)+1 {
		return fail("RID06_AFTER_REPLAY_BOUND_OR_CARDINALITY")
	}
	for key := range old {
		if oldHash[key] != nowHash[key] {
			return fail("RID06_OLD_REPLAY_IMMUTABLE")
		}
	}
	var replay rid06ReplayWitness
	for key, row := range now {
		if old[key] != nil {
			continue
		}
		expires, ok := rid06FailedTime(row["expires_at"])
		if !ok {
			return fail("RID06_REPLAY_EXPIRY_PARSE")
		}
		redeemed, ok := rid06FailedTime(row["redeemed_at"])
		if !ok {
			return fail("RID06_REPLAY_REDEMPTION_PARSE")
		}
		replay = rid06ReplayWitness{RowSHA256: nowHash[key], ClientSHA256: installationIdentitySHA(rid03S(row, "client_id")), AssertionSHA256: installationIdentitySHA(rid03S(row, "assertion_id")), ExpiresAt: expires, RedeemedAt: redeemed}
	}
	low, high := a.Whole.PrimaryFinishedAt, b.Whole.PrimaryStartedAt
	input := logs.Event
	if logs.AcceptedAt.IsZero() || logs.AcceptedAt.Before(low) || logs.AcceptedAt.After(high) {
		return fail("RID06_EVENT_WINDOW")
	}
	end := input.IssuedAt.Add(min(60*time.Second, tokenpolicy.MaxAssertionLifetime))
	if e.CredentialExpiresAt.Truncate(time.Second).Before(end) {
		end = e.CredentialExpiresAt.Truncate(time.Second)
	}
	if input.ClientSHA256 != e.ClientSHA256 || replay.ClientSHA256 != e.ClientSHA256 || !sha.MatchString(input.AssertionSHA256) || input.AssertionSHA256 != replay.AssertionSHA256 || input.IssuedAt.IsZero() || !input.IssuedAt.Equal(input.IssuedAt.Truncate(time.Second)) || input.IssuedAt.Before(low.Truncate(time.Second)) || input.IssuedAt.After(high) || !input.ExpiresAt.Equal(end) || !end.After(input.IssuedAt) || !replay.ExpiresAt.Equal(end) || replay.RedeemedAt.Before(low) || replay.RedeemedAt.After(high) || input.IssuedAt.After(replay.RedeemedAt.Add(tokenpolicy.ClockSkew)) || !replay.RedeemedAt.Before(end.Add(tokenpolicy.ClockSkew)) {
		return fail("RID06_ASSERTION_BINDING_TIME_CLOSURE")
	}
	ops, hashes, ok := rid06FailedBoundRows(b.Whole, "operations")
	if !ok {
		return fail("RID06_AFTER_OPERATIONS_BOUND")
	}
	previous, previousHashes, ok := rid06FailedBoundRows(a.Whole, "operations")
	if !ok {
		return fail("RID06_BEFORE_OPERATIONS_BOUND")
	}
	for key := range previous {
		if previousHashes[key] != hashes[key] {
			return fail("RID06_OLD_OPERATION_IMMUTABLE")
		}
	}
	// Независимый Raw снимок обязан описывать те же полные строки Operation.
	for _, pair := range []struct {
		rows map[string]rid09PrimaryRow
		raw  []rid09PrimaryRow
	}{{previous, a.Raw["operations"]}, {ops, b.Raw["operations"]}} {
		bound := map[string]rid09PrimaryRow{}
		for _, row := range pair.raw {
			id := rid03S(row, "id")
			if id == "" || bound[id] != nil {
				return fail("RID06_RAW_OPERATION_IDENTITY")
			}
			bound[id] = row
		}
		if rid03EvidenceHash(bound) != rid03EvidenceHash(pair.rows) {
			return fail("RID06_RAW_OPERATION_COHERENCE")
		}
	}
	expectedCount := 1
	if strings.Contains(e.CaseID, "-S2-") {
		expectedCount = 3
	}
	// Полный снимок проверяется целиком, включая ещё не обработанный суффикс.
	if len(e.Accounts) != expectedCount {
		return fail("RID06_EXPECTED_ACCOUNT_SET")
	}
	accounts := map[string]bool{}
	tenantIndex := -1
	for index, account := range e.Accounts {
		if account == "" || accounts[account] {
			return fail("RID06_EXPECTED_ACCOUNT_SET")
		}
		accounts[account] = true
		if account == e.TenantID {
			tenantIndex = index
		}
	}
	if tenantIndex < 0 {
		return fail("RID06_EXPECTED_ACCOUNT_SET")
	}
	// После первой ошибки есть ровно операции исходного префикса до tenant включительно.
	wanted := map[string]bool{}
	for _, account := range e.Accounts[:tenantIndex+1] {
		wanted[account] = true
	}
	if len(ops) != len(previous)+tenantIndex+1 {
		return fail("RID06_NEW_OPERATION_CARDINALITY")
	}
	proof := rid06FailedStartupProof{Expected: e, Logs: logs, Replay: replay, Operations: []rid06FailedOperationWitness{}, BeforeStartedAt: a.Whole.PrimaryStartedAt, BeforeFinishedAt: low, AfterStartedAt: high, AfterFinishedAt: b.Whole.PrimaryFinishedAt}
	seen := map[string]bool{}
	for id, row := range ops {
		if previous[id] != nil {
			continue
		}
		account, resource := rid03S(row, "account_id"), rid03S(row, "resource_id")
		done, ok := rid03Cell[bool](row, "done")
		if !ok || !done || !wanted[account] || seen[account] || resource == "" || resource == e.OldDelegationID || rid03S(row, "principal_type") != "service_account" || rid03S(row, "principal_id") != e.CreatorID || rid03S(row, "principal_display_name") != e.CreatorID {
			return fail("RID06_NEW_OPERATION_IDENTITY")
		}
		seen[account] = true
		created, ok := rid06FailedTime(row["created_at"])
		if !ok {
			return fail("RID06_OPERATION_CREATED_PARSE")
		}
		modified, ok := rid06FailedTime(row["modified_at"])
		if !ok || created.Before(low) || modified.Before(created) || modified.After(high) {
			return fail("RID06_OPERATION_TIME_WINDOW")
		}
		md, err := rid01ReadByteaCell(row, "metadata_data")
		if err != nil {
			return fail("RID06_OPERATION_METADATA_BYTES")
		}
		var meta iamv1.CreateGrantDelegationMetadata
		if (&anypb.Any{TypeUrl: rid03S(row, "metadata_type"), Value: md}).UnmarshalTo(&meta) != nil || meta.AccountId != account || meta.GrantDelegationId != resource {
			return fail("RID06_OPERATION_METADATA_CLOSURE")
		}
		witness := rid06FailedOperationWitness{RowSHA256: hashes[id], ID: id, AccountID: account, ResourceID: resource, CreatorID: e.CreatorID, CreatedAt: created, ModifiedAt: modified}
		if account == e.TenantID {
			code, ok := rid03Cell[*int32](row, "error_code")
			if !ok || code == nil || *code != 9 || !rid03SameCell(row, "response_type", nil) || !rid03SameCell(row, "response_data", nil) {
				return fail("RID06_TENANT_FAILURE_CLOSURE")
			}
			witness.ErrorCode = *code
		} else {
			if !rid03SameCell(row, "error_code", nil) {
				return fail("RID06_ANCESTOR_SUCCESS_CODE")
			}
			rd, err := rid01ReadByteaCell(row, "response_data")
			if err != nil {
				return fail("RID06_ANCESTOR_RESPONSE_BYTES")
			}
			var response iamv1.GrantDelegation
			if (&anypb.Any{TypeUrl: rid03S(row, "response_type"), Value: rd}).UnmarshalTo(&response) != nil || response.Id != resource || response.AccountId != account || response.Delegate == nil || response.Delegate.Id != e.DelegateID {
				return fail("RID06_ANCESTOR_RESPONSE_CLOSURE")
			}
			witness.ResponseID = response.Id
			matched := 0
			for _, gd := range b.Raw["grant_delegations"] {
				if rid03S(gd, "id") == resource && rid03S(gd, "account_id") == account && rid03S(gd, "delegate_id") == e.DelegateID && rid03S(gd, "status") == "ACTIVE" {
					matched++
				}
			}
			if matched != 1 {
				return fail("RID06_ANCESTOR_DELEGATION_CLOSURE")
			}
		}
		proof.Operations = append(proof.Operations, witness)
	}
	sort.Slice(proof.Operations, func(i, j int) bool { return proof.Operations[i].ID < proof.Operations[j].ID })
	return proof, true, ""
}

// Сравнение независимого входа сохраняется до запуска; исходные ID не форматируются.
func rid06RequireExpectedClient(t require.TestingT, expected, actual string) {
	require.True(t, expected == actual, "installation credential identity mismatch (redacted)")
}
