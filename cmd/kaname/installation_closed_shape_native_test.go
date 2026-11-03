// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

type rid12NativeInput struct {
	Name                  string
	Invalid, NoGD, Repeat bool
	Input                 rid09Input
	LegalM2               []byte
}
type rid12Proof struct {
	Name                                      string
	Invalid, NoGD, Reordered, NewmanExecuted  bool
	Accounts                                  []string
	NamedSystem, CanonicalSystem              string
	Input                                     rid09Input
	Before, After, Repeated                   ridWholeDeliverySnapshot
	PublicBefore, PublicAfter, PublicRepeated rid09PublicView
	Census, RepeatCensus                      rid08PublicProof
	Raw, RepeatRaw                            map[string]string
	Return, RepeatReturn                      ridWholeReturn
}

// Необязательный внешний публичный потребитель имеет настоящий штатный мир и фазу.
// nil означает NOT_EXECUTED для Newman; нативное доказательство API требуется независимо.
type rid12LivePublicConsumer func(*testing.T, *installationNativeWorld, rid12NativeInput, string)

func rid12NativeInputs(t *testing.T, kind string) []rid12NativeInput {
	t.Helper()
	first := installruntime.NewRIDDeliveryFixture().Second // независимый допустимый M1
	cases := rid12InputCases(t)
	require.Len(t, cases, 15)
	result := []rid12NativeInput{}
	add := func(name string, raw, legal []byte, field string, invalid, noGD, repeat bool) {
		_, err := manifest.Load(first)
		require.NoError(t, err)
		if invalid {
			_, err = manifest.Load(raw)
			require.Error(t, err)
			var coordinate interface{ FieldPath() string }
			require.True(t, errors.As(err, &coordinate))
			require.Equal(t, field, coordinate.FieldPath())
		} else {
			_, err = manifest.Load(raw)
			require.NoError(t, err)
		}
		result = append(result, rid12NativeInput{Name: name, Invalid: invalid, NoGD: noGD, Repeat: repeat, LegalM2: legal,
			Input: rid09Input{Axis: name, Field: "manifests[1]." + field, Twin: !invalid,
				Delivery: installruntime.RIDDeliveryFixture{First: append([]byte(nil), first...), Second: append([]byte(nil), raw...)},
				M1Digest: ridWholeDigest(t, string(first)), M2Digest: ridWholeDigest(t, string(raw)), LegalM2Digest: ridWholeDigest(t, string(legal))}})
	}
	if kind == "no-GD" {
		for _, name := range []string{"absent", "empty"} {
			path := []any{"seed", "grantDelegations"}
			raw := rid12ChangedDocument(t, installruntime.NewRIDDeliveryFixture().First, path, []any{}, name == "absent")
			add(name, raw, raw, "", false, true, false)
			last := &result[len(result)-1]
			last.Input.Delivery.First = rid12ChangedDocument(t, first, path, []any{}, name == "absent")
			last.Input.M1Digest = ridWholeDigest(t, string(last.Input.Delivery.First))
			parsed, err := manifest.Load(last.Input.Delivery.First)
			require.NoError(t, err)
			require.Empty(t, parsed.Seed.GrantDelegations)
		}
		return result
	}
	require.Contains(t, []string{"negative", "lawful-twin"}, kind)
	for _, tc := range cases {
		require.Equal(t, string(rid12WithoutField(t, tc.Invalid, tc.Changed)), string(rid12WithoutField(t, tc.Twin, tc.Changed)), "single-field lawful repair")
		raw := tc.Twin
		if kind == "negative" {
			raw = tc.Invalid
		}
		add(tc.Name, raw, tc.Twin, tc.Field, kind == "negative", false, kind == "lawful-twin" && tc.Name == "roles17")
	}
	return result
}
func rid12Ready(t *testing.T, f *installationNativeWorld, c *rid02OwnedChild, noGD bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.exited:
			t.Fatal("full RID12 delivery exited before readiness")
		default:
		}
		attempt, stop := context.WithTimeout(ctx, time.Second)
		err := f.wire.ProductionReady(attempt)
		stop()
		if err == nil {
			require.NoError(t, ctx.Err())
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("RID12 full delivery readiness deadline")
		case <-ticker.C:
		}
	}
	require.NoError(t, installruntime.CheckOwnedListeners(c.cmd.Process.Pid, c.dir, installruntime.DefaultNativePorts().All()...))
	if !noGD {
		c.seenEvent = true // только настоящая аутентификация GD требует положительного аудита токена FD5
		rid06ReadResult(t, c, installationResult{Stage: "delegation", Code: "OK", CompletedPairs: 6})
	}
}
func rid12Return(t *testing.T, c *rid02OwnedChild, noGD bool) ridWholeReturn {
	t.Helper()
	if !noGD {
		return rid09ReturnReceipt(t, c, codes.OK)
	}
	var out ridWholeReturn
	path := filepath.Join(c.dir, "actual-return.json")
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &out))
	require.True(t, out.CaptureComplete)
	require.False(t, out.ErrorPresent)
	require.Equal(t, int32(codes.OK), out.Code)
	require.Zero(t, out.CapturedRecords, "noGD path does not call installation authentication observer")
	require.Zero(t, out.IssuedTokens)
	require.False(t, c.seenEvent, "readiness does not imply C authentication when no GD was requested")
	p := &installruntime.Process{StdoutPath: filepath.Join(c.dir, "stdout"), StderrPath: filepath.Join(c.dir, "stderr")}
	results, err := p.Results()
	require.NoError(t, err)
	require.Empty(t, results, "no fabricated installation OK0 record on noGD path")
	return out
}
func rid12Declarations(t *testing.T, in rid09Input) map[string]*manifest.Manifest {
	t.Helper()
	out := map[string]*manifest.Manifest{}
	for _, raw := range [][]byte{in.Delivery.First, in.Delivery.Second} {
		m, err := manifest.Load(raw)
		require.NoError(t, err)
		require.NotContains(t, out, m.Module)
		out[m.Module] = m
	}
	require.Len(t, out, 2)
	return out
}
func rid12World(t *testing.T, in rid12NativeInput, consumer rid12LivePublicConsumer) *rid12Proof {
	t.Helper()
	f := newInstallationNativeWorldLifecycle(t, 7200, "", false, true)
	accounts, named, initial, full := rid08SetupN3(t, f)
	require.Len(t, accounts, 3)
	require.EqualValues(t, 1, initial.Admitted)
	require.EqualValues(t, 3, full.Admitted)
	require.EqualValues(t, 3, full.Limit)
	require.EqualValues(t, 3600, full.WindowSeconds)
	require.Contains(t, accounts, named)
	require.NotContains(t, accounts, f.baseline.SystemID)

	rid09RequireNoDelivery(t, f, accounts)
	var boundaryBefore int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT (SELECT count(*) FROM kaname.catalog_module WHERE module='ridbounds')+(SELECT count(*) FROM kaname.roles WHERE owner_module='ridbounds')+(SELECT count(*) FROM kaname.service_accounts WHERE name='svc-ridbounds')`).Scan(&boundaryBefore))
	require.Zero(t, boundaryBefore)
	beforePublic := rid09ReadPublic(t, f)
	if consumer == nil {
		consumer = rid12DefaultNewmanConsumer(t, f, in)
	}
	if consumer != nil {
		consumer(t, f, in, "before")
	}
	f.requireSameCredential(t)
	rid09StopBase(t, f)
	before := ridReadWholeDelivery(t, f)
	ops := rid08GDOperations(t, f)
	require.Empty(t, ops)
	out := &rid12Proof{Name: in.Name, Invalid: in.Invalid, NoGD: in.NoGD, NewmanExecuted: consumer != nil, Accounts: accounts, NamedSystem: named, CanonicalSystem: f.baseline.SystemID, Input: in.Input, Before: before, PublicBefore: beforePublic}
	rid08Write(t, f.session.Root, "rid12-exact-input", in)
	rid08Write(t, f.session.Root, "rid12-whole-before", before)
	watch := f.wire.StartReadinessWatch(f.given.ctx)
	defer watch.Stop()
	spawned := time.Now().UTC()
	child := rid12Start(t, f, in.Input, "first")
	if in.Invalid {
		rid06WaitExit(t, child, 1)
		observations := watch.Stop()
		require.NotEmpty(t, observations)
		require.False(t, observations[0].FinishedAt.After(spawned))
		require.True(t, observations[0].TransportFailed)
		for _, o := range observations {
			require.NotEqual(t, http.StatusOK, o.HTTPStatus)
		}
		rid08Write(t, child.dir, "readiness-observations", observations)
		rid06ReadResult(t, child, installationResult{Stage: "preflight", Code: "INVALID_ARGUMENT", Field: in.Input.Field, CompletedPairs: 0})
		out.Return = rid09ReturnReceipt(t, child, codes.Unknown) // настоящий обёрнутый код загрузчика code=2, отличный от структурированного INVALID_ARGUMENT
		out.After = ridReadWholeDelivery(t, f)
		ridRequireWholeDeliveryUnchanged(t, before, out.After)
		require.Equal(t, ops, rid08GDOperations(t, f))
		if consumer != nil {
			consumer(t, f, in, "refusal-before-restore")
		}
		p, err := f.session.StartBase(f.given.ctx)
		require.NoError(t, err)
		require.NoError(t, p.OwnsListeners(installruntime.DefaultNativePorts().All()...))
		rid09RequireNoDelivery(t, f, accounts)
		out.PublicAfter = rid09ReadPublic(t, f)
		require.Equal(t, beforePublic, out.PublicAfter)
		if consumer != nil {
			consumer(t, f, in, "after-negative")
		}
	} else {
		rid12Ready(t, f, child, in.NoGD)
		watch.Stop()
		declarations := rid12Declarations(t, in.Input)
		out.Census = rid12PublicCensus(t, f, accounts, declarations, in.NoGD)
		out.PublicAfter = rid09ReadPublic(t, f)
		rid12RequireDeclaredCatalogRoles(t, f, declarations, out.PublicAfter)
		want := 6
		if in.NoGD {
			want = 0
		}
		rid08NewOperations(t, f, ops, want)
		require.Len(t, out.Census.Delegations, want)
		if consumer != nil {
			consumer(t, f, in, "after-positive")
		}
		f.requireSameCredential(t)
		rid06GracefulStop(t, child)
		out.Return = rid12Return(t, child, in.NoGD)
		out.After = ridReadWholeDelivery(t, f)
		out.Raw = rid08RawRows(t, f)
		ridRequireOwnCeilingsPreserved(t, before, out.After)
		require.NotEqual(t, before.Delivery, out.After.Delivery)
		require.Equal(t, before.Delivery["accounts"], out.After.Delivery["accounts"])
		require.Equal(t, before.Delivery["cluster_admin_grants"], out.After.Delivery["cluster_admin_grants"])
		if in.NoGD {
			require.Empty(t, out.Raw)
			require.Equal(t, ops, rid08GDOperations(t, f))
		}
		if in.Repeat {
			repeated := in.Input
			// Переставляем каждую ось GD, сохраняя все заявленные узлы каталога/ролей/посева.
			doc := rid12Document(t, repeated.Delivery.Second)
			gd := doc["seed"].(map[string]any)["grantDelegations"].([]any)[0].(map[string]any)
			for _, axis := range []string{"roleIds", "targetTypes", "subjectTypes"} {
				values := gd[axis].([]any)
				require.Greater(t, len(values), 1)
				for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
					values[i], values[j] = values[j], values[i]
				}
			}
			repeated.Delivery.Second = rid12Encode(t, doc)
			repeated.M2Digest = ridWholeDigest(t, string(repeated.Delivery.Second))
			require.NotEqual(t, in.Input.M2Digest, repeated.M2Digest)
			repeatOps := rid08GDOperations(t, f)
			again := rid12Start(t, f, repeated, "reorder")
			rid12Ready(t, f, again, false)
			out.RepeatCensus = rid12PublicCensus(t, f, accounts, rid12Declarations(t, repeated), false)
			out.PublicRepeated = rid09ReadPublic(t, f)
			rid12RequireDeclaredCatalogRoles(t, f, rid12Declarations(t, repeated), out.PublicRepeated)
			rid08NewOperations(t, f, repeatOps, 6)
			require.Equal(t, out.Census, out.RepeatCensus, "all public IDs/createdAt and independent primary dates preserved")
			require.Equal(t, out.PublicAfter, out.PublicRepeated)
			if consumer != nil {
				consumer(t, f, in, "after-reorder")
			}
			rid06GracefulStop(t, again)
			out.RepeatReturn = rid12Return(t, again, false)
			out.Repeated = ridReadWholeDelivery(t, f)
			out.RepeatRaw = rid08RawRows(t, f)
			require.Equal(t, out.Raw, out.RepeatRaw, "complete GD history raw rows, all IDs and untruncated created_at")
			for _, table := range []string{"catalog_module", "catalog_resource", "catalog_verb", "roles", "service_accounts", "groups", "group_members", "access_bindings", "grant_delegations"} {
				require.Equal(t, out.After.Delivery[table], out.Repeated.Delivery[table], table)
			}
			out.Reordered = true
		}
	}
	rid08Write(t, f.session.Root, "rid12-whole-after", out.After)
	rid08Write(t, f.session.Root, "rid12-completed-proof", out)
	return out
}
func rid12Matrix(t *testing.T, kind string, consumer rid12LivePublicConsumer) []*rid12Proof {
	t.Helper()
	inputs := rid12NativeInputs(t, kind) // проверяем каждый точный вход до первого PG
	out := []*rid12Proof{}
	for _, in := range inputs {
		t.Run(in.Name+"/"+kind, func(t *testing.T) { out = append(out, rid12World(t, in, consumer)) })
	}
	// Завершаем с ошибкой после попыток всех независимых свежих миров, без остановки на первом отказе.
	require.Len(t, out, len(inputs), "matrix incomplete; attempted guard prevents automatic blind rerun")
	return out
}
func rid12RequireNegative(t *testing.T, proofs []*rid12Proof) {
	t.Helper()
	require.Len(t, proofs, 15)
	names := map[string]bool{}
	for _, p := range proofs {
		require.NotNil(t, p)
		require.True(t, p.Invalid)
		require.False(t, names[p.Name])
		names[p.Name] = true
		require.Len(t, p.Accounts, 3)
		require.NotEqual(t, p.NamedSystem, p.CanonicalSystem)
		ridRequireWholeDeliveryUnchanged(t, p.Before, p.After)
		require.Equal(t, p.PublicBefore, p.PublicAfter)
		require.Equal(t, int32(codes.Unknown), p.Return.Code)
		require.Zero(t, p.Return.CapturedRecords)
		require.Zero(t, p.Return.IssuedTokens)
	}
}
