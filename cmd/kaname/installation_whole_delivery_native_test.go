// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

type rid09Input struct {
	Axis, Field                       string
	Reverse, Twin                     bool
	Delivery                          installruntime.RIDDeliveryFixture
	M1Digest, M2Digest, LegalM2Digest string
}
type rid09Observation struct {
	Axis, Field                  string
	Reverse, Twin                bool
	Accounts                     []string
	NamedSystem, CanonicalSystem string
	Before, After                ridWholeDeliverySnapshot
	PublicBefore, PublicAfter    rid09PublicView
	GDPublic                     *rid08PublicProof
	Input                        rid09Input
	Return                       ridWholeReturn
	NewmanExecuted               bool
}

// Будущий мост Newman получает настоящий живой штатный транспорт/O и фазу того же мира.
// nil явно означает NOT_EXECUTED и не считается публичным доказательством Newman.
// Не добавляются окружение/CLI/хук продукта или синтетическое экспортированное удостоверение.
type rid09LivePublicConsumer func(*testing.T, *installationNativeWorld, rid09Input, string)

func rid09Inputs(t *testing.T, reverse, twin bool) []rid09Input {
	t.Helper()
	legal := installruntime.NewRIDDeliveryFixture()
	replacements := []struct{ axis, needle, bad string }{
		{"roleIds", "roleIds: [ridsecond.reader]", "roleIds: [ridfirst.reader]"},
		{"targetTypes", "targetTypes: [ridsecond.objects]", "targetTypes: [ridfirst.objects]"},
		{"subjectTypes", "subjectTypes: [SUBJECT_TYPE_SERVICE_ACCOUNT]", "subjectTypes: [SUBJECT_TYPE_UNSPECIFIED]"},
		{"delegate", "delegate: {account: system, name: svc-ridsecond}", "delegate: {account: system, name: svc-ridfirst}"},
	}
	out := []rid09Input{}
	for _, r := range replacements {
		require.Equal(t, 1, strings.Count(string(legal.Second), r.needle))
		bad := []byte(strings.Replace(string(legal.Second), r.needle, r.bad, 1))
		require.True(t, bytes.Equal(legal.Second, []byte(strings.Replace(string(bad), r.bad, r.needle, 1))), "twin restores exactly the single changed scalar; all other bytes identical")
		_, err := manifest.Load(legal.First)
		require.NoError(t, err)
		_, err = manifest.Load(legal.Second)
		require.NoError(t, err)
		_, err = manifest.Load(bad)
		require.Error(t, err)
		var field interface{ FieldPath() string }
		require.True(t, errors.As(err, &field))
		require.Equal(t, "seed.grantDelegations[0]."+r.axis, field.FieldPath())
		index := 1
		if reverse {
			index = 0
		}
		input := rid09Input{Axis: r.axis, Field: fmt.Sprintf("manifests[%d].seed.grantDelegations[0].%s", index, r.axis), Reverse: reverse, Twin: twin, Delivery: installruntime.RIDDeliveryFixture{First: append([]byte(nil), legal.First...), Second: bad}, M1Digest: ridWholeDigest(t, string(legal.First)), M2Digest: ridWholeDigest(t, string(bad)), LegalM2Digest: ridWholeDigest(t, string(legal.Second))}
		if twin {
			input.Delivery.Second = append([]byte(nil), legal.Second...)
			input.M2Digest = input.LegalM2Digest
		}
		out = append(out, input)
	}
	return out
}
func rid09StopBase(t *testing.T, f *installationNativeWorld) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, f.session.Stop(ctx))
	require.NoError(t, ctx.Err())
	// Завершение Stop/Wait предшествует независимой первичной базе. Его собственные
	// фоновые исполнители проекций, токенов и хранения не могут гоняться с оракулом.
	rid02CheckStreams(t, []string{f.base.StdoutPath, f.base.StderrPath}, rid02WorldSecretMaterial(t, f))
}
func rid09Start(t *testing.T, f *installationNativeWorld, in rid09Input) *rid02OwnedChild {
	t.Helper()
	root := filepath.Join(f.session.Root, "whole-input")
	require.NoError(t, os.Mkdir(root, 0700))
	dir := filepath.Join(root, "delivery")
	_, err := in.Delivery.Write(dir, in.Reverse)
	require.NoError(t, err)
	body, err := installruntime.FullStartupConfig(map[string]any{"manifests": map[string]any{"dir": dir, "required": true}, "moduleSeedInstaller": map[string]any{"credentialFile": f.creator.CredentialFile}}, f.writerPlan)
	require.NoError(t, err)
	config := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(config, body, 0600))
	ridRegistrationStartupProof(t, root, body, f.writerPlan)
	executable := rid06HashExecutable(t)
	child := startRIDInstallationChild(t, f, "whole-startup", ridWholeChildInput{ConfigPath: config, EvidenceDir: filepath.Join(f.session.Root, "whole-startup")}, f.session.Environment, ridWholeChildEnv, "TestRIDWholeDeliveryOwnedStartupChild", "3m")
	parentCG, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	childCG, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", child.cmd.Process.Pid))
	require.NoError(t, err)
	require.True(t, bytes.Equal(parentCG, childCG))
	memory, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	require.NoError(t, err)
	require.Equal(t, "4294967296", strings.TrimSpace(string(memory)))
	swap, err := os.ReadFile("/sys/fs/cgroup/memory.swap.max")
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(swap)))
	t.Cleanup(func() { require.Equal(t, executable, rid06HashExecutable(t)) })
	rid08Write(t, child.dir, "full-startup-provenance", map[string]any{"instrumentedTestExecutableSHA256": executable, "baseProductionAppSHA256": f.session.BinarySHA256, "pid": child.cmd.Process.Pid, "starttime": child.start, "cgroup": string(childCG), "observerOnly": true, "repositoryReplaced": false, "readerReplaced": false, "reverse": in.Reverse, "M1SHA256": in.M1Digest, "M2SHA256": in.M2Digest})
	rid09ArmAndRelease(t, f, child)
	return child
}

// Намеренно НЕ вызываем c.await: его seenEvent означает настоящую аутентификацию.
// Событие владения до запуска не может требовать выпущенных токенов при допустимом
// предварительном отказе. Глобальная семантика afterReap сохраняется побайтно.
func rid09ArmAndRelease(t *testing.T, f *installationNativeWorld, c *rid02OwnedChild) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 10*time.Second)
	defer cancel()
	require.False(t, c.seenEvent)
	var event rid02ChildEvent
	select {
	case event = <-c.events:
	case <-c.decodeError:
		t.Fatal("owned pre-auth startup handshake EOF/error")
	case <-c.exited:
		t.Fatal("owned child exited before ownership release")
	case <-ctx.Done():
		t.Fatal("owned pre-auth startup handshake deadline")
	}
	require.Equal(t, "whole-preauth-armed", event.Stage)
	require.Equal(t, c.cmd.Process.Pid, event.PID)
	require.Empty(t, event.Operation)
	start, err := rid02ProcessStart(c.cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, c.start, start)
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", c.cmd.Process.Pid))
	require.NoError(t, err)
	require.True(t, bytes.Equal(c.argv, argv))
	pgid, err := syscall.Getpgid(c.cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, c.cmd.Process.Pid, pgid)
	require.NoError(t, syscall.Kill(c.cmd.Process.Pid, 0))
	require.False(t, c.seenEvent)
	rid08Write(t, c.dir, "preauth-ownership-armed", map[string]any{"pid": event.PID, "starttime": start, "group": pgid, "preAuthentication": true, "issuedTokenClaimed": false, "provenanceRecordedBeforeRelease": true})
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	require.NoError(t, c.control.SetWriteDeadline(deadline))
	require.NoError(t, json.NewEncoder(c.control).Encode("start-full-startup"), "bounded full-startup release")
	require.NoError(t, ctx.Err())
	require.NoError(t, c.control.SetWriteDeadline(time.Time{}))
	require.False(t, c.seenEvent, "only actual successful authn/readiness may set this flag")
}
func rid09Ready(t *testing.T, f *installationNativeWorld, c *rid02OwnedChild) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.exited:
			t.Fatal("actual complete delivery exited before readiness")
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
			t.Fatal("full delivery readiness deadline")
		case <-ticker.C:
		}
	}
	c.seenEvent = true // успешная настоящая аутентификация требует непустого аудита настоящего токена FD5.
	require.NoError(t, installruntime.CheckOwnedListeners(c.cmd.Process.Pid, c.dir, installruntime.DefaultNativePorts().All()...))
	rid06ReadResult(t, c, installationResult{Stage: "delegation", Code: "OK", CompletedPairs: 6})
}
func rid09ReturnReceipt(t *testing.T, c *rid02OwnedChild, want codes.Code) ridWholeReturn {
	t.Helper()
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
	require.Equal(t, int32(want), out.Code)
	require.Equal(t, want != codes.OK, out.ErrorPresent)
	if want == codes.OK {
		require.Positive(t, out.CapturedRecords)
		require.Positive(t, out.IssuedTokens)
	} else {
		require.Zero(t, out.CapturedRecords, "shape/linkage refusal precedes startup authn")
		require.Zero(t, out.IssuedTokens)
	}
	return out
}
func rid09World(t *testing.T, in rid09Input, consumer rid09LivePublicConsumer) rid09Observation {
	t.Helper()
	f := newInstallationNativeWorldLifecycle(t, 7200, "", false, true)
	if consumer == nil {
		consumer = rid09DefaultNewmanConsumer(t, f, in)
	}
	accounts, namedSystem, initial, full := rid08SetupN3(t, f)
	require.Len(t, accounts, 3)
	require.EqualValues(t, 1, initial.Admitted)
	require.EqualValues(t, 3, full.Admitted)
	rid09RequireNoDelivery(t, f, accounts)
	beforePublic := rid09ReadPublic(t, f)
	if consumer != nil {
		consumer(t, f, in, "before")
	}
	f.requireSameCredential(t)
	rid09StopBase(t, f)
	before := ridReadWholeDelivery(t, f)
	ops := rid08GDOperations(t, f)
	require.Empty(t, ops)
	// Квитанция входа — точные несекретные порождённые байты манифеста. Все внешние
	// ID остаются возвращёнными штатной церемонией/учётными записями/подготовкой.
	rid08Write(t, f.session.Root, "whole-before", before)
	rid08Write(t, f.session.Root, "whole-input", in)
	out := rid09Observation{Axis: in.Axis, Field: in.Field, Reverse: in.Reverse, Twin: in.Twin, Accounts: accounts, NamedSystem: namedSystem, CanonicalSystem: f.baseline.SystemID, Before: before, PublicBefore: beforePublic, Input: in, NewmanExecuted: consumer != nil && os.Getenv("KANAME_RID_NEWMAN") == "1"}
	watch := f.wire.StartReadinessWatch(f.given.ctx)
	defer watch.Stop()
	spawned := time.Now().UTC()
	child := rid09Start(t, f, in)
	if !in.Twin {
		rid06WaitExit(t, child, 1)
		observations := watch.Stop()
		require.NotEmpty(t, observations)
		require.False(t, observations[0].FinishedAt.After(spawned))
		require.True(t, observations[0].TransportFailed)
		for _, o := range observations {
			require.NotEqual(t, http.StatusOK, o.HTTPStatus)
		}
		rid08Write(t, child.dir, "readiness-observations", observations)
		rid06ReadResult(t, child, installationResult{Stage: "preflight", Code: "INVALID_ARGUMENT", Field: in.Field, CompletedPairs: 0})
		// Загрузчик публикует INVALID_ARGUMENT выше, но возвращает свою обёрнутую
		// ошибку манифеста (module_manifests.go). Наблюдаем настоящий код Unknown
		// отдельно; не переименовываем его и не смешиваем результат запуска со статусом RPC.
		out.Return = rid09ReturnReceipt(t, child, codes.Unknown)
		out.After = ridReadWholeDelivery(t, f)
		rid08Write(t, f.session.Root, "whole-after", out.After)
		ridRequireWholeDeliveryUnchanged(t, before, out.After)
		require.Equal(t, ops, rid08GDOperations(t, f))
		// Читаем публичные последствия только после авторитетного доказательства до/после
		// остановленного процесса. Перезапуск — штатный запуск без поставки, а не починка.
		p, err := f.session.StartBase(f.given.ctx, f.writerPlan)
		require.NoError(t, err)
		require.NoError(t, p.OwnsListeners(installruntime.DefaultNativePorts().All()...))
		rid09RequireNoDelivery(t, f, accounts)
		out.PublicAfter = rid09ReadPublic(t, f)
		require.Equal(t, beforePublic, out.PublicAfter, "all existing public catalog/roles/groups/joins/grants remain unchanged")
		if consumer != nil {
			consumer(t, f, in, "after-negative")
		}
	} else {
		rid09Ready(t, f, child)
		watch.Stop()
		public := rid08PublicCensus(t, f, accounts)
		require.Len(t, public.Delegations, 6)
		out.GDPublic = &public
		rid08NewOperations(t, f, ops, 6)
		out.PublicAfter = rid09ReadPublic(t, f)
		rid09RequireFullDelivery(t, f, out.PublicAfter)
		if consumer != nil {
			consumer(t, f, in, "after-positive")
		}
		f.requireSameCredential(t)
		rid06GracefulStop(t, child)
		out.Return = rid09ReturnReceipt(t, child, codes.OK)
		out.After = ridReadWholeDelivery(t, f)
		rid08Write(t, f.session.Root, "whole-after", out.After)
		ridRequireOwnCeilingsPreserved(t, before, out.After)
		require.NotEqual(t, before.Delivery, out.After.Delivery)
		require.Equal(t, before.Delivery["accounts"], out.After.Delivery["accounts"])
		require.Equal(t, before.Delivery["cluster_admin_grants"], out.After.Delivery["cluster_admin_grants"])
	}
	rid08Write(t, f.session.Root, "rid09-completed-proof", out)
	return out
}
func rid09Matrix(t *testing.T, twin bool, consumer rid09LivePublicConsumer) []rid09Observation {
	t.Helper()
	// Проверяем все точные порождённые байты для ОБОИХ порядков файлов до первого PG.
	var inputs []rid09Input
	for _, reverse := range []bool{false, true} {
		inputs = append(inputs, rid09Inputs(t, reverse, twin)...)
	}
	require.Len(t, inputs, 8)
	out := []rid09Observation{}
	for _, in := range inputs {
		order := "M1-M2"
		if in.Reverse {
			order = "M2-M1"
		}
		kind := "negative"
		if twin {
			kind = "lawful-twin"
		}
		// Каждый неудачный мир очищается до следующего; собираем всю перепись.
		t.Run(in.Axis+"/"+order+"/"+kind, func(t *testing.T) { out = append(out, rid09World(t, in, consumer)) })
	}
	require.Len(t, out, 8)
	return out
}
func rid09RequireMatrixPreserved(t *testing.T, observed []rid09Observation) {
	t.Helper()
	require.Len(t, observed, 8)
	seen := map[string]bool{}
	for _, p := range observed {
		require.False(t, p.Twin)
		key := fmt.Sprintf("%s/%t", p.Axis, p.Reverse)
		require.False(t, seen[key])
		seen[key] = true
		require.Len(t, p.Accounts, 3)
		require.NotEqual(t, p.NamedSystem, p.CanonicalSystem)
		ridRequireWholeDeliveryUnchanged(t, p.Before, p.After)
		require.Equal(t, p.PublicBefore, p.PublicAfter)
		require.Equal(t, int32(codes.Unknown), p.Return.Code)
	}
}
