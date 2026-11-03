// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const ridNewmanInputEnv = "KANAME_RID_NEWMAN_CHILD_INPUT"

type ridNewmanToolInput struct {
	Probe                                                                            string
	PublicOrigin                                                                     string
	RequestPolicy                                                                    *ridNewmanRequestPolicy
	Node, Module, Collection, Script, CA, Cert, Key, CaseID, Evidence                string
	NodeSHA, ScriptSHA, CollectionSHA, PackageSHA, TreeSHA, TestExecutableSHA, RunID string
}
type ridNewmanReceipt struct {
	RID03ActGet            json.RawMessage         `json:"rid03ActGet,omitempty"`
	RID03ActGetObservation *rid03ActGetObservation `json:"-"`
	SchemaVersion          int                     `json:"schemaVersion"`
	OK                     bool                    `json:"ok"`
	CaseID                 string                  `json:"caseId"`
	CollectionSHA          string                  `json:"collectionSHA256"`
	NewmanVersion          string                  `json:"newmanVersion"`
	PackageSHA             string                  `json:"newmanPackageSHA256"`
	NodeSHA                string                  `json:"nodeSHA256"`
	RunnerSHA              string                  `json:"runnerSHA256"`
	TreeSHA                string                  `json:"toolTreeSHA256"`
	Producer               struct {
		RunID             string `json:"runId"`
		TestExecutableSHA string `json:"testExecutableSHA256"`
	} `json:"producer"`
	Counts struct {
		DeclaredRequests, UniqueRequests, Requests, Unanswered, Assertions, Failed, Skipped, FailureCount, WrongOrigin, UnexpectedItems, EmptyAssertionRequests int
		Missing                                                                                                                                                 []string
	} `json:"counts"`
}

func ridNewmanHash(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	require.LessOrEqual(t, n, int64(256<<20), "bounded tool artifact hash")
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}
func TestRIDNewmanOwnedPublicChild(t *testing.T) {
	path := os.Getenv(ridNewmanInputEnv)
	if path == "" {
		t.Skip("private owned Newman public client entrypoint")
	}
	own := func(fd uintptr, name string) *os.File {
		f := os.NewFile(fd, name)
		if f != nil {
			t.Cleanup(func() { _ = f.Close() })
		}
		require.NotNil(t, f)
		syscall.CloseOnExec(int(fd))
		return f
	}
	require.NoError(t, syscall.SetNonblock(3, true))
	events := own(3, "rid-newman-events")
	require.NoError(t, syscall.SetNonblock(4, true))
	control := own(4, "rid-newman-control")
	inventory := own(5, "rid-newman-anonymous-inventory")
	info, err := inventory.Stat()
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok && stat.Nlink == 0 && info.Mode().IsRegular() && info.Mode().Perm() == 0600)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var in ridNewmanToolInput
	require.NoError(t, json.Unmarshal(raw, &in))
	require.Equal(t, in.NodeSHA, ridNewmanHash(t, in.Node))
	require.Equal(t, in.ScriptSHA, ridNewmanHash(t, in.Script))
	require.Equal(t, in.CollectionSHA, ridNewmanHash(t, in.Collection))
	require.Equal(t, in.PackageSHA, ridNewmanHash(t, filepath.Join(in.Module, "package.json")))
	require.Equal(t, in.TestExecutableSHA, ridNewmanHash(t, os.Args[0]))
	tree, err := ridNewmanTreeManifest(in.Module)
	require.NoError(t, err)
	require.Equal(t, in.TreeSHA, tree.SHA)
	emit := func(stage string) {
		require.NoError(t, events.SetWriteDeadline(time.Now().Add(10*time.Second)))
		require.NoError(t, json.NewEncoder(events).Encode(rid02ChildEvent{Stage: stage, PID: os.Getpid()}))
	}
	// Parent captures exact Go-child argv/start/cgroup before supplying secrets.
	emit("newman-input")
	require.NoError(t, control.SetReadDeadline(time.Now().Add(20*time.Second)))
	var payload string
	require.NoError(t, json.NewDecoder(control).Decode(&payload))
	require.LessOrEqual(t, len(payload), 1<<20)
	var data struct {
		Variables         map[string]any  `json:"variables"`
		PublicOrigin      string          `json:"ownRestBaseUrl"`
		RequestPolicy     json.RawMessage `json:"requestPolicy"`
		RunID             string          `json:"runId"`
		TestExecutableSHA string          `json:"testExecutableSHA256"`
	}
	require.NoError(t, json.Unmarshal([]byte(payload), &data))
	require.Equal(t, in.RunID, data.RunID)
	require.Equal(t, in.TestExecutableSHA, data.TestExecutableSHA)
	policy, err := ridNewmanDecodeRequestPolicy(data.RequestPolicy)
	require.NoError(t, err)
	require.True(t, in.PublicOrigin == data.PublicOrigin, "payload public origin differs from parent-bound input")
	require.True(t, reflect.DeepEqual(in.RequestPolicy, policy), "payload request policy differs from parent-bound input")
	require.NoError(t, ridNewmanValidateRequestPolicy(in.CaseID, data.PublicOrigin, policy, data.Variables))
	stem := strings.SplitN(in.CaseID, "-", 4)
	require.Len(t, stem, 4)
	bearers, err := ridNewmanClientSecrets(strings.Join(stem[:3], "-"), in.CaseID, data.Variables)
	require.NoError(t, err)
	// Actual O, phase-bound C and opaque assertion secrets are captured before
	// the TLS key read and before any Node process can receive their bytes.
	require.NoError(t, ridNewmanRecordBearers(inventory, bearers))
	privateKey, err := os.ReadFile(in.Key)
	require.NoError(t, err)
	require.NoError(t, json.NewEncoder(inventory).Encode([]string{string(privateKey), bearers[0]}))
	dir := filepath.Join(in.Evidence, "newman")
	info, err = os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir() && info.Mode().Perm() == 0700)
	out, err := os.OpenFile(filepath.Join(dir, "stdout"), os.O_WRONLY|os.O_APPEND, 0600)
	if out != nil {
		t.Cleanup(func() { _ = out.Close() })
	}
	require.NoError(t, err)
	stderr, err := os.OpenFile(filepath.Join(dir, "stderr"), os.O_WRONLY|os.O_APPEND, 0600)
	if stderr != nil {
		t.Cleanup(func() { _ = stderr.Close() })
	}
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.Node, in.Script, in.Collection, in.Module, in.CA, in.Cert, in.Key, in.CaseID)
	cmd.Stdout = out
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdin.Close() })
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "PATH=" + filepath.Dir(in.Node) + ":/usr/bin:/bin", "NODE_OPTIONS=--max-old-space-size=256", "NO_PROXY=localhost,127.0.0.1"}
	ackRead, ackWrite, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	permitRead, permitWrite, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	closeProtocol := func() { _ = ackRead.Close(); _ = ackWrite.Close(); _ = permitRead.Close(); _ = permitWrite.Close() }
	t.Cleanup(closeProtocol)
	// The Go child's control/event/secret descriptors must not reach Node.
	for _, fd := range []int{3, 4, 5} {
		syscall.CloseOnExec(fd)
	}
	cmd.ExtraFiles = []*os.File{ackWrite, permitRead}
	require.NoError(t, cmd.Start())
	t.Cleanup(closeProtocol)
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); _ = out.Close(); _ = stderr.Close(); close(done) }()
	// Installed immediately after Start, before ownership reads or assertions.
	t.Cleanup(func() {
		select {
		case <-done:
		default:
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned Newman process not reaped")
			return
		}
		rid02CheckStreams(t, []string{filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")}, append(append([]string{}, bearers...), string(privateKey)))
		status, statusOK := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if !statusOK {
			t.Error("actual Node terminal wait status unavailable")
			return
		}
		terminal, _ := json.Marshal(map[string]any{"pid": cmd.Process.Pid, "exited": cmd.ProcessState.Exited() || status.Signaled(), "exitCode": cmd.ProcessState.ExitCode(), "signaled": status.Signaled(), "signal": status.Signal().String()})
		if err := os.WriteFile(filepath.Join(dir, "terminal.json"), terminal, 0600); err != nil {
			t.Error("Newman terminal receipt unavailable")
		}
	})
	_ = ackWrite.Close()
	_ = permitRead.Close()
	start, err := rid02ProcessStart(cmd.Process.Pid)
	require.NoError(t, err)
	expected := append([]string{in.Node}, cmd.Args[1:]...)
	deadline := time.Now().Add(2 * time.Second)
	var argv []byte
	for {
		argv, err = os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cmdline")
		require.NoError(t, err)
		if string(argv) == strings.Join(expected, "\x00")+"\x00" {
			break
		}
		current, e := rid02ProcessStart(cmd.Process.Pid)
		require.NoError(t, e)
		require.Equal(t, start, current)
		require.NoError(t, syscall.Kill(cmd.Process.Pid, 0))
		require.True(t, time.Now().Before(deadline), "Node argv capture deadline")
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal(t, strings.Join(expected, "\x00")+"\x00", string(argv))
	actualStart, err := rid02ProcessStart(cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, start, actualStart)
	group, err := syscall.Getpgid(cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, syscall.Getpgrp(), group, "Node must remain in the owned Go-child process group")
	parentCG, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	nodeCG, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cgroup")
	require.NoError(t, err)
	require.True(t, bytes.Equal(parentCG, nodeCG))
	ownership, _ := json.Marshal(map[string]any{"pid": cmd.Process.Pid, "starttime": start, "argv": expected, "group": group, "cgroup": string(nodeCG), "nodeSHA256": in.NodeSHA, "scriptSHA256": in.ScriptSHA})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "process.json"), ownership, 0600))
	// Node runner is still waiting for stdin. Parent independently captures
	// the actual Node identity/group before any secret/HTTP admission.
	emit("newman-node-armed")
	require.NoError(t, control.SetReadDeadline(time.Now().Add(20*time.Second)))
	var nodeRelease string
	require.NoError(t, json.NewDecoder(control).Decode(&nodeRelease))
	require.True(t, nodeRelease == "admit-owned-node", "unexpected Node admission")
	inputPipe, ok := stdin.(*os.File)
	require.True(t, ok, "Node input must be a deadline-capable owned pipe")
	require.NoError(t, inputPipe.SetWriteDeadline(time.Now().Add(15*time.Second)))
	_, err = io.WriteString(stdin, payload)
	require.NoError(t, err)
	require.NoError(t, stdin.Close())
	require.NoError(t, ridNewmanAwaitACK(ctx, ackRead, cmd.Process.Pid, in.CaseID, in.RunID))
	_ = ackRead.Close()
	emit("newman-node-input-validated")
	deadline, bounded := ctx.Deadline()
	require.True(t, bounded)
	require.NoError(t, control.SetReadDeadline(deadline))
	var permitMessage string
	require.NoError(t, json.NewDecoder(control).Decode(&permitMessage))
	require.True(t, permitMessage == ridNewmanPermitMessage(in.Probe), "unexpected post-ACK Node permit decision")
	if permitMessage == "permit-owned-node" {
		require.NoError(t, permitWrite.SetWriteDeadline(deadline))
		_, writeErr := io.WriteString(permitWrite, ridNewmanPermitFrame)
		require.NoError(t, writeErr)
	}
	require.NoError(t, permitWrite.Close())
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("bounded owned Newman client deadline")
	}
	if in.Probe == "reject-missing-permit" {
		var exit *exec.ExitError
		require.ErrorAs(t, waitErr, &exit)
		require.Equal(t, 1, exit.ExitCode())
		var refusal struct {
			OK   bool   `json:"ok"`
			Kind string `json:"kind"`
		}
		raw, readErr := os.ReadFile(filepath.Join(dir, "stdout"))
		require.NoError(t, readErr)
		require.NoError(t, json.Unmarshal(raw, &refusal))
		require.False(t, refusal.OK)
		require.Equal(t, "node-permit-rejected", refusal.Kind)
		emit("newman-probe-finished")
		return
	}
	require.NoError(t, waitErr, "Newman failed; sanitized private report retained")
	raw, err = os.ReadFile(filepath.Join(dir, "stdout"))
	require.NoError(t, err)
	var receipt ridNewmanReceipt
	require.NoError(t, rid03CheckReceiptObservationField(raw))
	require.NoError(t, json.Unmarshal(raw, &receipt))
	observation, observationErr := rid03DecodeReceiptObservation(receipt.CaseID, receipt.RID03ActGet)
	require.NoError(t, observationErr)
	receipt.RID03ActGetObservation = observation
	require.True(t, receipt.OK, "Newman public assertions/coverage failed; arbitrary messages withheld")
	require.Equal(t, in.CaseID, receipt.CaseID)
	require.Equal(t, in.CollectionSHA, receipt.CollectionSHA)
	require.Equal(t, in.PackageSHA, receipt.PackageSHA)
	require.Equal(t, in.NodeSHA, receipt.NodeSHA)
	require.Equal(t, in.ScriptSHA, receipt.RunnerSHA)
	require.Equal(t, in.TreeSHA, receipt.TreeSHA)
	require.Equal(t, in.RunID, receipt.Producer.RunID)
	require.Equal(t, in.TestExecutableSHA, receipt.Producer.TestExecutableSHA)
	require.Equal(t, in.NodeSHA, ridNewmanHash(t, in.Node))
	require.Equal(t, in.ScriptSHA, ridNewmanHash(t, in.Script))
	require.Equal(t, in.PackageSHA, ridNewmanHash(t, filepath.Join(in.Module, "package.json")))
	require.Equal(t, "6.2.2", receipt.NewmanVersion)
	require.Positive(t, receipt.Counts.Assertions)
	require.Positive(t, receipt.Counts.Requests)
	require.Equal(t, receipt.Counts.DeclaredRequests, receipt.Counts.UniqueRequests)
	require.Zero(t, receipt.Counts.FailureCount)
	require.Zero(t, receipt.Counts.WrongOrigin)
	require.Zero(t, receipt.Counts.UnexpectedItems)
	require.Zero(t, receipt.Counts.EmptyAssertionRequests)
	require.Zero(t, receipt.Counts.Unanswered)
	require.Zero(t, receipt.Counts.Failed)
	require.Zero(t, receipt.Counts.Skipped)
	require.Empty(t, receipt.Counts.Missing)
	emit("newman-finished")
}
func ridNewmanAwait(t *testing.T, c *rid02OwnedChild, ctx context.Context, stage string) {
	t.Helper()
	check := func(e rid02ChildEvent) {
		require.Equal(t, stage, e.Stage)
		require.Equal(t, c.cmd.Process.Pid, e.PID)
		require.Empty(t, e.Operation)
	}
	select {
	case e := <-c.events:
		check(e)
	case err := <-c.decodeError:
		select {
		case e := <-c.events:
			check(e)
		default:
			t.Fatalf("Newman child IPC unavailable (type %T)", err)
		}
	case <-ctx.Done():
		t.Fatal("Newman child IPC deadline")
	}
}
func ridRunNewmanPhase(t *testing.T, f *installationNativeWorld, stem, caseID, label string, variables map[string]any) ridNewmanReceipt {
	return ridRunNewmanPhaseMode(t, f, stem, caseID, label, variables, "")
}
func ridRunNewmanPhaseMode(t *testing.T, f *installationNativeWorld, stem, caseID, label string, variables map[string]any, probe string) ridNewmanReceipt {
	require.Contains(t, []string{"", "normal-permit", "reject-missing-permit", "node-kill", "group-kill"}, probe)

	t.Helper()
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		rid08Write(t, f.session.Root, "newman-"+label, map[string]any{"state": "NOT_EXECUTED", "caseId": caseID, "wholeDoDAccepted": false})
		return ridNewmanReceipt{}
	}
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	node := os.Getenv("KANAME_RID_NODE_BINARY")
	module := os.Getenv("KANAME_RID_NEWMAN_MODULE")
	require.True(t, filepath.IsAbs(node) && filepath.IsAbs(module), "explicit immutable Newman tool inputs required")
	f.renewOperator(t, f.given.ctx)
	variables["jwtRIDOperator"] = f.operator.Bearer()
	bearers, err := ridNewmanClientSecrets(stem, caseID, variables)
	require.NoError(t, err)
	f.secrets = append(f.secrets, bearers...)
	policy, err := ridNewmanParentRequestPolicy(caseID, f.wire.PublicURL, f.wire.IssuanceURL, variables)
	require.NoError(t, err)
	runID := os.Getenv("KANAME_RID_RUN_ID")
	require.Regexp(t, "^[A-Za-z0-9-]{16,80}$", runID, "explicit fresh owned run ID required")
	executableSHA := ridNewmanHash(t, os.Args[0])
	in := ridNewmanToolInput{Node: node, Module: module, Collection: filepath.Join(root, "tests/newman/collections", stem+".postman_collection.json"), Script: filepath.Join(root, "tests/newman/scripts/run-rid-native.cjs"), CA: filepath.Join(f.session.Root, "pki", "ca.crt"), Cert: filepath.Join(f.session.Root, "pki", "srv.crt"), Key: filepath.Join(f.session.Root, "pki", "srv.key"), CaseID: caseID, Evidence: filepath.Join(f.session.Root, "newman-"+label)}
	in.PublicOrigin, in.RequestPolicy = f.wire.PublicURL, policy
	in.Probe = probe
	in.NodeSHA = ridNewmanHash(t, in.Node)
	in.ScriptSHA = ridNewmanHash(t, in.Script)
	in.CollectionSHA = ridNewmanHash(t, in.Collection)
	in.PackageSHA = ridNewmanHash(t, filepath.Join(in.Module, "package.json"))
	in.TestExecutableSHA, in.RunID = executableSHA, runID
	tree, err := ridNewmanTreeManifest(in.Module)
	require.NoError(t, err)
	in.TreeSHA = tree.SHA
	expected, err := ridNewmanExpectedForCollection(
		os.Getenv("KANAME_RID_EXPECTED_IDENTITIES_FILE"),
		os.Getenv("KANAME_RID_EXPECTED_IDENTITIES_DIR"), stem)
	require.NoError(t, err, "externally frozen exact source/toolchain identities required")
	require.Equal(t, expected.Node, in.NodeSHA)
	require.Equal(t, expected.Runner, in.ScriptSHA)
	require.Equal(t, expected.Tree, in.TreeSHA)
	require.Equal(t, expected.Collection, in.CollectionSHA)
	require.Equal(t, expected.Test, in.TestExecutableSHA)
	payload, err := json.Marshal(map[string]any{"ownRestBaseUrl": f.wire.PublicURL, "variables": variables, "runId": runID, "testExecutableSHA256": executableSHA, "expectedIdentities": expected, "requestPolicy": policy})
	require.NoError(t, err)
	require.LessOrEqual(t, len(payload), 1<<20)
	c := startRIDInstallationChild(t, f, "newman-"+label, in, f.session.Environment, ridNewmanInputEnv, "TestRIDNewmanOwnedPublicChild", "3m")
	// Parent creates both mandatory streams and installs the fallback auditor
	// BEFORE control-payload admission can create any Node process.
	dir := filepath.Join(c.dir, "newman")
	require.NoError(t, os.Mkdir(dir, 0700))
	for _, name := range []string{"stdout", "stderr"} {
		stream, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if stream != nil {
			t.Cleanup(func() { _ = stream.Close() })
		}
		require.NoError(t, e)
		require.NoError(t, stream.Close())
	}
	admitted := false
	var actualKey string
	var auditResult *ridNewmanAuditResult
	c.afterReapAudit = func(t *testing.T, secrets []string) {
		if !admitted {
			return
		}
		result := ridNewmanCollectParentAudit(c, in, secrets, append(append([]string{}, bearers...), actualKey))
		auditResult = &result
		rid08Write(t, dir, "parent-structured-audit", result)
		if probe == "group-kill" {
			if !ridNewmanGroupKillAccepted(result) {
				ridNewmanReportParentAudit(t, result)
				t.Error("whole-group detector requires exact MISSING_NODE_TERMINAL plus all real independent checks")
			}
		} else {
			ridNewmanReportParentAudit(t, result)
		}
	}
	rid08Write(t, dir, "tool-tree-before-parent", tree)
	ctx, cancel := context.WithTimeout(f.given.ctx, 120*time.Second)
	defer cancel()
	ridNewmanAwait(t, c, ctx, "newman-input")
	require.NoError(t, c.control.SetWriteDeadline(time.Now().Add(15*time.Second)))
	// Capture each actual secret before any subsequent fallible step or Node
	// admission. FD5 is already anonymous/unlinked; no inventory pathname exists.
	require.NoError(t, ridNewmanRecordBearers(c.secretInventory, bearers))
	keyBytes, err := os.ReadFile(in.Key)
	require.NoError(t, err)
	actualKey = string(keyBytes)
	require.NoError(t, json.NewEncoder(c.secretInventory).Encode([]string{actualKey, bearers[0]}))
	admitted = true
	rid08Write(t, dir, "parent-admission", map[string]any{"ownedGroup": c.cmd.Process.Pid, "goStarttime": c.start, "nodeSHA256": in.NodeSHA, "runnerSHA256": in.ScriptSHA, "toolTreeSHA256": in.TreeSHA})
	c.release(t, string(payload))
	ridNewmanAwait(t, c, ctx, "newman-node-armed")
	ridNewmanParentObserveNode(t, c, in)
	require.NoError(t, c.control.SetWriteDeadline(time.Now().Add(10*time.Second)))
	c.release(t, "admit-owned-node")
	ridNewmanAwait(t, c, ctx, "newman-node-input-validated")
	ridNewmanParentObserveNodeStage(t, c, in, true)
	if probe == "group-kill" {
		require.NoError(t, c.kill())
		absenceCtx, absenceCancel := context.WithTimeout(ctx, 10*time.Second)
		defer absenceCancel()
		ridNewmanAwaitNodeAbsent(t, absenceCtx, c)
		select {
		case <-c.exited:
		case <-ctx.Done():
			t.Fatal("whole-group child reap exceeded overall deadline")
		}
		c.wait(t, true)
		require.NotNil(t, auditResult)
		require.True(t, ridNewmanGroupKillAccepted(*auditResult))
		rid08Write(t, f.session.Root, label+"-protocol-result", map[string]any{"detector": "INCOMPLETE_TERMINAL_DETECTED", "audit": auditResult, "publicAcceptance": false})
		return ridNewmanReceipt{}
	}
	if probe == "node-kill" {
		ridNewmanKillExactNode(t, c, in)
	}
	require.NoError(t, c.control.SetWriteDeadline(time.Now().Add(10*time.Second)))
	c.release(t, ridNewmanPermitMessage(probe))
	if probe == "node-kill" {
		select {
		case <-c.exited:
		case <-ctx.Done():
			t.Fatal("Node-kill Go child terminal exceeded overall deadline")
		}
		c.waitExpectedExit(t, 1)
		ridNewmanAssertNodeTerminal(t, c, true)
		require.NotNil(t, auditResult)
		require.Empty(t, auditResult.Errors)
		rid08Write(t, f.session.Root, label+"-protocol-result", map[string]any{"detector": "NODE_SIGKILL_HONEST_TERMINAL", "audit": auditResult, "publicAcceptance": false})
		return ridNewmanReceipt{}
	}
	if probe == "reject-missing-permit" {
		ridNewmanAwait(t, c, ctx, "newman-probe-finished")
		c.wait(t, false)
		ridNewmanAssertNodeTerminal(t, c, false)
		require.NotNil(t, auditResult)
		require.Empty(t, auditResult.Errors)
		rid08Write(t, f.session.Root, label+"-protocol-result", map[string]any{"detector": "MISSING_PERMIT_REJECTED", "audit": auditResult, "publicAcceptance": false})
		return ridNewmanReceipt{}
	}
	ridNewmanAwait(t, c, ctx, "newman-finished")
	c.seenEvent = true
	c.wait(t, false)
	raw, err := os.ReadFile(filepath.Join(c.dir, "newman", "stdout"))
	require.NoError(t, err)
	var receipt ridNewmanReceipt
	require.NoError(t, rid03CheckReceiptObservationField(raw))
	require.NoError(t, json.Unmarshal(raw, &receipt))
	observation, observationErr := rid03DecodeReceiptObservation(receipt.CaseID, receipt.RID03ActGet)
	require.NoError(t, observationErr)
	receipt.RID03ActGetObservation = observation
	require.True(t, receipt.OK)
	if probe == "" {
		rid08Write(t, f.session.Root, "newman-"+label+"-accepted", receipt)
	} else {
		rid08Write(t, f.session.Root, label+"-protocol-result", map[string]any{"detector": "NORMAL_PERMIT_ACTUAL_HTTP", "receipt": receipt, "publicAcceptance": false})
	}
	return receipt
}
