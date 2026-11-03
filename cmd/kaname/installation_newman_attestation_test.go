// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Same v1 canonical record algorithm as run-rid-native.cjs and the isolated
// synthetic premise. No symlink is followed while walking; its resolved target
// MUST stay inside root, and require.cache checks demand actual attested files.
type ridNewmanTree struct {
	SHA     string   `json:"sha256"`
	Entries []string `json:"entries"`
	Files   int      `json:"files"`
	Bytes   int64    `json:"bytes"`
}
type ridNewmanExpected struct {
	Node       string `json:"nodeSHA256"`
	Runner     string `json:"runnerSHA256"`
	Tree       string `json:"toolTreeSHA256"`
	Collection string `json:"collectionSHA256"`
	Test       string `json:"testExecutableSHA256"`
}

func ridNewmanTreeManifest(root string) (ridNewmanTree, error) {
	out := ridNewmanTree{Entries: []string{}}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return out, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return out, err
	}
	var count int
	visit := func(p string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if p == root {
			return nil
		}
		count++
		if count > 32768 {
			return fmt.Errorf("tool tree entry bound")
		}
		rel, e := filepath.Rel(root, p)
		if e != nil {
			return e
		}
		rel = filepath.ToSlash(rel)
		if len(rel) > 4096 {
			return fmt.Errorf("tool path bound")
		}
		for _, b := range []byte(rel) {
			if b < 32 || b > 126 {
				return fmt.Errorf("tool path alphabet")
			}
		}
		mode := fmt.Sprintf("%03o", info.Mode().Perm())
		kind, value := "", ""
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, e := filepath.EvalSymlinks(p)
			if e != nil {
				return e
			}
			r, e := filepath.Rel(root, target)
			if e != nil || r == ".." || strings.HasPrefix(r, ".."+string(os.PathSeparator)) || filepath.IsAbs(r) {
				return fmt.Errorf("tool symlink escape")
			}
			value = filepath.ToSlash(r)
			kind = "S"
			for _, b := range []byte(value) {
				if b < 32 || b > 126 {
					return fmt.Errorf("tool link alphabet")
				}
			}
		case info.IsDir():
			kind = "D"
			value = "-"
		case info.Mode().IsRegular():
			if info.Size() > 32<<20 {
				return fmt.Errorf("tool file bound")
			}
			out.Files++
			out.Bytes += info.Size()
			if out.Bytes > 256<<20 {
				return fmt.Errorf("tool tree byte bound")
			}
			f, e := os.Open(p)
			if e != nil {
				return e
			}
			h := sha256.New()
			n, e := io.Copy(h, io.LimitReader(f, (32<<20)+1))
			_ = f.Close()
			if e != nil {
				return e
			}
			if n != info.Size() {
				return fmt.Errorf("tool file changed while hashing")
			}
			value = hex.EncodeToString(h.Sum(nil))
			kind = "F"
		default:
			return fmt.Errorf("tool tree special file")
		}
		out.Entries = append(out.Entries, kind+"\t"+rel+"\t"+mode+"\t"+value+"\n")
		return nil
	}
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > 128 {
			return fmt.Errorf("tool tree depth bound")
		}
		f, e := os.Open(dir)
		if e != nil {
			return e
		}
		defer f.Close()
		for {
			batch, e := f.Readdir(128)
			for _, info := range batch {
				p := filepath.Join(dir, info.Name())
				if e := visit(p, info, nil); e != nil {
					return e
				}
				if info.IsDir() {
					if e := walk(p, depth+1); e != nil {
						return e
					}
				}
			}
			if e == io.EOF {
				return nil
			}
			if e != nil {
				return e
			}
		}
	}
	err = walk(root, 0)
	if err != nil {
		return out, err
	}
	if out.Files == 0 {
		return out, fmt.Errorf("empty tool tree")
	}
	sort.Strings(out.Entries)
	h := sha256.Sum256([]byte(strings.Join(out.Entries, "")))
	out.SHA = hex.EncodeToString(h[:])
	return out, nil
}

// Registered in the parent before it releases ANY Node input. Unlike Go-child
// Cleanup this still executes after a forced kill of that entire owned group.
type ridNewmanAuditError struct{ Code, Message string }
type ridNewmanAuditResult struct {
	Checks  map[string]bool
	Streams rid02StreamScan
	Errors  []ridNewmanAuditError
}

func ridNewmanGroupKillAccepted(r ridNewmanAuditResult) bool {
	if r.Streams.Requested != 4 || r.Streams.Metadata != 4 || r.Streams.Read != 4 || r.Streams.JWTChecks != 4 || r.Streams.PEMChecks != 4 || r.Streams.SecretChecks == 0 || len(r.Streams.Errors) != 0 {
		return false
	}
	if len(r.Errors) != 1 || r.Errors[0].Code != "MISSING_NODE_TERMINAL" {
		return false
	}
	for _, key := range []string{"allFourStreams", "actualFD5Secrets", "nodeIdentity", "preStdinIdentity", "postACKIdentity", "nodeAbsent", "groupAbsent", "toolTree", "allToolIdentityReads"} {
		if !r.Checks[key] {
			return false
		}
	}
	return true
}
func ridNewmanReportParentAudit(t *testing.T, r ridNewmanAuditResult) {
	t.Helper()
	for _, err := range r.Errors {
		t.Error(err.Code + ": " + err.Message)
	}
}
func ridNewmanParentAudit(t *testing.T, c *rid02OwnedChild, in ridNewmanToolInput, secrets []string, required ...string) {
	t.Helper()
	ridNewmanReportParentAudit(t, ridNewmanCollectParentAudit(c, in, secrets, required))
}

func ridNewmanCollectParentAudit(c *rid02OwnedChild, in ridNewmanToolInput, secrets, required []string) ridNewmanAuditResult {
	r := ridNewmanAuditResult{Checks: map[string]bool{}}
	add := func(code, message string) { r.Errors = append(r.Errors, ridNewmanAuditError{code, message}) }
	dir := filepath.Join(c.dir, "newman")
	r.Streams = rid02ScanStreams([]string{filepath.Join(c.dir, "stdout"), filepath.Join(c.dir, "stderr"), filepath.Join(dir, "stdout"), filepath.Join(dir, "stderr")}, secrets)
	for _, err := range r.Streams.Errors {
		add("STREAM_AUDIT", err)
	}
	r.Checks["allFourStreams"] = r.Streams.Requested == 4 && r.Streams.Metadata == 4 && r.Streams.Read == 4 && r.Streams.JWTChecks == 4 && r.Streams.PEMChecks == 4 && r.Streams.SecretChecks > 0
	if err := ridNewmanAuditAnonymousInventory(c.secretInventory, required); err != nil {
		add("FD5_AUDIT", "anonymous FD5 actual secret audit failed")
	} else {
		r.Checks["actualFD5Secrets"] = true
	}
	var identity struct {
		PID       int      `json:"pid"`
		Start     string   `json:"starttime"`
		Group     int      `json:"group"`
		Argv      []string `json:"argv"`
		NodeSHA   string   `json:"nodeSHA256"`
		ScriptSHA string   `json:"scriptSHA256"`
	}
	fullNodeIdentity := false
	raw, err := os.ReadFile(filepath.Join(dir, "process.json"))
	if err != nil {
		add("PARENT_AUDIT", "mandatory nested Node ownership receipt missing after admission")
	} else if json.Unmarshal(raw, &identity) != nil {
		add("PARENT_AUDIT", "nested Node ownership receipt invalid")
	} else {
		expected := []string{in.Node, in.Script, in.Collection, in.Module, in.CA, in.Cert, in.Key, in.CaseID}
		fullNodeIdentity = identity.PID > 0 && identity.Start != "" && identity.Group == c.cmd.Process.Pid && strings.Join(identity.Argv, "\x00") == strings.Join(expected, "\x00") && identity.NodeSHA == in.NodeSHA && identity.ScriptSHA == in.ScriptSHA
		if !fullNodeIdentity {
			add("PARENT_AUDIT", "nested Node ownership does not match admitted child and toolchain")
		}
		if identity.PID > 0 {
			if _, e := os.Stat("/proc/" + strconv.Itoa(identity.PID)); !errors.Is(e, os.ErrNotExist) {
				add("PARENT_AUDIT", "nested Node PID not proven absent independently")
			}
		}
	}
	var parent struct {
		PID         int    `json:"pid"`
		Start       string `json:"starttime"`
		Group       int    `json:"group"`
		ArgvExact   bool   `json:"argvExact"`
		SameCgroup  bool   `json:"sameBoundedCgroup"`
		BeforeStdin bool   `json:"beforeNodeStdin"`
	}
	observed, e := os.ReadFile(filepath.Join(dir, "parent-node-ownership.json"))
	if e != nil || json.Unmarshal(observed, &parent) != nil || parent.PID != identity.PID || parent.Start != identity.Start || parent.Group != c.cmd.Process.Pid || !parent.ArgvExact || !parent.SameCgroup || !parent.BeforeStdin {
		add("PARENT_AUDIT", "independent parent Node ownership proof missing or inconsistent")
	}
	if e := syscall.Kill(-c.cmd.Process.Pid, 0); !errors.Is(e, syscall.ESRCH) {
		add("PARENT_AUDIT", "nested Node owning process group not proven absent")
	}
	var postACK struct {
		PID        int    `json:"pid"`
		Start      string `json:"starttime"`
		Group      int    `json:"group"`
		ArgvExact  bool   `json:"argvExact"`
		SameCgroup bool   `json:"sameBoundedCgroup"`
		AfterACK   bool   `json:"afterInputValidationACK"`
	}
	ackReceipt, ackErr := os.ReadFile(filepath.Join(dir, "parent-node-input-validated-ownership.json"))
	r.Checks["postACKIdentity"] = ackErr == nil && json.Unmarshal(ackReceipt, &postACK) == nil && postACK.PID == identity.PID && postACK.Start == identity.Start && postACK.Group == c.cmd.Process.Pid && postACK.ArgvExact && postACK.SameCgroup && postACK.AfterACK
	if !r.Checks["postACKIdentity"] {
		add("PARENT_AUDIT", "independent post-ACK Node identity proof missing or inconsistent")
	}
	var terminal struct {
		PID      int  `json:"pid"`
		Exited   bool `json:"exited"`
		ExitCode int  `json:"exitCode"`
	}
	raw, err = os.ReadFile(filepath.Join(dir, "terminal.json"))
	if err != nil {
		add(ridNewmanTerminalReadCode(err), "mandatory nested Node terminal receipt unavailable; full stream audit still performed")
	} else if json.Unmarshal(raw, &terminal) != nil || !terminal.Exited || terminal.PID != identity.PID {
		add("PARENT_AUDIT", "nested Node terminal receipt inconsistent")
	}
	r.Checks["nodeIdentity"] = fullNodeIdentity
	r.Checks["preStdinIdentity"] = parent.PID == identity.PID && parent.Start == identity.Start && parent.ArgvExact && parent.SameCgroup && parent.BeforeStdin
	_, nodeStatErr := os.Stat("/proc/" + strconv.Itoa(identity.PID))
	r.Checks["nodeAbsent"] = identity.PID > 0 && errors.Is(nodeStatErr, os.ErrNotExist)
	r.Checks["groupAbsent"] = errors.Is(syscall.Kill(-c.cmd.Process.Pid, 0), syscall.ESRCH)
	after, e := ridNewmanTreeManifest(in.Module)
	if e != nil {
		add("PARENT_AUDIT", "bounded post-reap tool tree census failed")
	} else {
		r.Checks["toolTree"] = after.SHA == in.TreeSHA
		if after.SHA != in.TreeSHA {
			add("PARENT_AUDIT", "complete Newman tool tree changed")
		}
		b, e := json.Marshal(after)
		if e != nil || os.WriteFile(filepath.Join(dir, "tool-tree-after-parent.json"), b, 0600) != nil {
			add("PARENT_AUDIT", "parent tool tree evidence unavailable")
		}
	}
	toolReads := 0
	for _, item := range []struct{ path, want string }{{in.Node, in.NodeSHA}, {in.Script, in.ScriptSHA}, {in.Collection, in.CollectionSHA}} {
		if ridNewmanVerifiedToolRead(item.path, item.want) {
			toolReads++
		} else {
			add("PARENT_AUDIT", "parent bounded tool/source identity verification failed")
		}
	}
	r.Checks["allToolIdentityReads"] = toolReads == 3
	return r
}

func ridNewmanTerminalReadCode(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "MISSING_NODE_TERMINAL"
	}
	return "UNEXPECTED_NODE_TERMINAL_IO"
}
func ridNewmanVerifiedToolRead(path, want string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (256<<20)+1))
	return err == nil && n <= 256<<20 && hex.EncodeToString(h.Sum(nil)) == want
}

// Independent parent-side proof while Node is live but has received no stdin.
func ridNewmanParentObserveNode(t *testing.T, c *rid02OwnedChild, in ridNewmanToolInput) {
	ridNewmanParentObserveNodeStage(t, c, in, false)
}
func ridNewmanParentObserveNodeStage(t *testing.T, c *rid02OwnedChild, in ridNewmanToolInput, afterACK bool) {
	t.Helper()
	dir := filepath.Join(c.dir, "newman")
	var identity struct {
		PID   int      `json:"pid"`
		Start string   `json:"starttime"`
		Group int      `json:"group"`
		Argv  []string `json:"argv"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "process.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &identity))
	require.Positive(t, identity.PID)
	start, err := rid02ProcessStart(identity.PID)
	require.NoError(t, err)
	require.Equal(t, identity.Start, start)
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", identity.PID))
	require.NoError(t, err)
	expected := []string{in.Node, in.Script, in.Collection, in.Module, in.CA, in.Cert, in.Key, in.CaseID}
	require.True(t, bytes.Equal(argv, []byte(strings.Join(expected, "\x00")+"\x00")))
	group, err := syscall.Getpgid(identity.PID)
	require.NoError(t, err)
	require.Equal(t, c.cmd.Process.Pid, group)
	require.Equal(t, identity.Group, group)
	own, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	node, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", identity.PID))
	require.NoError(t, err)
	require.True(t, bytes.Equal(own, node))
	require.NoError(t, syscall.Kill(identity.PID, 0))
	label := "parent-node-ownership"
	if afterACK {
		label = "parent-node-input-validated-ownership"
	}
	rid08Write(t, dir, label, map[string]any{"pid": identity.PID, "starttime": start, "group": group, "argvExact": true, "sameBoundedCgroup": true, "beforeNodeStdin": !afterACK, "afterInputValidationACK": afterACK})
}
