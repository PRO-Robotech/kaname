// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// OwnsListeners checks actual Linux socket ownership, not just port readiness.
// Every listening socket of this PID must be IPv4 loopback and in the census.
func (p *Process) OwnsListeners(expected ...int) error {
	root := fmt.Sprintf("/proc/%d", p.cmd.Process.Pid)
	entries, err := os.ReadDir(filepath.Join(root, "fd"))
	if err != nil {
		return err
	}
	inodes := map[string]bool{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(root, "fd", entry.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if strings.HasPrefix(target, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	found := map[int]bool{}
	for _, family := range []string{"tcp", "tcp6"} {
		raw, err := os.ReadFile(filepath.Join(root, "net", family))
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(raw), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" || !inodes[fields[9]] {
				continue
			}
			address, port, _ := strings.Cut(fields[1], ":")
			if family != "tcp" || address != "0100007F" {
				return fmt.Errorf("native serve owns a non-loopback listener")
			}
			number, err := strconv.ParseInt(port, 16, 32)
			if err != nil {
				return err
			}
			found[int(number)] = true
		}
	}
	if len(found) != len(expected) {
		return fmt.Errorf("native serve listener count: got %d expected %d", len(found), len(expected))
	}
	for _, port := range expected {
		if !found[port] {
			return fmt.Errorf("listener %d is not owned by this serve PID", port)
		}
	}
	raw, _ := json.Marshal(map[string]any{"pid": p.cmd.Process.Pid, "loopbackPorts": expected, "owned": true})
	return os.WriteFile(filepath.Join(filepath.Dir(p.StdoutPath), "listener-ownership.json"), raw, 0600)
}
