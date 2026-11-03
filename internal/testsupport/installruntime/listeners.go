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

// OwnsListeners проверяет настоящее владение сокетами Linux, а не только готовность портов.
// Каждый слушающий сокет этого PID должен быть петлевым IPv4 и присутствовать в переписи.
func (p *Process) OwnsListeners(expected ...int) error {
	return CheckOwnedListeners(p.cmd.Process.Pid, filepath.Dir(p.StdoutPath), expected...)
}

// CheckOwnedListeners повторно использует точную нативную перепись сокетов для независимо
// проверенного на владение тестового файла, выполняющего настоящий полный корень запуска.
func CheckOwnedListeners(pid int, evidenceDir string, expected ...int) error {
	root := fmt.Sprintf("/proc/%d", pid)
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
	raw, _ := json.Marshal(map[string]any{"pid": pid, "loopbackPorts": expected, "owned": true})
	return os.WriteFile(filepath.Join(evidenceDir, "listener-ownership.json"), raw, 0600)
}
