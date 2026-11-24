//go:build linux

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStandaloneCaptureNoFollowPrimitive(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "real-file"), []byte("законный контекст"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "real-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real-file", filepath.Join(base, "link-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real-dir", filepath.Join(base, "link-dir")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, tc := range []struct {
		name      string
		directory bool
		allowed   bool
	}{
		{name: "real-file", allowed: true},
		{name: "real-dir", directory: true, allowed: true},
		{name: "link-file"},
		{name: "link-dir", directory: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Напрямую вызывается primitive: предварительный consumer Lstat не скрывает дефект.
			file, err := standaloneOpenNoFollow(root, tc.name, tc.directory)
			if file != nil {
				defer file.Close()
			}
			if !tc.allowed {
				if err == nil || file != nil {
					t.Errorf("symlink должен отказать при самом open: file=%v error=%v", file != nil, err)
				}
				return
			}
			if err != nil || file == nil {
				t.Fatalf("законный близнец не открылся: %v", err)
			}
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if info.IsDir() != tc.directory || (!tc.directory && !info.Mode().IsRegular()) {
				t.Errorf("открыт неверный тип: %v", info.Mode())
			}
		})
	}
}

func TestStandaloneCaptureNoFollowLeafBoundary(t *testing.T) {
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "nested", "file"), []byte("контекст"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"", ".", "..", "/", filepath.Join(base, "nested", "file"), "nested/file", "nested/../nested/file", "nested\\file", "file\x00tail"} {
		t.Run(name, func(t *testing.T) {
			file, err := standaloneOpenNoFollow(root, name, false)
			if file != nil {
				defer file.Close()
			}
			if err == nil || file != nil {
				t.Errorf("не-basename принят primitive: %q", name)
			}
		})
	}
}
