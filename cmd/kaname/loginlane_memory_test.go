// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"os"
	"testing"
)

// Читаются только данные карты; host cgroup, namespace и процессы не нужны.
func TestOwnCgroupMemoryLimit(t *testing.T) {
	const gib = uint64(1 << 30)
	base := func() map[string]string {
		return map[string]string{
			"/proc/self/cgroup":    "0::/parent/job\n",
			"/proc/self/mountinfo": "1 0 0:1 / /cg rw - cgroup2 cgroup rw\n",
			"/cg/memory.max":       "max\n", "/cg/parent/memory.max": "17179869184\n",
			"/cg/parent/job/memory.max": "3221225472\n",
		}
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]string)
		want   uint64
		ok     bool
	}{
		{"nested job below unlimited root", func(m map[string]string) {}, 3 * gib, true},
		{"lower parent wins", func(m map[string]string) { m["/cg/parent/memory.max"] = "1073741824" }, gib, true},
		{"unlimited leaf inherits", func(m map[string]string) { m["/cg/parent/job/memory.max"] = "max" }, 16 * gib, true},
		{"all unlimited", func(m map[string]string) { m["/cg/parent/job/memory.max"] = "max"; m["/cg/parent/memory.max"] = "max" }, 0, false},
		{"missing ancestor", func(m map[string]string) { delete(m, "/cg/parent/memory.max") }, 0, false},
		{"malformed ancestor", func(m map[string]string) { m["/cg/parent/memory.max"] = "garbage" }, 0, false},
		{"zero limit", func(m map[string]string) { m["/cg/parent/memory.max"] = "0" }, 0, false},
		{"no proc mapping", func(m map[string]string) { delete(m, "/proc/self/cgroup") }, 0, false},
		{"dotdot member", func(m map[string]string) { m["/proc/self/cgroup"] = "0::/parent/../job" }, 0, false},
		{"outside exposed root refused", func(m map[string]string) { m["/proc/self/mountinfo"] = "1 0 0:1 /other /cg rw - cgroup2 cgroup rw" }, 0, false},
		{"ambiguous mount refused", func(m map[string]string) { m["/proc/self/mountinfo"] += m["/proc/self/mountinfo"] }, 0, false},
		{"root has no memory.max", func(m map[string]string) { delete(m, "/cg/memory.max") }, 3 * gib, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.change(m)
			read := func(p string) ([]byte, error) {
				s, ok := m[p]
				if !ok {
					return nil, os.ErrNotExist
				}
				return []byte(s), nil
			}
			n, ok := readOwnCgroupMemoryLimit(read)
			if n != tc.want || ok != tc.ok {
				t.Fatalf("got %d,%v want %d,%v", n, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestOwnCgroupV1AndHybrid(t *testing.T) {
	m := map[string]string{"/proc/self/cgroup": "0::/unified\n5:cpu,memory:/parent/job\n", "/proc/self/mountinfo": "1 0 0:1 / /cg rw - cgroup cgroup rw,cpu,memory\n2 0 0:2 / /unified rw - cgroup2 cgroup rw\n"}
	for _, d := range []string{"/cg", "/cg/parent", "/cg/parent/job"} {
		m[d+"/memory.limit_in_bytes"] = "9223372036854771712"
		m[d+"/memory.use_hierarchy"] = "1"
	}
	m["/cg/parent/memory.limit_in_bytes"] = "1073741824"
	m["/cg/parent/job/memory.limit_in_bytes"] = "3221225472"
	read := func(p string) ([]byte, error) {
		s, ok := m[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(s), nil
	}
	n, ok := readOwnCgroupMemoryLimit(read)
	if !ok || n != 1<<30 {
		t.Fatalf("v1 inherited min: %d,%v", n, ok)
	}
	m["/cg/parent/memory.use_hierarchy"] = "0"
	if _, ok := readOwnCgroupMemoryLimit(read); ok {
		t.Fatal("nonhierarchical v1 must be refused")
	}
}

func TestOwnCgroupMappingEscapesAndMovement(t *testing.T) {
	h, ok := memoryCgroupMapping([]byte("0::/job"), []byte("1 0 0:1 / /cg\\040space rw - cgroup2 cgroup rw"))
	if !ok || h.mount != "/cg space" {
		t.Fatal("mount escape not decoded")
	}
	reads := 0
	read := func(p string) ([]byte, error) {
		switch p {
		case "/proc/self/cgroup":
			reads++
			if reads > 1 {
				return []byte("0::/other"), nil
			}
			return []byte("0::/"), nil
		case "/proc/self/mountinfo":
			return []byte("1 0 0:1 / /cg rw - cgroup2 cgroup rw"), nil
		case "/cg/memory.max":
			return []byte("3221225472"), nil
		}
		return nil, os.ErrNotExist
	}
	if _, ok := readOwnCgroupMemoryLimit(read); ok {
		t.Fatal("membership change must be refused")
	}
}

func TestEnvironmentMemoryLimitKeepsFileSeam(t *testing.T) {
	p := t.TempDir() + "/limit"
	writeFile(t, p, "3221225472\n")
	n, ok := readEnvironmentMemoryLimit([]string{p})
	if !ok || n != 3<<30 {
		t.Fatalf("file seam: %d,%v", n, ok)
	}
	writeFile(t, p, "max\n")
	if _, ok := readEnvironmentMemoryLimit([]string{p}); ok {
		t.Fatal("max is not finite")
	}
}
func TestOwnMemoryLimitPreservesPasswordBudget(t *testing.T) {
	login := loginLaneCfg().AuthN.Login
	login.VerifierCapacity = 8
	login.MemoryReserveBytes = 256 << 20
	for _, tc := range []struct {
		parent string
		accept bool
	}{{"17179869184", true}, {"1073741824", false}} {
		m := map[string]string{"/proc/self/cgroup": "0::/parent/job", "/proc/self/mountinfo": "1 0 0:1 / /cg rw - cgroup2 cgroup rw", "/cg/memory.max": "max", "/cg/parent/memory.max": tc.parent, "/cg/parent/job/memory.max": "3221225472"}
		read := func(p string) ([]byte, error) {
			s, ok := m[p]
			if !ok {
				return nil, os.ErrNotExist
			}
			return []byte(s), nil
		}
		n, ok := readOwnCgroupMemoryLimit(read)
		err := login.ValidateMemoryBudget(n, ok)
		if (err == nil) != tc.accept {
			t.Fatalf("parent %s: budget result %v", tc.parent, err)
		}
	}
}
func TestOwnMemoryLimitUnknownMappingOrReadDenied(t *testing.T) {
	if _, ok := memoryCgroupMapping([]byte("0::/job"), []byte("1 0 0:1 / /cg\\999 rw - cgroup2 cgroup rw")); ok {
		t.Fatal("unknown escape admitted")
	}
	read := func(p string) ([]byte, error) {
		switch p {
		case "/proc/self/cgroup":
			return []byte("0::/parent/job"), nil
		case "/proc/self/mountinfo":
			return []byte("1 0 0:1 / /cg rw - cgroup2 cgroup rw"), nil
		case "/cg/parent/job/memory.max":
			return []byte("3221225472"), nil
		}
		return nil, os.ErrPermission
	}
	if _, ok := readOwnCgroupMemoryLimit(read); ok {
		t.Fatal("unreadable ancestor admitted")
	}
}

// Bind-root сохраняет прежнюю контейнерную посадку. Пределы вне видимого
// mount не выдумываются; unrelated/prefix-neighbour не перенаправляются.
func TestOwnMemoryBindRootMapping(t *testing.T) {
	for _, tc := range []struct {
		name, member, root string
		files              map[string]string
		want               uint64
		ok                 bool
	}{
		{"own equals mount root", "/parent/job", "/parent/job", map[string]string{"/cg/memory.max": "3221225472"}, 3 << 30, true},
		{"own below bind root", "/parent/job", "/parent", map[string]string{"/cg/memory.max": "17179869184", "/cg/job/memory.max": "3221225472"}, 3 << 30, true},
		{"smaller visible ancestor", "/parent/job/child", "/parent", map[string]string{"/cg/memory.max": "17179869184", "/cg/job/memory.max": "1073741824", "/cg/job/child/memory.max": "3221225472"}, 1 << 30, true},
		{"same string prefix not descendant", "/parent2/job", "/parent", map[string]string{"/cg/memory.max": "17179869184"}, 0, false},
		{"unrelated hierarchy path", "/else/job", "/parent", map[string]string{"/cg/memory.max": "17179869184"}, 0, false},
		{"membership traversal", "/parent/../else", "/parent", map[string]string{"/cg/memory.max": "17179869184"}, 0, false},
		{"root traversal", "/parent/job", "/parent/..", map[string]string{"/cg/memory.max": "17179869184"}, 0, false},
		{"missing bind root is not hierarchy root", "/parent/job", "/parent/job", map[string]string{}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(p string) ([]byte, error) {
				switch p {
				case "/proc/self/cgroup":
					return []byte("0::" + tc.member + "\n"), nil
				case "/proc/self/mountinfo":
					return []byte("1 0 0:1 " + tc.root + " /cg rw - cgroup2 cgroup rw\n"), nil
				}
				s, ok := tc.files[p]
				if !ok {
					return nil, os.ErrNotExist
				}
				return []byte(s), nil
			}
			n, ok := readOwnCgroupMemoryLimit(read)
			if n != tc.want || ok != tc.ok {
				t.Fatalf("got %d,%v want %d,%v", n, ok, tc.want, tc.ok)
			}
		})
	}
}
func TestOwnMemoryMembershipTrailingSpaceIsIdentity(t *testing.T) {
	for _, suffix := range []string{"", "\n"} {
		t.Run("terminal="+suffix, func(t *testing.T) {
			m := map[string]string{"/proc/self/cgroup": "0::/job " + suffix, "/proc/self/mountinfo": "1 0 0:1 / /cg rw - cgroup2 cgroup rw\n", "/cg/memory.max": "max", "/cg/job /memory.max": "1073741824", "/cg/job/memory.max": "17179869184"}
			read := func(p string) ([]byte, error) {
				s, ok := m[p]
				if !ok {
					return nil, os.ErrNotExist
				}
				return []byte(s), nil
			}
			n, ok := readOwnCgroupMemoryLimit(read)
			if !ok || n != 1<<30 {
				t.Fatalf("trailing-space group redirected: %d,%v", n, ok)
			}
		})
	}
}

// Unicode-пробел в mountpoint сохраняет точное имя; соседний путь не заменяет
// ограничение памяти, даже если содержит читаемый и больший предел.
func TestOwnMemoryMountUnicodeSpaceIsIdentity(t *testing.T) {
	m := map[string]string{"/proc/self/cgroup": "0::/job\n", "/proc/self/mountinfo": "1 0 0:1 / /cg\u00a0suffix rw - cgroup2 cgroup rw\n", "/cg\u00a0suffix/memory.max": "max", "/cg\u00a0suffix/job/memory.max": "1073741824", "/cg/memory.max": "max", "/cg/job/memory.max": "17179869184"}
	read := func(p string) ([]byte, error) {
		s, ok := m[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(s), nil
	}
	n, ok := readOwnCgroupMemoryLimit(read)
	if !ok || n != 1<<30 {
		t.Fatalf("Unicode-space mount redirected: %d,%v", n, ok)
	}
	login := loginLaneCfg().AuthN.Login
	login.VerifierCapacity = 8
	login.MemoryReserveBytes = 256 << 20
	if err := login.ValidateMemoryBudget(n, ok); err == nil {
		t.Fatal("password budget must exceed the actual mount limit")
	}
}

func TestOwnMemoryMountAtFilesystemRoot(t *testing.T) {
	m := map[string]string{"/proc/self/cgroup": "0::/parent/job\n", "/proc/self/mountinfo": "1 0 0:1 / / rw - cgroup2 cgroup rw\n", "/memory.max": "max", "/parent/memory.max": "1073741824", "/parent/job/memory.max": "3221225472"}
	read := func(p string) ([]byte, error) {
		s, ok := m[p]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(s), nil
	}
	n, ok := readOwnCgroupMemoryLimit(read)
	if !ok || n != 1<<30 {
		t.Fatalf("root mount minimum: %d,%v", n, ok)
	}
}

func TestOwnMemoryChangedMountViewIsRefused(t *testing.T) {
	mountReads := 0
	read := func(p string) ([]byte, error) {
		switch p {
		case "/proc/self/cgroup":
			return []byte("0::/job\n"), nil
		case "/proc/self/mountinfo":
			mountReads++
			if mountReads > 1 {
				return []byte("1 0 0:1 / /other rw - cgroup2 cgroup rw\n"), nil
			}
			return []byte("1 0 0:1 / /cg rw - cgroup2 cgroup rw\n"), nil
		case "/cg/memory.max":
			return []byte("max"), nil
		case "/cg/job/memory.max":
			return []byte("3221225472"), nil
		}
		return nil, os.ErrNotExist
	}
	if _, ok := readOwnCgroupMemoryLimit(read); ok {
		t.Fatal("changed mount view admitted")
	}
}
