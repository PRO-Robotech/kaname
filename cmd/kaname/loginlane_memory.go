// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"os"
	"path"
	"strconv"
	"strings"
)

// Сохраняем прежний файловый seam. В production стандартные пути означают
// исследование собственной иерархии, а не произвольное чтение корня host.
func readEnvironmentMemoryLimit(files []string) (uint64, bool) {
	if len(files) != 2 || files[0] != "/sys/fs/cgroup/memory.max" || files[1] != "/sys/fs/cgroup/memory/memory.limit_in_bytes" {
		return readMemoryLimit(files)
	}
	return readOwnCgroupMemoryLimit(os.ReadFile)
}

type memoryCgroup struct {
	version             int
	member, root, mount string
}

// Пути поступают из proc ядра. Нормализация не должна исправлять неизвестное
// отображение: dot/dotdot и относительные пути отвергаются до файлового чтения.
func memoryAbsolute(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}
func memoryMountPath(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", false
		}
		switch s[i+1 : i+4] {
		case "040":
			b.WriteByte(' ')
		case "011":
			b.WriteByte('\t')
		case "012":
			b.WriteByte('\n')
		case "134":
			b.WriteByte('\\')
		default:
			return "", false
		}
		i += 3
	}
	p := b.String()
	return p, memoryAbsolute(p)
}
func memoryHasCSV(s, want string) bool {
	for _, v := range strings.Split(s, ",") {
		if v == want {
			return true
		}
	}
	return false
}

func memoryCgroupMapping(cgroups, mounts []byte) (memoryCgroup, bool) {
	var out memoryCgroup
	unified, legacy := "", ""
	// Только завершающий LF является разделителем; пробел принадлежит имени cgroup.
	for _, line := range strings.Split(strings.TrimSuffix(string(cgroups), "\n"), "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) != 3 || !memoryAbsolute(f[2]) {
			return out, false
		}
		if f[0] == "0" && f[1] == "" {
			if unified != "" {
				return out, false
			}
			unified = f[2]
		}
		if memoryHasCSV(f[1], "memory") {
			if legacy != "" {
				return out, false
			}
			legacy = f[2]
		}
	}
	// В hybrid memory принадлежит v1, даже если unified hierarchy тоже существует.
	out.version, out.member = 2, unified
	if legacy != "" {
		out.version, out.member = 1, legacy
	}
	if out.member == "" {
		return out, false
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(mounts), "\n"), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			return out, false
		}
		// Ядро разделяет поля ASCII-пробелом. Unicode-пробел принадлежит имени
		// пути и не должен перенаправлять чтение в соседнюю cgroup.
		left, right := strings.Split(parts[0], " "), strings.Split(parts[1], " ")
		if len(left) < 6 || len(right) < 3 {
			return out, false
		}
		selected := out.version == 2 && right[0] == "cgroup2" || out.version == 1 && right[0] == "cgroup" && memoryHasCSV(right[2], "memory")
		if !selected {
			continue
		}
		root, ok := memoryMountPath(left[3])
		if !ok {
			return out, false
		}
		mount, ok := memoryMountPath(left[4])
		if !ok {
			return out, false
		}
		// Root и membership — имена в одном cgroup view. Нужна граница
		// сегмента: /job2 не является потомком /job. Скрытых предков mount
		// это отображение не раскрывает; минимум вычисляется в видимой области.
		if out.mount != "" {
			return out, false
		}
		if out.member != root && root != "/" && !strings.HasPrefix(out.member, root+"/") {
			return out, false
		}
		out.root, out.mount = root, mount
	}
	return out, out.mount != ""
}

// Все конечные ограничения действующих предков участвуют в минимуме.
// Нечитаемый промежуточный уровень не равен unlimited. V1 поддерживается
// только при явно включённой hierarchical accounting на видимых уровнях.
func readOwnCgroupMemoryLimit(read func(string) ([]byte, error)) (uint64, bool) {
	c, err := read("/proc/self/cgroup")
	if err != nil {
		return 0, false
	}
	m, err := read("/proc/self/mountinfo")
	if err != nil {
		return 0, false
	}
	h, ok := memoryCgroupMapping(c, m)
	if !ok {
		return 0, false
	}
	leaf := h.mount
	if h.member != h.root {
		relative := strings.TrimPrefix(h.member, h.root)
		relative = strings.TrimPrefix(relative, "/")
		leaf = path.Join(h.mount, relative)
	}
	var minimum uint64
	for dir := leaf; ; dir = path.Dir(dir) {
		name := "memory.max"
		if h.version == 1 {
			name = "memory.limit_in_bytes"
		}
		raw, err := read(path.Join(dir, name))
		if err != nil {
			// Настоящий v2 hierarchy root может не иметь memory.max по модели ядра.
			if h.version != 2 || h.root != "/" || dir != h.mount || !os.IsNotExist(err) {
				return 0, false
			}
		} else {
			s := strings.TrimSpace(string(raw))
			if s != "max" || h.version == 1 {
				n, e := strconv.ParseUint(s, 10, 64)
				if e != nil || n == 0 {
					return 0, false
				}
				unlimited := h.version == 1 && n >= cgroupV1Unlimited
				if !unlimited && (minimum == 0 || n < minimum) {
					minimum = n
				}
			}
		}
		if h.version == 1 {
			raw, err = read(path.Join(dir, "memory.use_hierarchy"))
			if err != nil || strings.TrimSpace(string(raw)) != "1" {
				return 0, false
			}
		}
		if dir == h.mount {
			break
		}
		parent := path.Dir(dir)
		if parent == dir || (parent != h.mount && h.mount != "/" && !strings.HasPrefix(parent, h.mount+"/")) {
			return 0, false
		}
	}
	// Перемещение процесса или замена mount view во время чтения — неизвестное.
	c2, e1 := read("/proc/self/cgroup")
	m2, e2 := read("/proc/self/mountinfo")
	if e1 != nil || e2 != nil || !bytes.Equal(c, c2) || !bytes.Equal(m, m2) {
		return 0, false
	}
	return minimum, minimum != 0
}
