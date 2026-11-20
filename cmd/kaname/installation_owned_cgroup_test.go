// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import "testing"

// Только сохранённые строки proc: тест не читает и не меняет cgroup машины.
func TestRIDOwnedCgroupLeaf(t *testing.T) {
	for _, tc := range []struct {
		name, member, mounts, want string
	}{
		{
			name:   "nested hosted scope",
			member: "0::/system.slice/rid.scope\n",
			mounts: "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
			want:   "/sys/fs/cgroup/system.slice/rid.scope",
		},
		{
			name:   "namespace root is the leaf",
			member: "0::/\n",
			mounts: "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
			want:   "/sys/fs/cgroup",
		},
		{
			name:   "exposed subtree with escaped mount",
			member: "0::/system.slice/rid.scope\n",
			mounts: "1 0 0:1 /system.slice /cg\\040space rw - cgroup2 cgroup rw\n",
			want:   "/cg space/rid.scope",
		},
		{
			name:   "outside exposed subtree",
			member: "0::/other/rid.scope\n",
			mounts: "1 0 0:1 /system.slice /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
		},
		{
			name:   "legacy memory is not a v2 proof",
			member: "5:memory:/rid\n",
			mounts: "1 0 0:1 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf, ok := ridOwnedCgroupLeaf([]byte(tc.member), []byte(tc.mounts))
			if leaf != tc.want || ok != (tc.want != "") {
				t.Fatalf("leaf=%q ok=%v, want %q", leaf, ok, tc.want)
			}
		})
	}
}
