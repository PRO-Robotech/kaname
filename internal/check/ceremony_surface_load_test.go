// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// ceremony_surface_load_test.go — радиус гейта единственности поверхности
// церемонии (kaname#320) собирается `go list` под СВОИМ сроком.
//
// Зависший `go list` (сеть модулей, блокировка кэша) без своего срока съел бы
// весь бюджет прогона и оборвал его паникой пакета проб — «не исполнилось» без
// причины. Со сроком отказ называет себя: радиус не собран за столько-то.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/modfile"

	"github.com/PRO-Robotech/kaname/internal/treeroot"
)

// TestSurfaceListingRefusesPastItsDeadline — срок истёк раньше, чем `go list`
// назвал радиус: это отказ исполниться с причиной, а не вердикт.
func TestSurfaceListingRefusesPastItsDeadline(t *testing.T) {
	root, err := treeroot.ModuleRootFrom(".")
	if err != nil {
		t.Fatalf("корень модуля: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("go.mod: %v", err)
	}
	rootPkg := modfile.ModulePath(data) + "/cmd/kaname"

	if _, err := newListing(root, rootPkg, time.Nanosecond); err == nil {
		t.Fatalf("радиус собран за наносекунду срока — срок не действует")
	} else if !strings.Contains(err.Error(), "не уложился") {
		t.Fatalf("отказ по сроку не называет срок причиной: %v", err)
	}

	if _, err := newListing(root, rootPkg, surfaceListTimeout); err != nil {
		t.Fatalf("законный близнец: радиус не собран за штатный срок %s: %v", surfaceListTimeout, err)
	}
}
