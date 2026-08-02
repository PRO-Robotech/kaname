// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Command audit-list-filter is the CI entry point of kacho-iam's public-List
// gate. What is checked lives in package listfiltergate; how this service is laid
// out lives in package auditlistfilter.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/tools/auditlistfilter"
	"github.com/PRO-Robotech/kacho/tools/listfiltergate"
)

// allowFlag collects repeated --allow=<resource> values.
type allowFlag []string

func (a *allowFlag) String() string { return strings.Join(*a, ",") }

func (a *allowFlag) Set(v string) error {
	*a = append(*a, v)
	return nil
}

func main() {
	var allow allowFlag
	root := flag.String("root", ".", "service root to audit (the directory holding internal/…)")
	flag.Var(&allow, "allow", "resource excluded from the check (repeatable); an entry matching no resource is a finding")
	flag.Parse()

	_, err := listfiltergate.Audit(auditlistfilter.Profile, listfiltergate.Options{Root: *root, Allow: allow}, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
