// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command audit-list-filter is the CI entry point of kacho-iam's public-List gate.
// What is checked lives in package listfiltergate; how this service is laid out
// lives in package auditlistfilter.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/PRO-Robotech/kacho-iam/tools/auditlistfilter"
	"github.com/PRO-Robotech/kacho/pkg/listfiltergate"
)

func main() {
	root := flag.String("root", ".", "service root to audit (the directory holding internal/…)")
	protoRoot := flag.String("proto-root", "proto",
		"root of the proto tree, used to verify EdgeGate declarations against the RPC options "+
			"and the authorization model")
	flag.Parse()

	_, err := listfiltergate.Audit(
		auditlistfilter.Profile,
		listfiltergate.Options{Root: *root, ProtoRoot: *protoRoot},
		os.Stdout,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
