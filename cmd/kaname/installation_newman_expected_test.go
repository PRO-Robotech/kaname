// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// The full producer freezes one flat, externally supplied identity file for
// every literal collection. Node and collector still receive the same exact
// five-field contract used by the independently exercised single-RID bridge.
// All twelve files are checked together before selecting a collection: a
// different test binary/toolchain cannot be hidden in a later RID's file.
func ridNewmanExpectedForCollection(file, directory, stem string) (ridNewmanExpected, error) {
	var zero ridNewmanExpected
	if (file == "") == (directory == "") {
		return zero, errors.New("exactly one external identity FILE or DIR is required")
	}
	if valid, _ := regexp.MatchString(`^registry-installation-rid(?:0[1-9]|1[012])$`, stem); !valid {
		return zero, errors.New("identity collection is not a literal RID stem")
	}
	if file != "" {
		if !filepath.IsAbs(file) {
			return zero, errors.New("external identity FILE must be absolute")
		}
		fd, err := syscall.Open(file, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return zero, errors.New("external identity FILE cannot be opened")
		}
		return ridNewmanReadExpectedFD(fd)
	}
	if !filepath.IsAbs(directory) {
		return zero, errors.New("external identity DIR must be absolute")
	}
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return zero, errors.New("external identity DIR cannot be opened")
	}
	dir := os.NewFile(uintptr(fd), "rid-external-identities")
	defer dir.Close()
	names, err := dir.Readdirnames(13)
	if err != nil && !errors.Is(err, io.EOF) {
		return zero, errors.New("external identity DIR census failed")
	}
	if len(names) != 12 {
		return zero, errors.New("external identity DIR must contain exactly twelve files")
	}
	wanted := make(map[string]bool, 12)
	for n := 1; n <= 12; n++ {
		wanted[fmt.Sprintf("registry-installation-rid%02d.json", n)] = true
	}
	var selected, common ridNewmanExpected
	for n, name := range names {
		if !wanted[name] {
			return zero, errors.New("external identity DIR has an unexpected entry")
		}
		delete(wanted, name)
		child, openErr := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return zero, errors.New("external identity DIR file cannot be opened")
		}
		expected, readErr := ridNewmanReadExpectedFD(child)
		if readErr != nil {
			return zero, readErr
		}
		if n == 0 {
			common = expected
		} else if expected.Node != common.Node || expected.Runner != common.Runner || expected.Tree != common.Tree || expected.Test != common.Test {
			return zero, errors.New("external identity DIR mixes toolchains or test executables")
		}
		if name == stem+".json" {
			selected = expected
		}
	}
	if len(wanted) != 0 || selected.Collection == "" {
		return zero, errors.New("external identity DIR has incomplete literal RID membership")
	}
	return selected, nil
}

// fd is owned by this function. O_NONBLOCK plus the regular-file check also
// makes malformed FIFO/device entries a bounded refusal rather than a wait.
func ridNewmanReadExpectedFD(fd int) (ridNewmanExpected, error) {
	var out ridNewmanExpected
	f := os.NewFile(uintptr(fd), "rid-external-identity")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 16384 {
		return out, errors.New("external identity must be a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 || int64(len(raw)) != info.Size() {
		return out, errors.New("external identity changed or exceeded its byte bound")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return out, errors.New("external identity must be one closed object")
	}
	fields := map[string]*string{"nodeSHA256": &out.Node, "runnerSHA256": &out.Runner, "toolTreeSHA256": &out.Tree, "collectionSHA256": &out.Collection, "testExecutableSHA256": &out.Test}
	seen := make(map[string]bool, 5)
	for decoder.More() {
		token, err = decoder.Token()
		name, stringKey := token.(string)
		target, known := fields[name]
		if err != nil || !stringKey || !known || seen[name] {
			return ridNewmanExpected{}, errors.New("external identity contains an unknown or repeated field")
		}
		seen[name] = true
		if err = decoder.Decode(target); err != nil {
			return ridNewmanExpected{}, errors.New("external identity field must be a SHA256 string")
		}
		if valid, _ := regexp.MatchString(`^[a-f0-9]{64}$`, *target); !valid {
			return ridNewmanExpected{}, errors.New("external identity field must be a lowercase SHA256")
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(seen) != len(fields) {
		return ridNewmanExpected{}, errors.New("external identity object is incomplete")
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return ridNewmanExpected{}, errors.New("external identity has trailing input")
	}
	return out, nil
}
