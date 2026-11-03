// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
)

const rid01ExpiredAccessCase = "registry-installation-rid01-EXPIRED-ACCESS-TOKEN"
const rid01RenewedAccessCase = "registry-installation-rid01-RENEWAL-AFTER"
const rid01ExpiredKeyCase = "registry-installation-rid01-EXPIRED-KEY-REFUSAL"

func rid01PublicCase(id string) bool {
	switch id {
	case "registry-installation-rid01-CLEAN-BEFORE", "registry-installation-rid01-CLEAN-INSTALLED", "registry-installation-rid01-S1-EXACT-IDENTITIES", "registry-installation-rid01-RENEWAL-BEFORE", rid01ExpiredAccessCase, rid01RenewedAccessCase, rid01ExpiredKeyCase, "registry-installation-rid01-VALID-KEY-TWIN":
		return true
	}
	return false
}

type ridNewmanRequestPolicy struct {
	CaseID      string `json:"caseId"`
	RequestName string `json:"requestName"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Origin      string `json:"origin"`
}

func ridNewmanOrigin(raw string) (string, string, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1") {
		return "", "", "", errors.New("invalid owned HTTPS origin")
	}
	portNumber, portErr := strconv.Atoi(u.Port())
	// Match WHATWG URL canonicalization: explicit nonempty decimal port,
	// no leading zeros/range overflow, and no implicit HTTPS default443.
	if portErr != nil || portNumber < 0 || portNumber > 65535 || portNumber == 443 || strconv.Itoa(portNumber) != u.Port() {
		return "", "", "", errors.New("invalid owned HTTPS origin")
	}
	origin := "https://" + u.Host
	if raw != origin && raw != origin+"/" {
		return "", "", "", errors.New("invalid owned HTTPS origin")
	}
	return origin, u.Hostname(), u.Port(), nil
}
func ridNewmanDecodeRequestPolicy(raw json.RawMessage) (*ridNewmanRequestPolicy, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	// Decode through a map first to reject duplicate, missing and extra keys.
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid request policy")
	}
	fields := map[string]string{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, errors.New("invalid request policy")
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("invalid request policy")
		}
		if _, ok := fields[name]; ok {
			return nil, errors.New("invalid request policy")
		}
		var value string
		if dec.Decode(&value) != nil {
			return nil, errors.New("invalid request policy")
		}
		fields[name] = value
	}
	if _, err = dec.Token(); err != nil {
		return nil, errors.New("invalid request policy")
	}
	if _, err = dec.Token(); err != io.EOF {
		return nil, errors.New("invalid request policy")
	}
	if len(fields) != 5 {
		return nil, errors.New("invalid request policy")
	}
	for _, key := range []string{"caseId", "requestName", "method", "path", "origin"} {
		if _, ok := fields[key]; !ok {
			return nil, errors.New("invalid request policy")
		}
	}
	return &ridNewmanRequestPolicy{fields["caseId"], fields["requestName"], fields["method"], fields["path"], fields["origin"]}, nil
}
func ridNewmanValidateRequestPolicy(caseID, public string, p *ridNewmanRequestPolicy, variables map[string]any) error {
	_, host, port, err := ridNewmanOrigin(public)
	if err != nil {
		return errors.New("invalid public listener policy")
	}
	raw, has := variables["rid01IssuanceOrigin"]
	if caseID != rid01ExpiredKeyCase {
		if p != nil || has {
			return errors.New("unexpected issuance policy")
		}
		return nil
	}
	if port != "9098" && port != "9198" {
		return errors.New("invalid issuance public listener policy")
	}
	if p == nil || p.CaseID != caseID || p.RequestName != caseID+" :: expired-standing-key-token-refusal" || p.Method != "POST" || p.Path != "/iam/v1/token" {
		return errors.New("invalid issuance request policy")
	}
	expectedPort := "9096"
	if port == "9198" {
		expectedPort = "9196"
	}
	origin, tokenHost, tokenPort, err := ridNewmanOrigin(p.Origin)
	if err != nil || tokenHost != host || tokenPort != expectedPort || origin != p.Origin {
		return errors.New("invalid issuance origin policy")
	}
	value, ok := raw.(string)
	if !has || !ok || value != origin {
		return errors.New("issuance variable differs from owned policy")
	}
	return nil
}
func ridNewmanParentRequestPolicy(caseID, public, issuance string, variables map[string]any) (*ridNewmanRequestPolicy, error) {
	var p *ridNewmanRequestPolicy
	if caseID == rid01ExpiredKeyCase {
		p = &ridNewmanRequestPolicy{caseID, caseID + " :: expired-standing-key-token-refusal", "POST", "/iam/v1/token", issuance}
	}
	if err := ridNewmanValidateRequestPolicy(caseID, public, p, variables); err != nil {
		return nil, err
	}
	return p, nil
}
