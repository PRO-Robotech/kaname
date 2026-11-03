// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
	"strings"
)

// installationResult is deliberately value-free: no credentials, token, SQL,
// driver errors or manifest payloads can enter the structural startup result.
type installationResult struct {
	Stage          string `json:"stage"`
	Code           string `json:"code"`
	Field          string `json:"field,omitempty"`
	AccountID      string `json:"accountId,omitempty"`
	DelegateID     string `json:"delegateId,omitempty"`
	CompletedPairs int    `json:"completedPairs"`
}

type installationFailure struct {
	result installationResult
	cause  error
}

func (e *installationFailure) Error() string              { b, _ := json.Marshal(e.result); return string(b) }
func (e *installationFailure) Unwrap() error              { return e.cause }
func (e *installationFailure) GRPCStatus() *status.Status { return status.Convert(e.cause) }

func failInstallation(logger *slog.Logger, stage, field, account, delegate string, completed int, err error) error {
	code := status.Code(err)
	if code == codes.Unknown {
		code = codes.Internal
	}
	result := installationResult{Stage: stage, Code: installationCodeName(code), Field: field, AccountID: account, DelegateID: delegate, CompletedPairs: completed}
	if stage == "input" && field == "credentialFile" {
		result.Code = "INSTALL_INPUT_INVALID"
	}
	logger.Error("installation apply failed", slog.Any("installation", result))
	return &installationFailure{result: result, cause: err}
}

func installationCodeName(code codes.Code) string {
	var out []rune
	for i, r := range code.String() {
		if r >= 'A' && r <= 'Z' && i > 0 {
			out = append(out, '_')
		}
		out = append(out, r)
	}
	return strings.ToUpper(string(out))
}
