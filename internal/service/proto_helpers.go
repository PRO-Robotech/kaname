// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// proto_helpers.go — small adapters service → proto used by the authorize +
// conditions services. Kept private to the service package; handlers re-marshal
// as needed.
package service

import (
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"
)

// jsonToStructpb — unmarshal `[]byte` JSON object into structpb.Struct.
// Returns nil on empty input. Caller decides how to handle errors (we return
// them for diagnostic).
func jsonToStructpb(b []byte) (*structpb.Struct, error) {
	if len(b) == 0 || string(b) == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshal struct: %w", err)
	}
	return structpb.NewStruct(m)
}
