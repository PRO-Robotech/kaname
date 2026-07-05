// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// ops_response_redactor.go — in-place redaction of secret fields in
// operations.response_data (the BYTEA column where corelib
// operations.Repo.MarkDone marshals the Any-wrapped success response).
//
// Used by sa_keys.IssueSAKeyUseCase to redact `client_secret` AFTER the
// operations row is MarkDone'd. Combined with the anonymous-Get-returns-
// NotFound guard and the CreatedBy-from-principal stamping, this prevents
// both anonymous secret-leak via operation-id replay and audit-attribution
// spoofing.
//
// Implementation note: `operations` only has `response_type TEXT` and
// `response_data BYTEA` (proto-marshalled `Any`) — there is no JSONB
// `response` column to `jsonb_set`, so we redact at the proto layer.
//
// We now redact by:
//
//  1. SELECT response_type, response_data FROM <schema>.operations WHERE id = $1.
//  2. Unmarshal the Any (response_type → proto type URL; response_data → bytes).
//  3. Reflectively clear the named field on the inner message.
//  4. Marshal back, UPDATE response_data. Single statement.
//
// Idempotent: clearing an already-empty field is a no-op (the marshalled
// bytes will be identical). Concurrency-safe: each operation row has a
// single producer (the worker that MarkDone'd it); the redact runs after
// that worker returns and uses row-level UPDATE.
//
// Lives in repo/kacho/pg (not internal/clients) because it is a Postgres
// adapter owning a *pgxpool.Pool — pgx stays confined here (Clean Architecture).
// It satisfies the sa_keys.OpsResponseRedactor use-case port.
package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// OpsResponseRedactor wraps a pgxpool.Pool and provides the in-place proto
// redaction used by sa_keys IssueSAKeyUseCase to redact the plaintext
// `client_secret` field after the Operation is marked done.
type OpsResponseRedactor struct {
	pool   *pgxpool.Pool
	schema string // "kacho_iam"
}

// NewOpsResponseRedactor builds the adapter for the given schema.
func NewOpsResponseRedactor(pool *pgxpool.Pool, schema string) *OpsResponseRedactor {
	return &OpsResponseRedactor{pool: pool, schema: schema}
}

// RedactResponseField clears the named proto field in operations.response_data
// for the given operation id.
//
//	opID       — primary key of operations row.
//	fieldPath  — proto field name(s) to clear. Top-level only (no dotted paths;
//	             multi-field redaction iterates them). Names match the proto
//	             field name in lowerCamel form ("client_secret", "password").
//	             Each named field is set to its zero value (strings → "", bytes
//	             → empty, etc.); the cleared value is never surfaced.
//
// Returns nil even when no row matches OR when the row has no response_data
// (defensive — the redact races with worker.MarkError; a failed op never
// stored the secret).
func (r *OpsResponseRedactor) RedactResponseField(ctx context.Context, opID string, fieldPath []string) error {
	if len(fieldPath) == 0 {
		return errors.New("ops redact: empty field path")
	}

	table := pgx.Identifier{r.schema, "operations"}.Sanitize()
	if r.pool == nil {
		// Guarded by tests; production wiring always passes a real pool.
		return errors.New("ops redact: nil pool")
	}

	// 1. SELECT current response. response_type / response_data are nullable
	//    (un-finalised op, or finalised with MarkError); scan into *string /
	//    *[]byte and treat NULL as "no response yet" → no-op.
	var (
		respType *string
		respData []byte
	)
	selectSQL := fmt.Sprintf(
		`SELECT response_type, response_data FROM %s WHERE id = $1`, table)
	err := r.pool.QueryRow(ctx, selectSQL, opID).Scan(&respType, &respData)
	if err != nil {
		// pgx.ErrNoRows or any other error → defensive return.
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("ops redact SELECT: %w", err)
	}
	if respType == nil || *respType == "" || len(respData) == 0 {
		// Not yet finalised with a success response (or final error path).
		return nil
	}
	respTypeStr := *respType

	// 2. Resolve proto message type from response_type.
	//
	// corelib operations.Repo stores the response_type as the Any.TypeUrl
	// ("type.googleapis.com/<fullname>"), not the bare proto name. Strip the
	// "<host>/" prefix to recover the FullName the registry expects.
	fullName := respTypeStr
	if i := strings.LastIndex(fullName, "/"); i >= 0 {
		fullName = fullName[i+1:]
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(fullName))
	if err != nil {
		return fmt.Errorf("ops redact: unknown response type %q: %w", respTypeStr, err)
	}
	msg := mt.New().Interface()
	if err := proto.Unmarshal(respData, msg); err != nil {
		return fmt.Errorf("ops redact: unmarshal %s: %w", respTypeStr, err)
	}

	// 3. Clear each named field reflectively.
	mr := msg.ProtoReflect()
	desc := mr.Descriptor()
	cleared := false
	for _, name := range fieldPath {
		fd := desc.Fields().ByName(protoreflect.Name(name))
		if fd == nil {
			// Some callers pass JSON field names that are protobuf-camelCase
			// already; try snake_case too via lookup-by-json-name.
			fd = desc.Fields().ByJSONName(name)
		}
		if fd == nil {
			// Field absent on this proto type — skip (defensive; this lets a
			// single call cover multiple proto types where only some have the
			// field, e.g. shared redactor for multiple Issue* responses).
			continue
		}
		if mr.Has(fd) {
			mr.Clear(fd)
			cleared = true
		}
	}
	if !cleared {
		// Nothing to write back.
		return nil
	}

	// 4. Re-marshal + UPDATE.
	newData, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("ops redact: re-marshal: %w", err)
	}
	updateSQL := fmt.Sprintf(
		`UPDATE %s SET response_data = $2 WHERE id = $1`, table)
	if _, err := r.pool.Exec(ctx, updateSQL, opID, newData); err != nil {
		return fmt.Errorf("ops redact UPDATE: %w", err)
	}
	return nil
}
