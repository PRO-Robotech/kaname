// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package visibility — CQRS port for the STRUCTURAL FACTS about one caller that
// a list use-case needs before it reads its first candidate row.
//
// # What this package is for, and what it deliberately is NOT
//
// A list page must be a page of what the caller may SEE. To build one, the page
// has to be SELECTED narrowed — a window over the whole table from which the
// visible is subtracted afterwards loses every object with more than `page_size`
// invisible predecessors (task #645). Narrowing needs a set of CANDIDATES, and
// the candidates are read from iam's own database.
//
// The set this package answers with is a SUPERSET of the visible by
// construction: it names accounts and objects the caller's own grants reach,
// WITHOUT deciding whether any particular grant authors a read. That decision
// belongs to the authorization model and to nothing else
// (`security.md` §«Авторизация живёт в МОДЕЛИ»); this package must never become
// a second, home-grown rights system. Over-inclusion here is harmless — the
// model rejects the extra rows; under-inclusion is the original defect wearing a
// new address, because a path the candidate selection forgets produces an
// invisibility that shows only for the caller who travels it.
//
// Hence every judgement call in the SQL below is resolved TOWARDS INCLUSION: a
// PENDING binding counts, an expired one counts, a wildcard counts, a target
// named in either dictionary counts.
//
// # Why the answer is a memo and not a subquery
//
// Filling a page takes more than one read when the candidate set is dirty. If
// the structural facts were expressed as correlated subqueries of the page read,
// they would be recomputed once per refill — the same facts, re-derived, N
// times. They are resolved ONCE per request instead, and handed to the loop.
package visibility

import "context"

// Subject — the principal a scope is asked about. Type is the principal type as
// the transport reports it ("user" / "service_account"), NOT an FGA subject
// string: this package asks iam's own tables, whose columns carry that spelling.
type Subject struct {
	Type string
	ID   string
}

// Scope — the structural facts of ONE subject, resolved once per request.
//
// The zero value is the scope of a caller iam's tables know nothing about: no
// accounts, no grants, not unrestricted — that is, no candidates at all. That is
// the right default: a subject with no reachable rows gets an empty page, never
// the whole table.
type Scope struct {
	// Unrestricted — the subject holds a grant whose scope is the CLUSTER (or a
	// wildcard scope). Every row of every type is then a candidate of his, and
	// narrowing by account or by object id would be narrower than the model.
	//
	// It is not the same fact as "cluster administrator": that one is a question
	// about the SUBJECT put to the model, asked once per request by the use-case
	// (§3.6 of the acceptance). This one is about a row in iam's own tables.
	Unrestricted bool

	// OwnedAccounts — accounts whose owner column names this subject.
	//
	// Ownership is a CODE FLOOR, not a grant: it is not expressed by any tuple,
	// and an account owner sees the contents of his account even on a stand whose
	// materialization has never run. Kept apart from ScopedAccounts precisely
	// because the two are consumed differently — this one skips the model verdict,
	// that one only selects candidates.
	OwnedAccounts []string

	// ScopedAccounts — accounts the subject reaches at all: owned, granted
	// directly, or granted through a group he belongs to. Every object living in
	// one of them is a candidate.
	ScopedAccounts []string

	// GrantedObjects — objects named by a grant BY NAME, keyed by the model's
	// spelling of the object type ("project", "iam_group", …). These are the
	// candidates a subject has without reaching their account at all.
	GrantedObjects map[string][]string
}

// PageScope — the narrowing handed to one resource's page read: a row is a
// candidate when its account is named here, or the row itself is.
//
// A nil *PageScope means "no narrowing" and is NOT the same as an empty one: an
// empty PageScope names nothing and therefore selects nothing. The distinction
// is the difference between a cluster administrator and a stranger, and it must
// be representable apart from the values it carries.
type PageScope struct {
	AccountIDs []string
	ObjectIDs  []string
}

// Candidates projects a Scope onto ONE object type. Returns nil when the scope
// is unrestricted — nil is the narrowing's own "do not narrow".
func (s Scope) Candidates(objectType string) *PageScope {
	if s.Unrestricted {
		return nil
	}
	return &PageScope{
		AccountIDs: s.ScopedAccounts,
		ObjectIDs:  s.GrantedObjects[objectType],
	}
}

// Owns reports whether the subject owns the account — the code floor above,
// asked per row of a page.
func (s Scope) Owns(accountID string) bool {
	for _, id := range s.OwnedAccounts {
		if id == accountID {
			return true
		}
	}
	return false
}

// ReaderIface — read-only port.
type ReaderIface interface {
	// ScopeOf resolves the structural facts of one subject in a single query.
	// An unknown subject is not an error: it yields the zero Scope.
	ScopeOf(ctx context.Context, s Subject) (Scope, error)
}
