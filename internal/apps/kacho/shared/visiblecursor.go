// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// visiblecursor.go — the page token of a list whose page is a page of the
// VISIBLE (task #645).
//
// # Why a second token form exists at all
//
// The legacy token marks the boundary of a RAW page — the last row the database
// handed over, whether or not the caller may read it. A list that fills its page
// with visible rows cannot use it: its boundary is the last row it RETURNED, and
// that row is visible by construction.
//
// The two look identical on the wire (both are base64 of `<time>|<id>`), so a
// traversal begun before the change and continued after it would be accepted and
// continued APPROXIMATELY — rows skipped silently, which is the very outcome the
// change exists to remove. A token is opaque by contract, but "opaque" is a
// promise the client will not read it, not a promise the server will not know its
// own forms apart.
//
// Hence the version marker. `.` is not in the base64 alphabet, so a token
// carrying one cannot be a legacy token, and a legacy token can never be
// mistaken for this one — the discriminator is structural, not statistical.
//
// # Where it is judged
//
// At the app boundary, as the FIRST statement of the use-case — before the
// short-circuit on identity. An anonymous caller never reaches the repository, so
// a refusal that lived only there would not be reached either, and the same
// malformed token would get different answers depending on what the caller has
// been granted (api-conventions.md: формат → authz → repo).

import (
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/pagetoken"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"
)

// visibleTokenPrefix marks the visible-page cursor form. It is part of the wire
// value: changing it invalidates outstanding tokens, which is a contract change
// and never a refactor.
const visibleTokenPrefix = "kv1."

// VisibleCursor — the boundary of a visible page: the last row RETURNED, in
// keyset order.
type VisibleCursor struct {
	CreatedAt time.Time
	ID        string
}

// EncodeVisiblePageToken renders the cursor. Nanosecond precision is kept
// because the keyset compares the stored timestamp, not the truncated one the
// resource message carries.
func EncodeVisiblePageToken(c VisibleCursor) string {
	return visibleTokenPrefix + pagetoken.Encode(
		pagetoken.Cursor{CreatedAt: c.CreatedAt, ID: c.ID})
}

// DecodeVisiblePageToken parses a token of this form. An empty token is the
// first page and yields (nil, nil) — absence is representable apart from any
// value. Anything else that is not this form is INVALID_ARGUMENT with the
// contract tone, including a token of the previous form.
func DecodeVisiblePageToken(field, token string) (*VisibleCursor, error) {
	if token == "" {
		return nil, nil
	}
	rest, ok := strings.CutPrefix(token, visibleTokenPrefix)
	if !ok {
		return nil, InvalidArg(field, "Illegal argument "+field)
	}
	// Тело — КАНОНИЧЕСКАЯ форма курсора, объявленная один раз (#652). Своим
	// здесь остаётся только префикс: он метит вид страницы и является частью
	// значения на проводе.
	c, ok := pagetoken.Decode(rest)
	if !ok || c == nil {
		return nil, InvalidArg(field, "Illegal argument "+field)
	}
	return &VisibleCursor{CreatedAt: c.CreatedAt, ID: c.ID}, nil
}

// ValidateVisiblePagination — the whole page-format question for a visible-page
// list, answered before anything about the caller is decided.
func ValidateVisiblePagination(pageToken string, pageSize int32) error {
	if pageSize < 0 || pageSize > MaxListPageSize {
		return InvalidArg("page_size", "Illegal argument page_size")
	}
	_, err := DecodeVisiblePageToken("page_token", pageToken)
	return err
}

// ValidateRawVisiblePagination is ValidateVisiblePagination over the RAW request
// values — the transport's int64 page_size before it is narrowed to int32.
// Narrowing saturates, and saturation is not validation: −1 becomes 0, and 0
// means "apply the default", so a caller would receive a page it did not ask for
// and never learn of it.
func ValidateRawVisiblePagination(pageToken string, pageSize int64) error {
	if _, err := corevalidate.PageSize("page_size", pageSize); err != nil {
		return err
	}
	_, err := DecodeVisiblePageToken("page_token", pageToken)
	return err
}

// EffectiveListPageSize resolves a requested page size to the number of visible
// rows a page holds. It mirrors the repository's own resolution (0 means the
// default) and is needed in the use-case because THAT is where the page is now
// filled — the repository no longer knows how large the answer is.
//
// The value is assumed already validated by ValidateVisiblePagination; out of
// range it clamps to the default rather than inventing a limit, and the guard
// above is what makes that branch unreachable on the served path.
func EffectiveListPageSize(pageSize int32) int {
	if pageSize <= 0 || pageSize > MaxListPageSize {
		return DefaultListPageSize
	}
	return int(pageSize)
}

// DefaultListPageSize — the page a caller gets when he names no size. Same value
// the repository applies (pg.defaultListPageSize); stated here because the
// use-case now decides the length of the answer.
const DefaultListPageSize = 50
