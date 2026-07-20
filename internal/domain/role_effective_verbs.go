// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// role_effective_verbs.go — redesign-2026 F6. The honest effective-verb preview
// surfaced by RoleService (authored vs effective). authoredVerbs is the deduped,
// canonically-ordered union of the verbs the role's rules grant (`*` expands to
// full CRUD). effectiveVerbs adds the editor `delete*` qualifier: a role that
// grants `update` but not `delete`/`*` is editor-tier, and an editor MAY delete
// the in-scope leaf objects it edits (co-materialized), but NOT the account/project
// anchor — the verbNote states this verbatim so the least-privilege preview never
// under-promises.

// crudOrder — the canonical CRUD ordering; unknown verbs sort after, stably.
var crudOrder = []string{"get", "list", "create", "update", "delete"}

// EditorDeleteVerb is the qualifier appended to an editor-tier role's effective
// verbs (delete of in-scope leaf objects, not the anchor).
const EditorDeleteVerb = "delete*"

// EditorDeleteNote is the verbatim explanation of the editor delete-qualifier.
const EditorDeleteNote = "co-materialized on in-scope leaf objects, NOT on the account/project anchor itself"

// expandedVerbSet returns the deduped verb set the role grants, with `*` expanded
// to full CRUD, plus whether any rule used the `*` wildcard.
func (r Role) expandedVerbSet() (set map[string]bool, wildcard bool) {
	set = map[string]bool{}
	for _, rule := range r.Rules {
		for _, v := range rule.Verbs {
			if v == "*" {
				wildcard = true
				for _, c := range crudOrder {
					set[c] = true
				}
				continue
			}
			set[v] = true
		}
	}
	return set, wildcard
}

// orderVerbs returns the verbs of set in canonical CRUD order, unknown verbs
// appended in first-seen... deterministic (sorted) order.
func orderVerbs(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	seen := map[string]bool{}
	for _, c := range crudOrder {
		if set[c] {
			out = append(out, c)
			seen[c] = true
		}
	}
	// deterministic tail for any non-CRUD verbs.
	extra := make([]string, 0)
	for v := range set {
		if !seen[v] {
			extra = append(extra, v)
		}
	}
	sortStrings(extra)
	return append(out, extra...)
}

// AuthoredVerbs is the deduped, canonically-ordered union of the role's rule verbs
// (`*` expands to full CRUD). Empty for a label-only / rules-less role.
func (r Role) AuthoredVerbs() []string {
	set, _ := r.expandedVerbSet()
	return orderVerbs(set)
}

// isEditorTier reports whether the role is editor-tier: it grants `update` but not
// `delete` and did not use the `*` wildcard (an admin/owner already carries delete).
func (r Role) isEditorTier() bool {
	set, wildcard := r.expandedVerbSet()
	return !wildcard && set["update"] && !set["delete"]
}

// EffectiveVerbs is AuthoredVerbs plus the editor `delete*` qualifier for an
// editor-tier role.
func (r Role) EffectiveVerbs() []string {
	authored := r.AuthoredVerbs()
	if r.isEditorTier() {
		return append(authored, EditorDeleteVerb)
	}
	return authored
}

// VerbNotes returns the per-verb clarifications for the effective preview. Only
// the editor `delete*` qualifier carries a note today.
func (r Role) VerbNotes() map[string]string {
	if r.isEditorTier() {
		return map[string]string{EditorDeleteVerb: EditorDeleteNote}
	}
	return map[string]string{}
}

// sortStrings — tiny in-place ascending sort (avoids importing sort for one call).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
