// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type canonicalCursor struct{ Kind, ID string }

func canonicalPage(f kaname.CanonicalSourceFilter) (canonicalCursor, error) {
	if f.Actor.Validate() != nil || f.Actor.ID == "*" || (f.Actor.Type != domain.SubjectTypeUser && f.Actor.Type != domain.SubjectTypeServiceAccount) || f.Limit < 1 || f.Limit > kaname.MaxCanonicalSourcePage {
		return canonicalCursor{}, kaname.ErrCanonicalSourceInvalid
	}
	if f.After == "" {
		return canonicalCursor{}, nil
	}
	if len(f.After) > 2048 {
		return canonicalCursor{}, kaname.ErrCanonicalSourceInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(f.After)
	var c canonicalCursor
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Kind == "" || c.ID == "" || strings.ContainsRune(c.ID, 0) {
		return canonicalCursor{}, kaname.ErrCanonicalSourceInvalid
	}
	return c, nil
}
func canonicalNext(kind, id string) string {
	b, _ := json.Marshal(canonicalCursor{kind, id})
	return base64.RawURLEncoding.EncodeToString(b)
}
func (w *authorityWriteTx) canonicalCoverage(account domain.AccountID) error {
	if w.fence.decisionAt.IsZero() {
		return kaname.ErrCanonicalSourceInvalid
	}
	if w.fence.mode == kaname.AuthorityFenceGlobal {
		return nil
	}
	if w.fence.mode != kaname.AuthorityFenceAccounts {
		return kaname.ErrCanonicalSourceFence
	}
	// Глобальные источники защищены общим shared cluster fence только после
	// подключения ВСЕХ global writers. Этот компонент не удостоверяет cutover.
	if account == "" {
		return nil
	}
	for _, a := range w.fence.accounts {
		if a == account {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", kaname.ErrCanonicalSourceFence, account)
}

// CanonicalDirectSources читает только текущие authoritative rows на w.tx.
// relation_fact/ledger не участвуют даже как запасной путь. Полный обход actor
// проверяет все account partitions; чужой partition даёт ошибку, не усечение.
func (w *authorityWriteTx) CanonicalDirectSources(ctx context.Context, f kaname.CanonicalSourceFilter) ([]kaname.CanonicalDirectSource, string, error) {
	c, err := canonicalPage(f)
	if err != nil {
		return nil, "", err
	}
	if err = w.canonicalCoverage(""); err != nil {
		return nil, "", err
	}
	rows, err := w.tx.Query(ctx, `WITH sources AS (
 SELECT 'account_owner'::text kind,a.id source_id,a.id account_id,'account'::text object_type,a.id object_id,'owner'::text relation,'user'::text recipient_type,a.owner_user_id recipient_id,NULL::timestamptz expires_at
 FROM kaname.accounts a JOIN kaname.users u ON u.id=a.owner_user_id WHERE $1='user' AND a.owner_user_id=$2
 UNION ALL
 SELECT 'cluster_admin',g.id,'','cluster',g.cluster_id,'system_admin',g.subject_type,g.subject_id,g.granted_until
 FROM kaname.cluster_admin_grants g WHERE g.subject_type=$1 AND g.subject_id=$2 AND (g.granted_until IS NULL OR g.granted_until>$3)
 UNION ALL
 SELECT 'user_self',u.id,'','iam_user',u.id,'subject','user',u.id,NULL::timestamptz
 FROM kaname.users u WHERE $1='user' AND u.id=$2
 ) SELECT kind,source_id,account_id,object_type,object_id,relation,recipient_type,recipient_id,expires_at FROM sources
 WHERE (kind COLLATE "C",source_id COLLATE "C")>($4::text COLLATE "C",$5::text COLLATE "C")
 ORDER BY kind COLLATE "C",source_id COLLATE "C" LIMIT $6`, string(f.Actor.Type), string(f.Actor.ID), w.fence.decisionAt, c.Kind, c.ID, f.Limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []kaname.CanonicalDirectSource{}
	for rows.Next() {
		var s kaname.CanonicalDirectSource
		if err = rows.Scan(&s.SourceKind, &s.SourceID, &s.AccountID, &s.ObjectType, &s.ObjectID, &s.Relation, &s.Recipient.Type, &s.Recipient.ID, &s.ExpiresAt); err != nil {
			return nil, "", err
		}
		if s.SourceID == "" || s.ObjectID == "" || s.Recipient != f.Actor || (s.SourceKind == kaname.CanonicalClusterAdmin && s.ObjectID != domain.ClusterSingletonID) {
			return nil, "", kaname.ErrCanonicalSourceInvalid
		}
		if err = w.canonicalCoverage(s.AccountID); err != nil {
			return nil, "", err
		}
		out = append(out, s)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > f.Limit {
		out = out[:f.Limit]
		last := out[len(out)-1]
		next = canonicalNext(string(last.SourceKind), last.SourceID)
	}
	return out, next, nil
}

// CanonicalCreatorSources не проецирует создателя в полномочия. Тип и ID
// берутся из одной immutable пары service_accounts, на той же транзакции.
func (w *authorityWriteTx) CanonicalCreatorSources(ctx context.Context, f kaname.CanonicalSourceFilter) ([]kaname.CanonicalCreatorSource, string, error) {
	c, err := canonicalPage(f)
	if err != nil {
		return nil, "", err
	}
	if c.Kind != "" && c.Kind != "service_account_creator" {
		return nil, "", kaname.ErrCanonicalSourceInvalid
	}
	if err = w.canonicalCoverage(""); err != nil {
		return nil, "", err
	}
	rows, err := w.tx.Query(ctx, `SELECT id,account_id,created_by_type,created_by_id FROM kaname.service_accounts
 WHERE created_by_type=$1 AND created_by_id=$2 AND id COLLATE "C">$3::text COLLATE "C" ORDER BY id COLLATE "C" LIMIT $4`, string(f.Actor.Type), string(f.Actor.ID), c.ID, f.Limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []kaname.CanonicalCreatorSource{}
	for rows.Next() {
		var s kaname.CanonicalCreatorSource
		if err = rows.Scan(&s.ObjectID, &s.AccountID, &s.Creator.Type, &s.Creator.ID); err != nil {
			return nil, "", err
		}
		s.SourceID = s.ObjectID
		s.ObjectType = "iam_service_account"
		if s.ObjectID == "" || s.AccountID == "" || s.Creator != f.Actor {
			return nil, "", kaname.ErrCanonicalSourceInvalid
		}
		if err = w.canonicalCoverage(s.AccountID); err != nil {
			return nil, "", err
		}
		out = append(out, s)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > f.Limit {
		out = out[:f.Limit]
		next = canonicalNext("service_account_creator", out[len(out)-1].SourceID)
	}
	return out, next, nil
}
