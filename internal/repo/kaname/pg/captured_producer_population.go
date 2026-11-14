// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Ни захват, ни привязанная запись не имеют публичного конструктора. Перепись
// публикуется лишь после успешного чтения всех RR-страниц и списания их бюджета.
// Её полнота описывает эту RR-перепись, но никогда не текущую RC-популяцию.
type producerReceiptKey [7]string
type producerReceiptWitness struct {
	key   producerReceiptKey
	state string
}
type producerPopulationCapture struct {
	actor    domain.Subject
	bundle   *granteffect.Bundle
	conn     *pgx.Conn
	receipts []producerReceiptWitness
	budget   *relverdict.AdministrativeReadBudget
	owner    *authorityWriteTx
}
type boundProducerPopulation struct {
	capture *producerPopulationCapture
	owner   *authorityWriteTx
	at      time.Time
}

func captureProducerPopulation(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, actor domain.Subject, budget *relverdict.AdministrativeReadBudget) (*producerPopulationCapture, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tx == nil || bundle == nil || bundle.Validate() != nil || actor.Validate() != nil || actor.ID == "*" || (actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := chargeNativePolicyBudget(budget, 1, 1); err != nil {
		return nil, err
	}
	var isolation, readonly string
	if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation'), current_setting('transaction_read_only')`).Scan(&isolation, &readonly); err != nil {
		return nil, err
	}
	// Существующие RR-этапы prepared-role пишут только в собственный временный spool.
	// Допущены оба RR-режима; сам этот сборщик выполняет только SELECT.
	if isolation != "repeatable read" || (readonly != "on" && readonly != "off") {
		return nil, kaname.ErrSourceUnconfirmed
	}
	c := &producerPopulationCapture{actor: actor, bundle: bundle, conn: tx.Conn(), budget: budget}
	public := slices.Contains(domain.SpeakerClasses(string(actor.Type)+":"+string(actor.ID)), domain.SpeakerAnonymous)
	cursor := ""
	for {
		if err := chargeNativePolicyBudget(budget, 0, 1); err != nil {
			return nil, err
		}
		rows, err := tx.Query(ctx, captureProducerPopulationSQL, string(actor.Type), string(actor.ID), public, cursor, kaname.MaxCanonicalSourcePage)
		if err != nil {
			return nil, err
		}
		count := 0
		for rows.Next() {
			var raw, state string
			if err = rows.Scan(&raw, &state); err != nil {
				rows.Close()
				return nil, err
			}
			if err = chargeNativePolicyBudget(budget, 1, 0); err != nil {
				rows.Close()
				return nil, err
			}
			var key producerReceiptKey
			if json.Unmarshal([]byte(raw), &key) != nil || key[0] == "" || raw <= cursor {
				rows.Close()
				return nil, kaname.ErrSourceUnconfirmed
			}
			c.receipts = append(c.receipts, producerReceiptWitness{key: key, state: state})
			cursor = raw
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		if count < kaname.MaxCanonicalSourcePage {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *producerPopulationCapture) bind(w *authorityWriteTx, bundle *granteffect.Bundle, budget *relverdict.AdministrativeReadBudget) error {
	if c == nil || w == nil || w.closed || w.writeTx == nil || w.tx == nil || c.conn == nil || w.tx.Conn() != c.conn || c.bundle != bundle || budget == nil || budget != c.budget || w.fence.decisionAt.IsZero() || (c.owner != nil && c.owner != w) {
		return kaname.ErrSourceUnconfirmed
	}
	c.owner = w
	if w.producerCaptures == nil {
		w.producerCaptures = make(map[domain.Subject]*boundProducerPopulation)
	}
	// Более поздние окончательные часы создают новую запись: свидетельства, собранные до
	// последнего ожидания, недействительны, даже если часы backend вернули тот же момент.
	w.producerCaptures[c.actor] = &boundProducerPopulation{capture: c, owner: w, at: w.fence.decisionAt}
	w.producerBudget = budget
	return nil
}

func (p *boundProducerPopulation) Validate(writer kaname.SemanticAuthorityWriter, actor domain.Subject, at time.Time) error {
	var w *semanticAuthorityWriteTx
	switch typed := writer.(type) {
	case *semanticAuthorityWriteTx:
		w = typed
	case *preparedRoleWriteTx:
		if typed != nil {
			w = typed.semanticAuthorityWriteTx
		}
	default:
		return kaname.ErrSourceUnconfirmed
	}
	if w == nil || w.authorityWriteTx == nil || p == nil || p.capture == nil || p.owner == nil || w.authorityWriteTx != p.owner || p.owner.closed || p.capture.owner != p.owner || p.capture.actor != actor || p.capture.bundle != w.bundle || p.owner.producerCaptures[actor] != p || p.owner.producerBudget != p.capture.budget || p.owner.writeTx == nil || p.owner.tx == nil || p.owner.tx.Conn() != p.capture.conn || at.IsZero() || !at.Equal(p.at) || !at.Equal(p.owner.fence.decisionAt) {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}

func (w *semanticAuthorityWriteTx) CapturedProducerPopulation(ctx context.Context, actor domain.Subject) (kaname.CapturedProducerPopulation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if w == nil || w.authorityWriteTx == nil || w.closed {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if w.producerCaptures == nil {
		return nil, nil
	} // historical full-population mode
	p := w.producerCaptures[actor]
	if err := p.Validate(w, actor, w.fence.decisionAt); err != nil {
		return nil, err
	}
	return p, nil
}

// page принимает только курсор, созданный этим неизменяемым захватом. SQL-порядок
// текущих строк не может создать, пропустить или переупорядочить следующую захваченную страницу.
func (c *producerPopulationCapture) page(after string, limit int) ([]producerReceiptWitness, string, error) {
	if c == nil || limit <= 0 || limit > kaname.MaxCanonicalSourcePage {
		return nil, "", kaname.ErrCanonicalSourceInvalid
	}
	start := 0
	if after != "" {
		if len(after) > 4096 {
			return nil, "", kaname.ErrCanonicalSourceInvalid
		}
		raw, err := base64.RawURLEncoding.DecodeString(after)
		var key producerReceiptKey
		if err != nil || json.Unmarshal(raw, &key) != nil {
			return nil, "", kaname.ErrCanonicalSourceInvalid
		}
		found := false
		for i, r := range c.receipts {
			if r.key == key {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return nil, "", kaname.ErrCanonicalSourceInvalid
		}
	}
	end := min(start+limit, len(c.receipts))
	next := ""
	if end < len(c.receipts) {
		raw, _ := json.Marshal(c.receipts[end-1].key)
		next = base64.RawURLEncoding.EncodeToString(raw)
	}
	return c.receipts[start:end], next, nil
}

func (w *semanticAuthorityWriteTx) capturedProducerSources(ctx context.Context, f kaname.CanonicalSourceFilter) (kaname.ProducerSourcePage, string, error) {
	if _, err := canonicalPage(kaname.CanonicalSourceFilter{Actor: f.Actor, Limit: f.Limit}); err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	token, err := w.CapturedProducerPopulation(ctx, f.Actor)
	if err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	p, ok := token.(*boundProducerPopulation)
	if !ok {
		return kaname.ProducerSourcePage{}, "", kaname.ErrSourceUnconfirmed
	}
	captured, next, err := p.capture.page(f.After, f.Limit)
	if err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	keys := make([]producerReceiptKey, 0, len(captured))
	for _, r := range captured {
		keys = append(keys, r.key)
	}
	encoded, err := json.Marshal(keys)
	if err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	cost, err := w.rereadCapturedProducerState(ctx, captured, encoded)
	if err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	f.After = ""
	page, _, err := w.producerSourcesQuery(ctx, f, encoded)
	if err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	if len(page.Sources) != len(captured) {
		return kaname.ProducerSourcePage{}, "", kaname.ErrAuthorityClassificationChanged
	}
	page.Cost.Rows += cost.Rows
	page.Cost.Reads += cost.Reads
	if err = p.Validate(w, f.Actor, w.fence.decisionAt); err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	if err = ctx.Err(); err != nil {
		return kaname.ProducerSourcePage{}, "", err
	}
	return page, next, nil
}

func (w *semanticAuthorityWriteTx) rereadCapturedProducerState(ctx context.Context, captured []producerReceiptWitness, encoded []byte) (kaname.SourceReadCost, error) {
	// Текущая популяция не перечисляется: даже неактивные, перенесённые или повторно вставленные строки перечитываются по
	// точным захваченным ключам. Изменённый или отсутствующий источник перезапускает подготовку всей попытки.
	wanted := make(map[producerReceiptKey]string, len(captured))
	for _, r := range captured {
		wanted[r.key] = r.state
	}
	rows, err := w.tx.Query(ctx, rereadCapturedProducerSQL, encoded)
	if err != nil {
		return kaname.SourceReadCost{}, err
	}
	cost := kaname.SourceReadCost{Reads: 1}
	for rows.Next() {
		var raw, state string
		if err = rows.Scan(&raw, &state); err != nil {
			rows.Close()
			return kaname.SourceReadCost{}, err
		}
		cost.Rows++
		var key producerReceiptKey
		if json.Unmarshal([]byte(raw), &key) != nil || wanted[key] == "" || wanted[key] != state {
			rows.Close()
			return kaname.SourceReadCost{}, kaname.ErrAuthorityClassificationChanged
		}
		delete(wanted, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return kaname.SourceReadCost{}, err
	}
	if len(wanted) != 0 {
		return kaname.SourceReadCost{}, kaname.ErrAuthorityClassificationChanged
	}
	return cost, ctx.Err()
}

// xmin + ctid привязывают фактическое воплощение строки, включая ABA с равными значениями.
// Полный JSON привязывает все поля состояния/версии receipt; текущая допустимость поддержки
// отдельно проверяется producerSourcesQuery под удерживаемыми policy epochs.
const capturedProducerKeySQL = `jsonb_build_array(r.kind,r.module,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id)`
const capturedProducerStateSQL = `jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))::text`
const captureProducerPopulationSQL = `SELECT ` + capturedProducerKeySQL + `::text, ` + capturedProducerStateSQL + `
 FROM kaname.producer_source_receipt r WHERE r.active
 AND ((r.kind='registration_owner' AND r.subject_type=$1 AND r.subject_id=$2) OR (r.kind='publication' AND $3))
 AND ` + capturedProducerKeySQL + `::text COLLATE "C" > $4::text COLLATE "C"
 ORDER BY ` + capturedProducerKeySQL + `::text COLLATE "C" LIMIT $5`
const rereadCapturedProducerSQL = `SELECT ` + capturedProducerKeySQL + `::text, ` + capturedProducerStateSQL + `
 FROM kaname.producer_source_receipt r WHERE EXISTS(SELECT 1 FROM jsonb_array_elements($1::jsonb) wanted WHERE wanted.value=` + capturedProducerKeySQL + `)`

var _ kaname.CapturedProducerPopulationReader = (*semanticAuthorityWriteTx)(nil)
var _ kaname.CapturedProducerPopulation = (*boundProducerPopulation)(nil)
