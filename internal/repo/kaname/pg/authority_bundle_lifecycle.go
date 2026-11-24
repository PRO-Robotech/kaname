// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

const authorityLifecycleDeadline = 30 * time.Second

// kaname#1034: retries всегда освобождают полную TX и заново получают drain.
// Нельзя ждать освобождения dependency tables, уже удерживая protocol row.
func (r *Repository) authorityLifecycle(ctx context.Context, action func(context.Context, pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, authorityLifecycleDeadline)
	defer cancel()
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx, err := r.master.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `SELECT kaname.authority_protocol_drain()`)
		if err == nil {
			err = action(ctx, tx)
		}
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		rollbackErr := tx.Rollback(cleanup)
		stop()
		if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			return errors.Join(err, rollbackErr)
		}
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || (pgerr.Code != "55P03" && pgerr.Code != "40P01" && pgerr.Code != "40001") {
			return err
		}
		if attempt == authorityEntryAttempts-1 {
			return err
		}
	}
	return kaname.ErrAuthorityClassificationChanged
}

func authorityCatalogSnapshot(ctx context.Context, tx pgx.Tx) (catalog.Halves, error) {
	live, err := readCatalogHalf(ctx, tx, liveCatalogHalf)
	if err != nil {
		return catalog.Halves{}, err
	}
	retired, err := readCatalogHalf(ctx, tx, retiredCatalogHalf)
	if err != nil {
		return catalog.Halves{}, err
	}
	return catalog.Halves{Live: live, Retired: retired}, nil
}
func authorityCatalogMatches(ctx context.Context, tx pgx.Tx, b *granteffect.Bundle) error {
	rows, err := authorityCatalogSnapshot(ctx, tx)
	if err != nil {
		return err
	}
	input, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	if len(input) > granteffect.MaxInputBytes {
		return granteffect.ErrInvalidBundle
	}
	raw, err := catalog.CanonicalJSON(rows)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, b.CanonicalCatalog()) {
		return kaname.ErrSemanticIdentityUnavailable
	}
	return nil
}

func (r *Repository) StageAuthorityBundle(ctx context.Context, b *granteffect.Bundle, editions ...kaname.AuthorityModuleEdition) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	editions = append([]kaname.AuthorityModuleEdition(nil), editions...)
	return r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := authorityCatalogMatches(ctx, tx, b); err != nil {
			return err
		}
		if err := authorityEditionsMatch(ctx, tx, editions); err != nil {
			return err
		}
		id := b.Identity()
		_, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_stage($1,$2,$3,$4,$5)`, b.ModelSource(), b.CanonicalCatalog(), id.ModelID, id.CatalogID, id.ProjectorVersion)
		return err
	})
}
func (r *Repository) ActivateAuthorityBundle(ctx context.Context, b *granteffect.Bundle, editions ...kaname.AuthorityModuleEdition) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	editions = append([]kaname.AuthorityModuleEdition(nil), editions...)
	return r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := authorityCatalogMatches(ctx, tx, b); err != nil {
			return err
		}
		if err := authorityEditionsMatch(ctx, tx, editions); err != nil {
			return err
		}
		id := b.Identity()
		_, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_activate($1,$2,$3)`, id.ModelID, id.CatalogID, id.ProjectorVersion)
		return err
	})
}
func (r *Repository) StageFullAuthorityBundle(ctx context.Context, b *granteffect.Bundle, editions ...kaname.AuthorityModuleEdition) error {
	editions = append([]kaname.AuthorityModuleEdition(nil), editions...)
	return r.changeFullAuthorityBundle(ctx, b, false, func(ctx context.Context, tx pgx.Tx) error {
		if err := requireUnpublishedAuthority(ctx, tx); err != nil {
			return err
		}
		return authorityEditionsMatch(ctx, tx, editions)
	})
}
func (r *Repository) ActivateFullAuthorityBundle(ctx context.Context, b *granteffect.Bundle, editions ...kaname.AuthorityModuleEdition) error {
	editions = append([]kaname.AuthorityModuleEdition(nil), editions...)
	return r.changeFullAuthorityBundle(ctx, b, true, func(ctx context.Context, tx pgx.Tx) error {
		if err := requireUnpublishedAuthority(ctx, tx); err != nil {
			return err
		}
		return authorityEditionsMatch(ctx, tx, editions)
	})
}

// PublicationAuthorityBundle связывает данные владельца с точной редакцией
// журнала. Одинаковые отпечатки модели могут принадлежать разным редакциям.
type PublicationAuthorityBundle struct {
	Bundle    *granteffect.Bundle
	Revision  int64
	Digest    string
	CatalogID string
}

// После появления журнала старый путь активации больше не может поднять
// полномочия только по отпечатку модели. Замок держится до фиксации drain.
func requireUnpublishedAuthority(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `LOCK TABLE kaname.publication_model_revision IN SHARE MODE`); err != nil {
		return err
	}
	var published bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.publication_model_revision)`).Scan(&published); err != nil {
		return err
	}
	if published {
		return kaname.ErrSemanticIdentityUnavailable
	}
	return nil
}

// StageFullPublicationAuthorityBundle готовит ровно прочитанную редакцию.
func (r *Repository) StageFullPublicationAuthorityBundle(ctx context.Context, published PublicationAuthorityBundle) error {
	return r.changeFullAuthorityBundle(ctx, published.Bundle, false, published.matchHead)
}

// ActivateFullPublicationAuthorityBundle повторяет проверку головы под drain.
// Более новая публикация отменяет активацию даже при совпадении текста модели.
func (r *Repository) ActivateFullPublicationAuthorityBundle(ctx context.Context, published PublicationAuthorityBundle) error {
	if err := published.Bundle.Validate(); err != nil {
		return err
	}
	return r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := authorityCatalogMatches(ctx, tx, published.Bundle); err != nil {
			return err
		}
		if err := published.matchHead(ctx, tx); err != nil {
			return err
		}
		return activatePublicationAndRecord(ctx, tx, published)
	})
}

// AdvanceNextCatalogPublication продолжает только уже начатую владельцем цепь.
// Drain, повторная сверка, Stage, Activate и watermark входят в одну транзакцию.
// false означает отсутствие изменения; ошибка не подтверждает результат commit.
func (r *Repository) AdvanceNextCatalogPublication(ctx context.Context, published PublicationAuthorityBundle) (bool, error) {
	if err := published.Bundle.Validate(); err != nil {
		return false, err
	}
	advanced := false
	err := r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// Callback может повториться после rollback: результат относится только
		// к последней попытке, завершившейся подтверждённым commit.
		advanced = false
		if err := authorityCatalogMatches(ctx, tx, published.Bundle); err != nil {
			return err
		}
		if err := published.matchHead(ctx, tx); err != nil {
			return err
		}
		var watermark int64
		var manualHold bool
		var previousDigest, previousCatalog string
		err := tx.QueryRow(ctx, `SELECT w.revision,w.manual_hold,p.digest,p.catalog_id
 FROM kaname.authority_publication_activation w
 JOIN kaname.publication_model_revision p ON p.revision=w.revision
 WHERE w.singleton FOR UPDATE OF w`).Scan(&watermark, &manualHold, &previousDigest, &previousCatalog)
		if errors.Is(err, pgx.ErrNoRows) {
			return kaname.ErrSemanticIdentityUnavailable
		}
		if err != nil {
			return err
		}
		if manualHold || published.Revision == watermark {
			// Ручной запрет сохраняется и для ещё не активированной редакции.
			return nil
		}
		if published.Revision <= watermark || published.Revision-watermark != 1 {
			return kaname.ErrSemanticIdentityUnavailable
		}
		var phase, modelID, catalogID, projector string
		if err := tx.QueryRow(ctx, `SELECT phase,model_id,catalog_id,projector_version
 FROM kaname.authority_semantic_identity WHERE singleton FOR UPDATE`).Scan(&phase, &modelID, &catalogID, &projector); err != nil {
			return err
		}
		id := published.Bundle.Identity()
		switch phase {
		case "transition":
			if "sha256:"+modelID != previousDigest || catalogID != previousCatalog || projector != id.ProjectorVersion {
				return kaname.ErrSemanticIdentityUnavailable
			}
		case "prepared":
			if modelID != id.ModelID || catalogID != id.CatalogID || projector != id.ProjectorVersion {
				return kaname.ErrSemanticIdentityUnavailable
			}
		default:
			return kaname.ErrSemanticIdentityUnavailable
		}
		if _, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_stage_full_v3($1,$2,$3,$4,$5)`,
			published.Bundle.ModelSource(), published.Bundle.CanonicalCatalog(), id.ModelID, id.CatalogID, id.ProjectorVersion); err != nil {
			return err
		}
		if err := activatePublicationAndRecord(ctx, tx, published); err != nil {
			return err
		}
		advanced = true
		return nil
	})
	return advanced && err == nil, err
}

func activatePublicationAndRecord(ctx context.Context, tx pgx.Tx, published PublicationAuthorityBundle) error {
	id := published.Bundle.Identity()
	if _, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_activate_full_v3($1,$2,$3)`, id.ModelID, id.CatalogID, id.ProjectorVersion); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO kaname.authority_publication_activation(singleton,revision,manual_hold)
 VALUES (true,$1,false) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,manual_hold=false`, published.Revision)
	return err
}

func (p PublicationAuthorityBundle) matchHead(ctx context.Context, tx pgx.Tx) error {
	if p.Revision <= 0 || p.Digest != "sha256:"+p.Bundle.Identity().ModelID || p.CatalogID != p.Bundle.Identity().CatalogID {
		return kaname.ErrSemanticIdentityUnavailable
	}
	// Под drain блокируем запись журнала до завершения передачи полномочий,
	// включая первоначальную установку, когда прежней передачи ещё нет.
	if _, err := tx.Exec(ctx, `LOCK TABLE kaname.publication_model_revision IN SHARE MODE`); err != nil {
		return errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	var revision int64
	var digest, catalogID string
	if err := tx.QueryRow(ctx, `SELECT revision,digest,catalog_id FROM kaname.publication_model_revision
 WHERE NOT pg_is_in_recovery() ORDER BY revision DESC LIMIT 1`).Scan(&revision, &digest, &catalogID); err != nil {
		return errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	if revision != p.Revision || digest != p.Digest || catalogID != p.CatalogID {
		return kaname.ErrSemanticIdentityUnavailable
	}
	return nil
}

func (r *Repository) changeFullAuthorityBundle(ctx context.Context, b *granteffect.Bundle, activate bool, matchSource func(context.Context, pgx.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	return r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := authorityCatalogMatches(ctx, tx, b); err != nil {
			return err
		}
		if err := matchSource(ctx, tx); err != nil {
			return err
		}
		id := b.Identity()
		if activate {
			_, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_activate_full_v3($1,$2,$3)`, id.ModelID, id.CatalogID, id.ProjectorVersion)
			return err
		}
		_, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_stage_full_v3($1,$2,$3,$4,$5)`, b.ModelSource(), b.CanonicalCatalog(), id.ModelID, id.CatalogID, id.ProjectorVersion)
		return err
	})
}
func (r *Repository) CloseAuthorityBundle(ctx context.Context) error {
	return r.authorityLifecycle(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT kaname.authority_protocol_close()`)
		return err
	})
}

// LoadAuthorityBundle не принимает readiness/authority flags. Источник модели
// и key terms задаёт реальная композиция caller. Actual catalog защищён table
// locks даже от старых unfenced writers; active identity повторно судит entry.
func (r *Repository) LoadAuthorityBundle(ctx context.Context, expectedModel string, keys ...authzmodel.KeyTerm) (_ *granteffect.Bundle, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if expectedModel == "" || len(expectedModel) > granteffect.MaxInputBytes {
		return nil, granteffect.ErrInvalidBundle
	}
	keys = append([]authzmodel.KeyTerm(nil), keys...)
	ctx, cancel := context.WithTimeout(ctx, authorityLifecycleDeadline)
	defer cancel()
	tx, err := r.master.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(1262569283,0)`); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `LOCK TABLE kaname.catalog_module,kaname.catalog_resource,kaname.catalog_verb IN SHARE MODE`); err != nil {
		return nil, err
	}
	var source string
	var canonical []byte
	var id grantcoverage.Identity
	if err = tx.QueryRow(ctx, `SELECT model_source,catalog_json,model_id,catalog_id,projector_version FROM kaname.authority_protocol_read_bundle()`).Scan(&source, &canonical, &id.ModelID, &id.CatalogID, &id.ProjectorVersion); err != nil {
		return nil, errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
	}
	if source != expectedModel || id.ProjectorVersion != granteffect.ProjectorVersion {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	rows, err := authorityCatalogSnapshot(ctx, tx)
	if err != nil {
		return nil, err
	}
	b, err := granteffect.NewBundle(ctx, source, rows, id.ProjectorVersion, keys...)
	if err != nil {
		return nil, err
	}
	if b.Identity() != id || !bytes.Equal(b.CanonicalCatalog(), canonical) {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	// Откат read-only работы обязан завершиться до передачи immutable результата.
	if err = tx.Rollback(ctx); err != nil {
		return nil, err
	}
	return b, nil
}

var _ kaname.AuthorityBundleLifecycle = (*Repository)(nil)
var _ kaname.AuthorityBundleHandoff = (*Repository)(nil)

// kaname#1034: повторная сверка delivery выполняется ПОСЛЕ drain на той же TX.
// Даже неизменившиеся строки каталога не позволяют выдать старую модель за новую редакцию.
func authorityEditionsMatch(ctx context.Context, tx pgx.Tx, editions []kaname.AuthorityModuleEdition) error {
	seen := make(map[string]struct{}, len(editions))
	for _, want := range editions {
		if want.Module == "" || want.Revision < 0 || (want.Revision == 0) != (want.Digest == "") {
			return kaname.ErrSemanticIdentityUnavailable
		}
		if _, ok := seen[want.Module]; ok {
			return kaname.ErrSemanticIdentityUnavailable
		}
		seen[want.Module] = struct{}{}
		var revision int64
		var digest string
		if err := tx.QueryRow(ctx, `SELECT coalesce(applied_revision,0),coalesce(applied_digest,'') FROM kaname.catalog_module WHERE module=$1 AND live`, want.Module).Scan(&revision, &digest); err != nil {
			return errors.Join(kaname.ErrSemanticIdentityUnavailable, err)
		}
		if revision != want.Revision || digest != want.Digest {
			return kaname.ErrSemanticIdentityUnavailable
		}
	}
	return nil
}
