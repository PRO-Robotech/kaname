// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/PRO-Robotech/corelib/migratorcli"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const (
	registrationReconciliation = int64(20261026090001)
	registrationCollision = int64(20261026090000)
	creatorMigration = "20261026090000_service_account_creation_is_its_own_right.sql"
	writerMigration = "historical/20261026090000_module_writes_only_what_its_manifest_declares.sql"
)

// registrationHistoryFS выбирает исходную половину столкнувшегося номера.
// Файлы истории и строки goose не меняются: подстановка действует только
// для текущего вызова накатчика и только при сохранённом происхождении.
type registrationHistoryFS struct {
	fs.FS
	writer bool
}

type registrationMigrationFile struct {
	*bytes.Reader
	info fs.FileInfo
}

type registrationMigrationInfo struct {
	fs.FileInfo
	size int64
}

func (i registrationMigrationInfo) Size() int64 { return i.size }

func (f *registrationMigrationFile) Close() error { return nil }
func (f *registrationMigrationFile) Stat() (fs.FileInfo,error) { return f.info,nil }

func (f registrationHistoryFS) Open(name string) (fs.File, error) {
	if name == creatorMigration {
		input:=f.FS
		path:=name
		side:="creator"
		if f.writer { input=migrations.Historical; path=writerMigration; side="writer" }
		data,err:=fs.ReadFile(input,path)
		if err!=nil { return nil,err }
		info,err:=fs.Stat(input,path)
		if err!=nil { return nil,err }
		// Исходный SQL идёт дословно; перед ним в той же транзакции исполняется
		// общий страж потери данных. История файла и ledger не переписываются.
		guard:="\nSELECT kaname.registration_lineage_assert_unused('"+side+"');\n"
		body:=strings.Replace(string(data),migrations.SectionDownMarker,migrations.SectionDownMarker+guard,1)
		return &registrationMigrationFile{Reader:bytes.NewReader([]byte(body)),info:registrationMigrationInfo{FileInfo:info,size:int64(len(body))}},nil
	}
	return f.FS.Open(name)
}

// registrationMigrationSource отказывает до первого Down, если запрос пересёк
// границу с неизвестным происхождением. Номер максимальной записи недостаточен:
// WithAllowMissing допускает дыру ниже головы, поэтому читаются все версии.
func registrationMigrationSource(ctx context.Context, opts *rootOptions, source fs.FS, target string, down bool) (fs.FS, error) {
	if _, err := fs.Stat(source, "20261026090001_reconcile_registration_and_creator_lineages.sql"); err != nil {
		if !errors.Is(err, fs.ErrNotExist) { return nil, err }
		return source, nil
	}
	spec, err := migratorcli.ResolveDialectSpec(opts.dialect)
	if err != nil { return nil, err }
	dsn, err := validatedMigrationDSN(opts)
	if err != nil { return nil, err }
	db, err := migratorcli.OpenDB(ctx, dsn, spec, migratorcli.NewNoticeRelay(serviceName, io.Discard))
	if err != nil { return nil, err }
	defer func() { _ = db.Close() }()
	var hasLedger, hasOrigin bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('goose_db_version') IS NOT NULL,
        to_regclass('kaname.registration_lineage_origin') IS NOT NULL`).Scan(&hasLedger, &hasOrigin); err != nil {
		return nil, err
	}
	applied := map[int64]bool{}
	var head int64
	if hasLedger {
		rows, err := db.QueryContext(ctx, `SELECT version_id, is_applied FROM
            (SELECT DISTINCT ON (version_id) version_id, is_applied
               FROM goose_db_version ORDER BY version_id, id DESC) AS latest`)
		if err != nil { return nil, err }
		for rows.Next() {
			var version int64
			var active bool
			if err := rows.Scan(&version,&active); err != nil { _ = rows.Close(); return nil, err }
			applied[version] = active
			if active && version > head { head = version }
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil { return nil, err }
	}
	floor := head-1
	if target != "" {
		floor, err = migratorcli.ParseTargetVersion(target)
		if err != nil { return nil, err }
	}
	if !hasOrigin {
		if down && applied[registrationReconciliation] && floor < registrationReconciliation {
			return nil, fmt.Errorf("registration rollback refused before any Down: reconciliation provenance is missing")
		}
		if down && applied[registrationCollision] && floor < registrationCollision {
			return nil,fmt.Errorf("registration rollback refused before any Down: historical 90000 origin is unknown; reconcile the lineage before rollback")
		}
		return source, nil
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM kaname.registration_lineage_origin`).Scan(&count); err != nil { return nil, err }
	if count != 1 { return nil, fmt.Errorf("registration migration provenance must contain exactly one origin") }
	var creator, writer bool
	var version int
	var state string
	if err := db.QueryRowContext(ctx, `SELECT format_version,had_creator,had_writer,state
        FROM kaname.registration_lineage_origin WHERE singleton`).Scan(&version,&creator,&writer,&state); err != nil { return nil, err }
	if version != 1 || (!creator && !writer) || (state != "up" && state != "down") || (applied[registrationReconciliation] != (state == "up")) {
		return nil, fmt.Errorf("registration migration provenance does not match the applied ledger")
	}
	if down && creator && writer && applied[registrationCollision] && floor < registrationCollision {
		return nil, fmt.Errorf("registration rollback refused before any Down: both historical 90000 lineages have an ambiguous ledger owner")
	}
	if down && applied[registrationReconciliation] && floor < registrationReconciliation {
		var matches bool
		if err := db.QueryRowContext(ctx, `SELECT complete_shape=kaname.registration_lineage_shape()
            FROM kaname.registration_lineage_origin WHERE singleton`).Scan(&matches); err != nil { return nil, err }
		if !matches { return nil, fmt.Errorf("registration rollback refused before any Down: reconciled schema differs") }
	}
	if writer && !creator {
		data, err := migrations.Historical.ReadFile(writerMigration)
		if err != nil { return nil, err }
		if fmt.Sprintf("%x",sha256.Sum256(data)) != "bd9449a671136b68ae82ce38edabbe2801a056fd4f7919fde769406be7bced29" {
			return nil, fmt.Errorf("registration historical writer identity differs")
		}
		return registrationHistoryFS{FS:source,writer:true}, nil
	}
	return registrationHistoryFS{FS:source}, nil
}
