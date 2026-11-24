// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Порт сохраняет адаптеры полосы входа и допускает выбор поколения перед TX.
type humanRegistrationStore interface {
	Writer(context.Context) (*kanamepg.RegistrationWriter, error)
	VerificationWriter(context.Context, domain.UserID) (*kanamepg.RegistrationWriter, error)
	EmailChangeWriter(context.Context, domain.UserID) (*kanamepg.RegistrationWriter, error)
	RunRegistrationWrite(context.Context, func(context.Context, *kanamepg.RegistrationWriter) error) error
	RunVerificationWrite(context.Context, domain.UserID, func(context.Context, *kanamepg.RegistrationWriter) error) error
	RunEmailChangeWrite(context.Context, domain.UserID, func(context.Context, *kanamepg.RegistrationWriter) error) error
}

type humanRecoveryStore interface {
	humansession.RecoveryCompletionStore
	humansession.PreparedRecoveryCompletionStore
}

// Старые режимы сохраняют прежний participant; опубликованный режим выбирает
// его из того же поколения, что и остальные писатели полного старта.
func loginHumanAdmissionStores(pool *pgxpool.Pool, mode config.AuthorityProtocolConfig, participant *kanamepg.HumanAdmissionParticipant,
	published ...*publishedWriterGenerations,
) (humanRegistrationStore, humanRecoveryStore, error) {
	if err := mode.Validate(); err != nil {
		return nil, nil, err
	}
	if len(published) > 1 {
		return nil, nil, fmt.Errorf("human admission accepts one published generation source")
	}
	if len(published) == 1 && published[0] != nil {
		r := published[0]
		if !mode.Participant() || r.pool == nil || r.pool != pool || r.repo == nil || r.store == nil {
			return nil, nil, fmt.Errorf("published human admission generation source is invalid")
		}
		store := &publishedHumanAdmissionStore{writers: r}
		return store, store, nil
	}
	return humanAdmissionStores(pool, mode, participant)
}

type publishedHumanAdmissionStore struct{ writers *publishedWriterGenerations }

// Конкретные хранилища одной попытки держат неизменяемый participant.
// Повторы открываются внутри них и не выбирают новое поколение.
func (s *publishedHumanAdmissionStore) resolve(ctx context.Context) (context.Context, *kanamepg.RegistrationStore, *kanamepg.RecoveryCompletionStore, error) {
	if s == nil || s.writers == nil {
		return ctx, nil, nil, kaname.ErrInvalidAuthorityFencePlan
	}
	pinned, generation, err := s.writers.resolve(ctx)
	if err != nil {
		return pinned, nil, nil, err
	}
	registration, recovery, err := humanAdmissionStores(s.writers.pool,
		config.AuthorityProtocolConfig{Participation: "participant"}, generation.admission)
	return pinned, registration, recovery, err
}

func (r *publishedWriterGenerations) IdentityLifecycleWriter(ctx context.Context, kind kaname.IdentityMutation, id domain.UserID) (kaname.Writer, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return generation.admission.IdentityLifecycleWriter(pinned, kind, id)
}

func (s *publishedHumanAdmissionStore) Writer(ctx context.Context) (*kanamepg.RegistrationWriter, error) {
	pinned, registration, _, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return registration.Writer(pinned)
}

func (s *publishedHumanAdmissionStore) VerificationWriter(ctx context.Context, id domain.UserID) (*kanamepg.RegistrationWriter, error) {
	pinned, registration, _, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return registration.VerificationWriter(pinned, id)
}

func (s *publishedHumanAdmissionStore) EmailChangeWriter(ctx context.Context, id domain.UserID) (*kanamepg.RegistrationWriter, error) {
	pinned, registration, _, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return registration.EmailChangeWriter(pinned, id)
}

func (s *publishedHumanAdmissionStore) RecoveryCompletionWriter(ctx context.Context, id domain.UserID) (humansession.RecoveryCompletionWriter, error) {
	pinned, _, recovery, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return recovery.RecoveryCompletionWriter(pinned, id)
}

func (s *publishedHumanAdmissionStore) RunRegistrationWrite(ctx context.Context, body func(context.Context, *kanamepg.RegistrationWriter) error) error {
	pinned, registration, _, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return registration.RunRegistrationWrite(pinned, body)
}

func (s *publishedHumanAdmissionStore) RunVerificationWrite(ctx context.Context, id domain.UserID, body func(context.Context, *kanamepg.RegistrationWriter) error) error {
	pinned, registration, _, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return registration.RunVerificationWrite(pinned, id, body)
}

func (s *publishedHumanAdmissionStore) RunEmailChangeWrite(ctx context.Context, id domain.UserID, body func(context.Context, *kanamepg.RegistrationWriter) error) error {
	pinned, registration, _, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return registration.RunEmailChangeWrite(pinned, id, body)
}

func (s *publishedHumanAdmissionStore) RunRecoveryCompletionWrite(ctx context.Context, id domain.UserID, body func(context.Context, humansession.RecoveryCompletionWriter) error) error {
	pinned, _, recovery, err := s.resolve(ctx)
	if err != nil {
		return err
	}
	return recovery.RunRecoveryCompletionWrite(pinned, id, body)
}

var (
	_ kaname.IdentityLifecycleWriterFactory = (*publishedWriterGenerations)(nil)
	_ humanRegistrationStore                = (*publishedHumanAdmissionStore)(nil)
	_ humanRecoveryStore                    = (*publishedHumanAdmissionStore)(nil)
)
