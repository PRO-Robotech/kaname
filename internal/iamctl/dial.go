// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamctl

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"

	operationv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/grpcclient"
)

// dial.go — переходник от сгенерированного gRPC-клиента к порту ModuleService.
//
// # Незашифрованного пути у инструмента НЕТ
//
// Всякий поднятый стенд работает в производственной посадке, поэтому именованной
// ручки обхода («-insecure») здесь нет вовсе: она давала бы режим, годный только
// для стенда, а такой режим — нарушение, а не удобство.
//
// # Адрес и удостоверение — ПАРА
//
// Объявить адрес соседа и не объявить удостоверение к нему значит завести
// контроль, который отказывает всегда и по одной причине, а выглядит
// настроенным. Половина пары отвергается разбором вызова — до сети, а не на
// первом обращении к ней.

// DialConfig — что нужно, чтобы дойти до службы применения.
type DialConfig struct {
	// Endpoint — адрес ВНУТРЕННЕГО слушателя iam. Глаголы каталога модуля
	// внешним маршрутизатором не обслуживаются by construction.
	Endpoint string
	// ServerName сверяется с SAN сертификата службы.
	ServerName string
	// CAFiles — корни доверия, которыми проверяется сертификат службы.
	CAFiles []string
	// CertFile, KeyFile — СВОЁ удостоверение: служба принимает решение по
	// личности вызывающего, а не по факту достижимости.
	CertFile string
	KeyFile  string
	// Timeout — срок КАЖДОГО вызова. Без него неотвечающий сосед вешает
	// инструмент навсегда.
	Timeout time.Duration
}

// Validate — fail-closed разбор посадки: неполная пара не доезжает до сети.
//
// Отказ называет ФЛАГ, а не поле структуры: читает его оператор, а не тот, кто
// правит эту строку.
func (c DialConfig) Validate() error {
	var missing []string
	if c.Endpoint == "" {
		missing = append(missing, "-endpoint (адрес внутреннего слушателя iam)")
	}
	if c.ServerName == "" {
		missing = append(missing, "-server-name (имя в SAN сертификата службы)")
	}
	if len(c.CAFiles) == 0 {
		missing = append(missing, "-ca (корень доверия, которым проверяется сертификат службы)")
	}
	if c.CertFile == "" {
		missing = append(missing, "-cert (СВОЁ удостоверение: служба решает по личности вызывающего)")
	}
	if c.KeyFile == "" {
		missing = append(missing, "-key (ключ к своему удостоверению)")
	}
	if c.Timeout <= 0 {
		missing = append(missing, "-timeout (срок каждого вызова; без него неотвечающий сосед вешает инструмент)")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("посадка неполна — не заданы:\n\t%s\n"+
		"адрес службы и удостоверение к ней приезжают ПАРОЙ: половина её даёт вызов, "+
		"который отвергается всегда и по одной причине, а выглядит настроенным; "+
		"незашифрованного пути у инструмента нет",
		joinLines(missing))
}

func joinLines(items []string) string {
	out := ""
	for i, it := range items {
		if i > 0 {
			out += "\n\t"
		}
		out += it
	}
	return out
}

// Connector отдаёт Deps.Connect поверх сгенерированного клиента.
//
// Посадка проверяется ВНУТРИ замыкания, а не при сборке: validate обязан
// работать там, где ни адреса, ни сертификатов нет вовсе, и разбор посадки на
// старте отнял бы у него эту способность.
func Connector(cfg DialConfig) func(context.Context) (ModuleService, func() error, error) {
	return func(context.Context) (ModuleService, func() error, error) {
		if err := cfg.Validate(); err != nil {
			return nil, nil, err
		}
		creds, err := grpcclient.TLSClientCreds(grpcclient.TLSClient{
			Enable:     true,
			CertFile:   cfg.CertFile,
			KeyFile:    cfg.KeyFile,
			CAFiles:    cfg.CAFiles,
			ServerName: cfg.ServerName,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("удостоверение не собрано: %w", err)
		}
		conn, err := grpc.NewClient(cfg.Endpoint, creds, grpcclient.KeepaliveDialOption(false))
		if err != nil {
			return nil, nil, fmt.Errorf("клиент к %s не собран: %w", cfg.Endpoint, err)
		}
		return &grpcModuleService{
			client:  iamv1.NewInternalModuleServiceClient(conn),
			timeout: cfg.Timeout,
		}, conn.Close, nil
	}
}

// grpcModuleService — порт поверх сгенерированного клиента.
//
// Срок ставится ЗДЕСЬ и на каждом глаголе одинаковый: «часть вызовов со сроком,
// часть без» — та же беда, что срока нет вовсе, только незаметная.
type grpcModuleService struct {
	client  iamv1.InternalModuleServiceClient
	timeout time.Duration
}

func (s *grpcModuleService) Plan(ctx context.Context, in *iamv1.PlanModuleRequest) (*iamv1.PlanModuleResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.client.Plan(ctx, in)
}

func (s *grpcModuleService) Apply(ctx context.Context, in *iamv1.ApplyModuleRequest) (*operationv1.Operation, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.client.Apply(ctx, in)
}

func (s *grpcModuleService) Get(ctx context.Context, in *iamv1.GetModuleRequest) (*iamv1.ModuleCatalog, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.client.Get(ctx, in)
}

func (s *grpcModuleService) List(ctx context.Context, in *iamv1.ListModulesRequest) (*iamv1.ListModulesResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.client.List(ctx, in)
}

var _ ModuleService = (*grpcModuleService)(nil)
