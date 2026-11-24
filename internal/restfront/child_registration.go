// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func configureChildRegistrationJSON(mux *runtime.ServeMux) {
	fallback, _ := runtime.MarshalerForRequest(mux, &http.Request{})
	runtime.WithMarshalerOption(runtime.MIMEWildcard, childRegistrationJSON{fallback})(mux)
	runtime.WithErrorHandler(childRegistrationJSONError)(mux)
}

type childRegistrationJSON struct{ runtime.Marshaler }

// Сгенерированный шлюз оборачивает ошибку decoder в InvalidArgument.
// По фиксированному признаку восстанавливаем единый отказ без деталей.
var errChildRegistrationForm = errors.New("child registration request form rejected")

func (m childRegistrationJSON) NewDecoder(body io.Reader) runtime.Decoder {
	fallback := m.Marshaler.NewDecoder(body)
	reader := json.NewDecoder(body)
	strict := runtime.DecoderWrapper{Decoder: reader}
	return runtime.DecoderFunc(func(dst any) error {
		if _, child := dst.(*iamv1.RegisterChildRequest); !child {
			return fallback.Decode(dst)
		}
		err := strict.Decode(dst)
		if errors.Is(err, io.EOF) {
			return err
		}
		if err != nil {
			return errChildRegistrationForm
		}
		// Допустимо одно JSON-значение. Хвост не должен скрывать второй ввод.
		var extra json.RawMessage
		if !errors.Is(reader.Decode(&extra), io.EOF) {
			return errChildRegistrationForm
		}
		return nil
	})
}

func childRegistrationJSONError(ctx context.Context, mux *runtime.ServeMux, m runtime.Marshaler,
	w http.ResponseWriter, r *http.Request, err error,
) {
	method, _ := runtime.RPCMethod(ctx)
	reply := status.Convert(err)
	if method == iamv1.ChildRegistrationService_Register_FullMethodName &&
		reply.Code() == codes.InvalidArgument && reply.Message() == errChildRegistrationForm.Error() {
		err = authzguard.PermissionDenied()
	}
	stepUpErrorHandler(ctx, mux, m, w, r, err)
}
