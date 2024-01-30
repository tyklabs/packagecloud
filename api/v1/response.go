package packagecloud

import (
	"errors"
	"io"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func processResponse(resp *http.Response) ([]byte, error) {
	switch resp.StatusCode {
	case http.StatusCreated:
		b, err := io.ReadAll(resp.Body)
		return b, err
	case http.StatusUnauthorized:
		b, err := io.ReadAll(resp.Body)
		return b, errors.Join(err, status.Error(codes.Unauthenticated, string(b)))
	case http.StatusNotFound:
		b, err := io.ReadAll(resp.Body)
		return b, errors.Join(err, status.Error(codes.NotFound, string(b)))
	case http.StatusUnprocessableEntity:
		b, err := io.ReadAll(resp.Body)
		return b, errors.Join(err, status.Error(codes.AlreadyExists, string(b)))
	default:
		b, err := io.ReadAll(resp.Body)
		return b, errors.Join(err, status.Errorf(codes.Internal, "resp: %s, %q", resp.Status, b))
	}
}
