//go:build !windows

package main

import (
	"context"
	"errors"

	"github.com/detectqq/tamizdat"
)

func runTUN(context.Context, tunOptions, *tamizdat.Client) error {
	return errors.New("samizdat-tun-windows is only supported on Windows; cross-compile with GOOS=windows GOARCH=amd64")
}
