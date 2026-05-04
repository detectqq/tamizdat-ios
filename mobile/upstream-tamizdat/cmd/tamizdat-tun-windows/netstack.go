//go:build windows

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/detectqq/tamizdat"
	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
)

func runTUN(ctx context.Context, opts tunOptions, client *tamizdat.Client) error {
	if opts.MTU <= 0 {
		return fmt.Errorf("MTU must be > 0, got %d", opts.MTU)
	}
	if err := requireWintunDLL(); err != nil {
		return err
	}

	dev, err := tun.Open(opts.Name, uint32(opts.MTU))
	if err != nil {
		return fmt.Errorf("open wintun device %q: %w", opts.Name, err)
	}
	// MED-6: defer device close immediately so any subsequent failure path
	// (ProcessAsync, CreateStack, PostTunUp) cleans up the wintun adapter.
	// We use a sentinel `released` flag flipped right before the normal
	// shutdown order so the defer becomes a no-op on the happy path.
	released := false
	defer func() {
		if !released {
			closeDevice(dev)
		}
	}()

	dialer := newSamizdatProxyDialer(client, opts.Debug)
	defer dialer.Stop()
	handler := tunnel.New(dialer, statistic.DefaultManager)
	handler.ProcessAsync()
	defer func() {
		if !released {
			handler.Close()
		}
	}()

	stackOpts := make([]option.Option, 0, 3)
	if opts.TCPModerateReceiveBuffer {
		stackOpts = append(stackOpts, option.WithTCPModerateReceiveBuffer(true))
	}
	if opts.TCPSendBufferSize > 0 {
		stackOpts = append(stackOpts, option.WithTCPSendBufferSize(opts.TCPSendBufferSize))
	}
	if opts.TCPReceiveBufferSize > 0 {
		stackOpts = append(stackOpts, option.WithTCPReceiveBufferSize(opts.TCPReceiveBufferSize))
	}

	stack, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: handler,
		Options:          stackOpts,
	})
	if err != nil {
		return fmt.Errorf("create netstack: %w", err)
	}
	defer func() {
		if !released {
			stack.Close()
			stack.Wait()
		}
	}()

	log.Printf("TUN up: name=%s type=%s mtu=%d", dev.Name(), dev.Type(), opts.MTU)
	if opts.PostTunUp != nil {
		if err := opts.PostTunUp(); err != nil {
			return fmt.Errorf("post-tun-up callback: %w", err)
		}
	} else {
		log.Printf("Routes were not modified. Run --route-help for manual Windows route commands.")
	}

	<-ctx.Done()
	// Happy-path shutdown: prevent the defers above from double-closing.
	released = true
	closeDevice(dev)
	stack.Close()
	stack.Wait()
	handler.Close()
	return nil
}

func closeDevice(dev any) {
	if c, ok := dev.(interface{ Close() }); ok {
		c.Close()
	}
}
