//go:build example

// Package serve hosts the listener boilerplate every example main.go
// would otherwise duplicate. It exists so each example focuses on the
// op.Option surface it is meant to demonstrate, and so the timeout /
// shutdown policy is set in exactly one place.
//
// Production embedders MUST NOT use this package. Real deployments
// own their HTTP server lifecycle (TLS termination, reverse proxy
// integration, graceful shutdown, observability hooks); the helper
// here picks defaults that are safe for a localhost demo and
// documented through the operator log line, not a deployment surface.
// The package is gated behind the "example" build tag so it cannot
// be imported into production binaries by accident.
package serve

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Listen binds addr with a hardened *http.Server and serves h until
// SIGINT / SIGTERM. The timeout policy:
//
//   - ReadHeaderTimeout: 10 s — bounds Slowloris-style stalls on the
//     request line + headers without truncating legitimate large
//     bodies (PAR / DCR / token).
//   - IdleTimeout: 60 s — caps idle keep-alive sockets; matches the
//     Go default for embedders who do not override it.
//   - ReadTimeout / WriteTimeout: unset on purpose. Per-request
//     deadlines belong to the handler / client, not the listener;
//     setting them at this layer would cap legitimate slow consumers
//     of /jwks or /.well-known and produce noisy 408s in the demo.
//
// On signal, Listen calls Shutdown with a 5 s grace and returns the
// first non-nil error (Shutdown's or ListenAndServe's, whichever
// fired first).
func Listen(addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutErr := srv.Shutdown(ctx); shutErr != nil {
			return shutErr
		}
		return <-errCh
	case err := <-errCh:
		return err
	}
}

// Demo logs a uniform "<name> listening on <addr> (issuer <issuer>)"
// banner followed by any operator-facing curl probes the example
// documents. The banner gives every example a consistent first log
// line so an embedder skimming the output can spot the bound port
// and issuer without grepping for the example's literal string.
func Demo(name, addr, issuer string, probes ...string) {
	log.Printf("%s listening on %s (issuer %s)", name, addr, issuer)
	for _, p := range probes {
		log.Printf("try: %s", p)
	}
}
