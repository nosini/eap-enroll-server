// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command eap-enroll is the EAP-TLS enrollment server and its admin
// commands.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/nosini/eap-enroll-server/internal/config"
	"github.com/nosini/eap-enroll-server/internal/enroll"
	"github.com/nosini/eap-enroll-server/internal/openbao"
	"github.com/nosini/eap-enroll-server/internal/store"
)

const usage = `usage:
  eap-enroll serve -config FILE
  eap-enroll code -config FILE -user USERNAME -label LABEL
  eap-enroll devices -config FILE
  eap-enroll disable -config FILE DEVICE_ID
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "code":
		err = code(os.Args[2:])
	case "devices":
		err = devices(os.Args[2:])
	case "disable":
		err = disable(os.Args[2:])
	case "-h", "-help", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "eap-enroll:", err)
		os.Exit(1)
	}
}

type app struct {
	cfg   *config.Config
	store *store.Store
	bao   *openbao.Client
	svc   *enroll.Service
}

// close revokes the OpenBao token, so it isn't left valid until its TTL
// ends, and closes the database.
func (a *app) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.bao.Close(ctx); err != nil {
		slog.Error("token_revoke_failed", "error", err.Error())
	}
	a.store.Close()
}

// open parses the flags common to all commands plus extra ones, then
// opens the configuration, database and service.
func open(name string, args []string, minArgs, maxArgs int, extra func(*flag.FlagSet)) (*app, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", "", "configuration file")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if *path == "" || fs.NArg() < minArgs || fs.NArg() > maxArgs {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		return nil, nil, err
	}
	bao, err := openbao.New(cfg.OpenBao)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	// The audit log goes to stderr (the journal) for every command.
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	svc, err := enroll.New(cfg, st, bao, log)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return &app{cfg: cfg, store: st, bao: bao, svc: svc}, fs.Args(), nil
}

func serve(args []string) error {
	a, _, err := open("serve", args, 0, 0, nil)
	if err != nil {
		return err
	}
	defer a.close()
	srv, err := a.svc.Server()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	a.svc.CleanupCodes(ctx)
	go a.svc.RunAttestationStatus(ctx)
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.svc.CleanupCodes(ctx)
			}
		}
	}()

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	slog.Info("listening", "address", a.cfg.Listen)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdown); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func code(args []string) error {
	var user, label string
	a, _, err := open("code", args, 0, 0, func(fs *flag.FlagSet) {
		fs.StringVar(&user, "user", "", "enabled username")
		fs.StringVar(&label, "label", "", "device label, e.g. \"Pixel\"")
	})
	if err != nil {
		return err
	}
	defer a.close()
	if user == "" || label == "" {
		return errors.New("-user and -label are required")
	}
	uri, expires, err := a.svc.CreateCode(context.Background(), user, label)
	if err != nil {
		return err
	}
	fmt.Println(uri)
	fmt.Fprintf(os.Stderr, "Valid until %s; single use.\n", expires.Local().Format(time.DateTime))
	return nil
}

func devices(args []string) error {
	a, _, err := open("devices", args, 0, 0, nil)
	if err != nil {
		return err
	}
	defer a.close()
	list, err := a.store.Devices(context.Background())
	if err != nil {
		return err
	}
	return printDevices(os.Stdout, list)
}

func printDevices(out io.Writer, list []store.DeviceSummary) error {
	day := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.Local().Format(time.DateOnly)
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tUSER\tLABEL\tCREATED\tSTATUS\tWIFI CERT UNTIL\tDEVICE CERT UNTIL")
	for _, d := range list {
		status := "enabled"
		if d.Disabled != nil {
			status = "disabled " + day(d.Disabled)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Username, d.Label,
			day(&d.Created), status, day(d.WifiNotAfter), day(d.DeviceNotAfter))
	}
	return w.Flush()
}

func disable(args []string) error {
	a, rest, err := open("disable", args, 1, 1, nil)
	if err != nil {
		return err
	}
	defer a.close()
	remaining, err := a.svc.DisableDevice(context.Background(), rest[0])
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no device %s", rest[0])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Device %s is disabled, but %d certificate(s) are not revoked yet: %v\n",
			rest[0], len(remaining), remaining)
		fmt.Fprintln(os.Stderr, "Run the same command again to retry.")
		return err
	}
	fmt.Fprintf(os.Stderr, "Device %s is disabled and its certificates are revoked.\n", rest[0])
	return nil
}
