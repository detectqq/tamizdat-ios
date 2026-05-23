package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/detectqq/tamizdat"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(args []string, out io.Writer) error {
	cmd := "master"
	if len(args) > 0 && args[0] != "" {
		cmd = args[0]
	}
	switch cmd {
	case "master":
		return emitMaster(out)
	case "epoch":
		return emitEpoch(out, time.Now().UTC())
	default:
		return fmt.Errorf("unknown subcommand %q (want master or epoch)", cmd)
	}
}

func emitMaster(out io.Writer) error {
	id, err := tamizdat.GenerateShortID()
	if err != nil {
		return err
	}
	hexID := hex.EncodeToString(id[:])
	fmt.Fprintf(out, "master shortid: %s\n", hexID)
	fmt.Fprintf(out, "uri: tamizdat://%s@host:port?pbk=<server_pubkey_hex>&sni=<cover_sni>#label\n", hexID)
	fmt.Fprintf(out, "cmdline: --shortid %s\n", hexID)
	return nil
}

func emitEpoch(out io.Writer, now time.Time) error {
	var suffix [4]byte
	if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
		return err
	}
	epoch := fmt.Sprintf("ep-%s-rotated-%s", now.Format("2006-01-02"), hex.EncodeToString(suffix[:]))
	fmt.Fprintf(out, "epoch_key: %s\n", epoch)
	fmt.Fprintf(out, "sample_json: {\"version\":1,\"epoch_key\":\"%s\",\"shortid_pool_size\":100}\n", epoch)
	return nil
}
