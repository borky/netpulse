// backup.go — backups automáticos de la BD (#741): config persistida en kv,
// run manual (POST /api/backup/run), descarga completa (#218) y, desde el fix
// del scheduler, un bucle periódico que ejecuta el backup cuando vence el
// intervalo (o a la hora fija configurada). El vencimiento se deriva SIEMPRE
// del last_run persistido, así los reinicios y el auto-updater no resetean
// el reloj (el bug original: la config existía pero nada la ejecutaba).
package httpapi

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gnacho/netpulse/server-go/internal/auth"
	"github.com/gnacho/netpulse/server-go/internal/backupcrypt"
	"github.com/gnacho/netpulse/server-go/internal/db"
	"github.com/gnacho/netpulse/server-go/internal/kvseal"
)

const (
	kvBackupEnabled       = "backup.enabled"
	kvBackupFrequencyH    = "backup.frequency_h"
	kvBackupRetentionDays = "backup.retention_days"
	kvBackupLastRun       = "backup.last_run"
	kvBackupTime          = "backup.time"
	// kvBackupPassphrase (fork): the backup passphrase, sealed with kvseal.
	// Set, every backup is encrypted (backupcrypt); absent, backups are
	// plain archives as upstream writes them.
	kvBackupPassphrase = "backup.passphrase"

	// backupTickEvery: cadencia del bucle. Corta a propósito: un cambio de
	// ajustes aplica en menos de un minuto sin canales ni reinicios (mismo
	// patrón que el scheduler de speedtest #511).
	backupTickEvery = 1 * time.Minute
)

// BackupConfig es la configuración de backups automáticos (kv backup.*).
// Time es opcional ("HH:MM", hora local): con valor, el backup es diario a
// esa hora (ventana de mantenimiento); vacío, cada FrequencyH horas.
type BackupConfig struct {
	Enabled       bool   `json:"enabled"`
	FrequencyH    int    `json:"frequency_h"`
	RetentionDays int    `json:"retention_days"`
	LastRun       string `json:"last_run"`
	Time          string `json:"time"`
}

func kvGetInt(db *sql.DB, key string, defaultVal int) int {
	v := kvGet(db, key)
	if v == "" {
		return defaultVal
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return defaultVal
	}
	return n
}

func getBackupConfig(d *db.DB) BackupConfig {
	return BackupConfig{
		Enabled:       kvGetBool(d.DB, kvBackupEnabled),
		FrequencyH:    kvGetInt(d.DB, kvBackupFrequencyH, 24),
		RetentionDays: kvGetInt(d.DB, kvBackupRetentionDays, 3),
		LastRun:       kvGet(d.DB, kvBackupLastRun),
		Time:          kvGet(d.DB, kvBackupTime),
	}
}

// BackupDue decide si toca backup. Con Time vacío: intervalo FrequencyH desde
// lastRun (lastRun zero = ya). Con Time "HH:MM": diario a esa hora local;
// toca si ya pasó la hora de hoy y el último backup es anterior a la de hoy.
func BackupDue(cfg BackupConfig, lastRun time.Time, now time.Time) bool {
	if !cfg.Enabled {
		return false
	}
	if t, err := time.Parse("15:04", cfg.Time); err == nil && cfg.Time != "" {
		today := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location())
		return !now.Before(today) && lastRun.Before(today)
	}
	if lastRun.IsZero() {
		return true
	}
	return now.Sub(lastRun) >= time.Duration(cfg.FrequencyH)*time.Hour
}

// errBackupPassphraseUnreadable: a passphrase is stored but this server
// cannot open it. Backups then fail rather than fall back to plaintext.
var errBackupPassphraseUnreadable = errors.New("the backup passphrase is stored but cannot be decrypted (secrets.key lost or replaced): set it again")

// backupPassphrase returns the passphrase backups are encrypted with, "" for
// none. A stored passphrase that cannot be opened is an error, never "".
func (s *server) backupPassphrase() (string, error) {
	stored := kvGet(s.db.DB, kvBackupPassphrase)
	if stored == "" {
		return "", nil
	}
	if s.secrets == nil {
		return "", errBackupPassphraseUnreadable
	}
	pass, err := s.secrets.Unseal(kvBackupPassphrase, stored)
	if err != nil || pass == "" {
		return "", errBackupPassphraseUnreadable
	}
	return pass, nil
}

// backupView is the settings answer: the schedule plus whether backups are
// encrypted. The passphrase itself never leaves the server.
type backupView struct {
	BackupConfig
	Encrypted            bool `json:"encrypted"`
	PassphraseUnreadable bool `json:"passphrase_unreadable,omitempty"`
	SecretsUnavailable   bool `json:"secrets_unavailable,omitempty"`
}

func (s *server) backupView() backupView {
	v := backupView{BackupConfig: getBackupConfig(s.db), SecretsUnavailable: s.secrets == nil}
	if kvGet(s.db.DB, kvBackupPassphrase) != "" {
		if _, err := s.backupPassphrase(); err != nil {
			v.PassphraseUnreadable = true
		} else {
			v.Encrypted = true
		}
	}
	return v
}

// backupArchiveName is the archive's file name for ts, encrypted or not.
func backupArchiveName(ts string, encrypted bool) string {
	name := "netpulse-" + ts + ".tar.gz"
	if encrypted {
		name += backupcrypt.Ext
	}
	return name
}

// backupLastRun lee el último run persistido (RFC3339 UTC; zero si nunca).
func (s *server) backupLastRun() time.Time {
	v := kvGet(s.db.DB, kvBackupLastRun)
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// runBackup copia la BD, marca last_run y aplica la retención. Single-flight
// con mutex: el run manual y el programado nunca se pisan.
func (s *server) runBackup() (string, error) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()

	cfg := getBackupConfig(s.db)
	pass, err := s.backupPassphrase()
	if err != nil {
		return "", err
	}
	backupDir := filepath.Join(s.cfg.DataDir, "backups")
	if err := ensureBackupDir(backupDir); err != nil {
		return "", err
	}

	ts := time.Now().UTC().Format("20060102-150405")
	// #1864: un backup es más que la BD. Una instalación nueva restaurada solo
	// con el .db tiene datos y ajustes pero no puede entrar por SSH en los
	// routers (la clave vive en .ssh) ni sirve TLS sin volver a generarlo, así
	// que el archivo lleva el conjunto: netpulse.db, .ssh y tls. Va en tar.gz
	// para que sea un único fichero, con la purga tratándolo como uno solo.
	dst := filepath.Join(backupDir, backupArchiveName(ts, pass != ""))
	if err := writeBackupArchive(s.db.DB, s.cfg.DataDir, s.db.Path, dst, pass); err != nil {
		return "", err
	}

	upsert := "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
	if _, err := s.db.Exec(upsert, kvBackupLastRun, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return dst, err
	}

	if cfg.RetentionDays > 0 {
		purgeOldBackups(backupDir, cfg.RetentionDays)
	}
	return dst, nil
}

// backupLoop es el bucle periódico de backups automáticos (#741).
func (s *server) backupLoop(ctx context.Context, tickEvery time.Duration) {
	s.backupMu.Lock()
	cleanBackupLeftovers(filepath.Join(filepath.Dir(s.db.Path), "backups"))
	s.backupMu.Unlock()
	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.backupTick()
		}
	}
}

func (s *server) backupTick() {
	cfg := getBackupConfig(s.db)
	if !BackupDue(cfg, s.backupLastRun(), time.Now()) {
		return
	}
	dst, err := s.runBackup()
	if err != nil {
		log.Printf("[netpulse] automatic backup failed: %v", err)
		return
	}
	log.Printf("[netpulse] automatic backup completed: %s", dst)
}

func validBackupTime(v string) bool {
	if v == "" {
		return true
	}
	_, err := time.Parse("15:04", v)
	return err == nil
}

func (s *server) registerBackupRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/settings/backup", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.backupView())
	})))

	mux.Handle("PUT /api/settings/backup", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Enabled       *bool   `json:"enabled"`
			FrequencyH    *int    `json:"frequency_h"`
			RetentionDays *int    `json:"retention_days"`
			Time          *string `json:"time"`
			// Passphrase (fork): set or replace the backup passphrase; ""
			// removes it, after which backups are written unencrypted.
			Passphrase *string `json:"passphrase"`
		}
		if st := readJSONBody(w, r, &body); st != 0 {
			writeBodyError(w, st, "invalid_body", "")
			return
		}

		if body.Enabled != nil {
			if err := kvSetBool(s.db.DB, kvBackupEnabled, *body.Enabled); err != nil {
				writeError(w, http.StatusInternalServerError, "kv_error")
				return
			}
		}
		if body.FrequencyH != nil {
			if *body.FrequencyH < 1 || *body.FrequencyH > 72 {
				writeError(w, http.StatusBadRequest, "invalid_frequency")
				return
			}
			upsert := "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
			if _, err := s.db.Exec(upsert, kvBackupFrequencyH, fmt.Sprintf("%d", *body.FrequencyH)); err != nil {
				writeError(w, http.StatusInternalServerError, "kv_error")
				return
			}
		}
		if body.RetentionDays != nil {
			if *body.RetentionDays < 1 || *body.RetentionDays > 30 {
				writeError(w, http.StatusBadRequest, "invalid_retention")
				return
			}
			upsert := "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
			if _, err := s.db.Exec(upsert, kvBackupRetentionDays, fmt.Sprintf("%d", *body.RetentionDays)); err != nil {
				writeError(w, http.StatusInternalServerError, "kv_error")
				return
			}
		}
		if body.Time != nil && !validBackupTime(*body.Time) {
			writeError(w, http.StatusBadRequest, "invalid_time")
			return
		}
		if body.Time != nil {
			if *body.Time == "" {
				if _, err := s.db.Exec("DELETE FROM kv WHERE key = ?", kvBackupTime); err != nil {
					writeError(w, http.StatusInternalServerError, "kv_error")
					return
				}
			} else {
				upsert := "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
				if _, err := s.db.Exec(upsert, kvBackupTime, *body.Time); err != nil {
					writeError(w, http.StatusInternalServerError, "kv_error")
					return
				}
			}
		}

		if body.Passphrase != nil {
			if *body.Passphrase == "" {
				if _, err := s.db.Exec("DELETE FROM kv WHERE key = ?", kvBackupPassphrase); err != nil {
					writeError(w, http.StatusInternalServerError, "kv_error")
					return
				}
			} else {
				if len(*body.Passphrase) < backupcrypt.MinPassphraseLen {
					writeError(w, http.StatusBadRequest, "passphrase_too_short",
						fmt.Sprintf("the backup passphrase needs at least %d characters", backupcrypt.MinPassphraseLen))
					return
				}
				if s.secrets == nil {
					writeError(w, http.StatusServiceUnavailable, "secrets_unavailable", "secret storage is not available on this server")
					return
				}
				sealed, err := s.secrets.Seal(kvBackupPassphrase, *body.Passphrase)
				if err != nil {
					writeError(w, http.StatusInternalServerError, "seal_error")
					return
				}
				upsert := "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
				if _, err := s.db.Exec(upsert, kvBackupPassphrase, sealed); err != nil {
					writeError(w, http.StatusInternalServerError, "kv_error")
					return
				}
			}
		}

		writeJSON(w, http.StatusOK, s.backupView())
	})))

	mux.Handle("POST /api/backup/run", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dst, err := s.runBackup()
		if errors.Is(err, errBackupPassphraseUnreadable) {
			writeError(w, http.StatusConflict, "passphrase_unreadable", err.Error())
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "backup_error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":   true,
			"file": dst,
			"size": fileSizeHuman(dst),
		})
	})))

	// GET /api/backup/download (admin) — the same complete archive as the
	// scheduled backup (database, .ssh, tls and secrets.key), encrypted with
	// the backup passphrase when one is set. It contains every kv secret
	// (session_secret, adguard_pass, agent and pairing tokens...) and, in
	// the clear, the SSH and TLS private keys: nothing is redacted, since a
	// redaction would break a restore. Bounded as #218 set it: RequireAdmin,
	// the X-Netpulse-Backup-Contains-Credentials header, and an audit line.
	//
	// FORK: upstream served a copy of the live database file alone. With
	// every install on WAL (#1700) that copy can miss what is still in the
	// WAL, and it left out the keys the scheduled archive carries (#1864).
	mux.Handle("GET /api/backup/download", auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pass, err := s.backupPassphrase()
		if err != nil {
			writeError(w, http.StatusConflict, "passphrase_unreadable", err.Error())
			return
		}
		backupDir := filepath.Join(s.cfg.DataDir, "backups")
		if err := ensureBackupDir(backupDir); err != nil {
			writeError(w, http.StatusInternalServerError, "backup_error")
			return
		}
		name := backupArchiveName(time.Now().UTC().Format("20060102-150405"), pass != "")
		// Each export builds in a directory of its own, so concurrent
		// exports never share a file, and the purge never sees it.
		exportDir, err := os.MkdirTemp(backupDir, exportDirPrefix+"*")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "backup_error")
			return
		}
		defer os.RemoveAll(exportDir)
		tmpFile := filepath.Join(exportDir, name)
		if err := writeBackupArchive(s.db.DB, s.cfg.DataDir, s.db.Path, tmpFile, pass); err != nil {
			writeError(w, http.StatusInternalServerError, "backup_error")
			return
		}

		if u := auth.UserFromContext(r.Context()); u != nil {
			log.Printf("[netpulse] backup: full archive download (encrypted=%t) by admin %s", pass != "", u.Username)
		}
		contains := "true"
		if pass != "" {
			contains = "encrypted"
		}
		w.Header().Set("X-Netpulse-Backup-Contains-Credentials", contains)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
		http.ServeFile(w, r, tmpFile)
	})))
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, backupFileMode)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	if err := dstFile.Chmod(backupFileMode); err != nil {
		return err
	}

	_, err = dstFile.ReadFrom(srcFile)
	return err
}

// writeBackupArchive escribe el backup completo (#1864) en un único tar.gz:
// la BD más .ssh y tls, que son lo que hace falta para que una restauración en
// otro host pueda entrar por SSH en los routers y servir TLS sin regenerar
// nada. Un directorio que no exista (instalación sin clave todavía) se omite
// sin fallar: el backup sigue siendo válido.
//
// With pass set, the gzip stream goes through backupcrypt, so the file on
// disk is encrypted from its first byte (fork).
func writeBackupArchive(d *sql.DB, dataDir, dbPath, dst, pass string) error {
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, backupFileMode)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Chmod(backupFileMode); err != nil {
		return fail(err)
	}

	// #1866: la copia se hace con VACUUM INTO, no copiando el fichero vivo.
	// Leer el fichero mientras SQLite escribe daba una cabecera con un tamaño
	// que ya no cuadraba (archive/tar: write too long) y, aunque cuadrara, el
	// .db solo puede venir sin transacciones que aún viven en el WAL. El
	// snapshot tiene tamaño fijo y es una base válida por sí sola.
	//
	// FORK: the snapshot is the whole database in the clear, so it goes in a
	// directory of its own (0700, unique per call) that is removed when done,
	// and cleanBackupLeftovers removes one a crash left behind. Next to dst
	// with a fixed name, two exports in the same second shared it, and a
	// crash left a plaintext copy beside encrypted backups.
	snapDir, err := os.MkdirTemp(filepath.Dir(dst), snapshotDirPrefix+"*")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(snapDir)
	snapshot := filepath.Join(snapDir, "netpulse.db")
	if _, err := d.Exec("VACUUM INTO ?", snapshot); err != nil {
		return fail(err)
	}

	var sink io.Writer = out
	var enc io.WriteCloser
	if pass != "" {
		if enc, err = backupcrypt.NewWriter(out, pass); err != nil {
			return fail(err)
		}
		sink = enc
	}
	zw := gzip.NewWriter(sink)
	tw := tar.NewWriter(zw)

	if err := addTarFile(tw, snapshot, filepath.Base(dbPath)); err != nil {
		return fail(err)
	}
	for _, name := range []string{".ssh", "tls"} {
		p := filepath.Join(dataDir, name)
		if _, statErr := os.Stat(p); statErr != nil {
			continue
		}
		if err := addTarTree(tw, p, name); err != nil {
			return fail(err)
		}
	}
	// FORK: the key kvseal seals credentials with (Matrix, the backup
	// passphrase). Restored without it, the database keeps those values but
	// nothing can open them.
	if p := filepath.Join(dataDir, kvseal.KeyFile); fileExists(p) {
		if err := addTarFile(tw, p, kvseal.KeyFile); err != nil {
			return fail(err)
		}
	}

	if err := tw.Close(); err != nil {
		return fail(err)
	}
	if err := zw.Close(); err != nil {
		return fail(err)
	}
	if enc != nil {
		if err := enc.Close(); err != nil {
			return fail(err)
		}
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

// addTarFile mete un fichero suelto en el archivo con su modo (la clave SSH va
// en 0600 y tiene que seguir así al restaurar).
func addTarFile(tw *tar.Writer, src, name string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	// #1866: el tamaño sale del descriptor abierto y la copia se corta en él.
	// Con os.Stat antes de abrir, un fichero que crece entre las dos llamadas
	// desborda la cabecera y archive/tar aborta con "write too long".
	info, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.CopyN(tw, f, hdr.Size)
	return err
}

// addTarTree mete un directorio entero (permisos incluidos) con rutas
// relativas a root.
func addTarTree(tw *tar.Writer, src, root string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(src, p)
		if relErr != nil {
			return relErr
		}
		name := root
		if rel != "." {
			name = filepath.ToSlash(filepath.Join(root, rel))
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		hdr, hdrErr := tar.FileInfoHeader(info, "")
		if hdrErr != nil {
			return hdrErr
		}
		hdr.Name = name
		if d.IsDir() {
			hdr.Name = name + "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, openErr := os.Open(p)
		if openErr != nil {
			return openErr
		}
		defer f.Close()
		_, copyErr := io.Copy(tw, f)
		return copyErr
	})
}

// isBackupFile decide qué ficheros de backups/ son backups. Reconoce el
// archivo completo de hoy (.tar.gz) y los formatos anteriores (#818, #741)
// para que la retención siga limpiando lo que dejaron versiones viejas.
func isBackupFile(name string) bool {
	return strings.HasSuffix(name, ".tar.gz") ||
		strings.HasSuffix(name, ".tar.gz"+backupcrypt.Ext) ||
		strings.HasSuffix(name, ".db.gz") ||
		strings.HasSuffix(name, ".db")
}

func purgeOldBackups(dir string, retentionDays int) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// #818: reconoce backups comprimidos (.db.gz) y los antiguos sin
		// comprimir (.db); #1864 añade el archivo completo (.tar.gz).
		// Cualquier otro fichero se ignora.
		if !isBackupFile(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

func fileSizeHuman(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "?"
	}
	size := info.Size()
	switch {
	case size >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(size)/(1<<30))
	case size >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(size)/(1<<20))
	case size >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(size)/(1<<10))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Prefixes of the private directories a backup and an export build in.
const (
	snapshotDirPrefix = ".snapshot-"
	exportDirPrefix   = ".export-"
)

// cleanBackupLeftovers removes what an interrupted backup or export left in
// the backups directory: the private build directories (a plaintext
// database snapshot among them) and half-written archives (*.tmp). Run at
// start, before any backup can be in progress.
func cleanBackupLeftovers(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		switch {
		case e.IsDir() && (strings.HasPrefix(n, snapshotDirPrefix) || strings.HasPrefix(n, exportDirPrefix)):
			_ = os.RemoveAll(filepath.Join(dir, n))
		case !e.IsDir() && (strings.HasSuffix(n, ".tmp") || strings.HasSuffix(n, ".tmp.db")):
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
}
