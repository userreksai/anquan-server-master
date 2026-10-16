package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"time"
)

const maxSudoFileBytes = 64 << 20

var sudoSessionKey = regexp.MustCompile(`^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$`)
var sudoGeneration = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
var sudoFileNames = map[string]bool{"log": true, "log.json": true, "timing": true, "stdin": true, "stdout": true, "stderr": true, "ttyin": true, "ttyout": true}

type sudoIOChunk struct {
	SessionID  string `json:"session_id"`
	Generation string `json:"generation"`
	File       string `json:"file"`
	Offset     int64  `json:"offset"`
	Content    string `json:"content_base64"`
	TotalSize  int64  `json:"total_size"`
	Complete   bool   `json:"complete"`
	data       []byte
}

func parseSudoIOChunk(data json.RawMessage) (*sudoIOChunk, error) {
	var event struct {
		Source  string          `json:"source"`
		Kind    string          `json:"kind"`
		Details json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, err
	}
	if event.Source != "sudo" || event.Kind != "io_chunk" {
		return nil, nil
	}
	var chunk sudoIOChunk
	if err := json.Unmarshal(event.Details, &chunk); err != nil {
		return nil, fmt.Errorf("invalid sudo I/O chunk")
	}
	if len(chunk.SessionID) == 0 || len(chunk.SessionID) > 128 || !sudoSessionKey.MatchString(chunk.SessionID) || len(chunk.Generation) == 0 || len(chunk.Generation) > 128 || !sudoGeneration.MatchString(chunk.Generation) || !sudoFileNames[chunk.File] || chunk.Offset < 0 || chunk.Offset > chunk.TotalSize || chunk.TotalSize < 0 || chunk.TotalSize > maxSudoFileBytes || len(chunk.Content) > base64.StdEncoding.EncodedLen(24<<10) {
		return nil, fmt.Errorf("invalid sudo I/O chunk metadata")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(chunk.Content)
	if err != nil || len(decoded) > 24<<10 || chunk.Offset+int64(len(decoded)) > chunk.TotalSize || (len(decoded) == 0 && (chunk.TotalSize != 0 || chunk.Offset != 0 || !chunk.Complete)) {
		return nil, fmt.Errorf("invalid sudo I/O chunk content")
	}
	chunk.data = decoded
	return &chunk, nil
}

func storeSudoIOChunk(ctx context.Context, tx *sql.Tx, e Envelope, machineIP string, now int64, chunk *sudoIOChunk) (bool, error) {
	if _, err := tx.ExecContext(ctx, `INSERT INTO sudo_sessions(machine_ip,host,session_key,generation,time,received_at) VALUES(?,?,?,?,?,?)
ON CONFLICT(machine_ip,session_key,generation) DO UPDATE SET received_at=MAX(sudo_sessions.received_at,excluded.received_at)`, machineIP, e.Host, chunk.SessionID, chunk.Generation, stamp(e.Time), now); err != nil {
		return false, err
	}
	var sessionID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM sudo_sessions WHERE machine_ip=? AND session_key=? AND generation=?`, machineIP, chunk.SessionID, chunk.Generation).Scan(&sessionID); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sudo_session_files(session_id,name,total_size,complete_requested) VALUES(?,?,?,?)
ON CONFLICT(session_id,name) DO UPDATE SET total_size=MAX(sudo_session_files.total_size,excluded.total_size),
complete_requested=CASE WHEN excluded.total_size>sudo_session_files.total_size THEN excluded.complete_requested ELSE MAX(sudo_session_files.complete_requested,excluded.complete_requested) END`, sessionID, chunk.File, chunk.TotalSize, chunk.Complete); err != nil {
		return false, err
	}
	// Exact duplicate offsets are safe regardless of envelope identity; changed
	// bytes require a new generation so truncated/reused sessions cannot mix.
	var existing []byte
	var previousFile string
	var previousSession, previousOffset int64
	err := tx.QueryRowContext(ctx, `SELECT session_id,name,offset,data FROM sudo_io_chunks WHERE machine_ip=? AND event_id=?`, machineIP, e.EventID).Scan(&previousSession, &previousFile, &previousOffset, &existing)
	if err == nil {
		if previousSession != sessionID || previousFile != chunk.File || previousOffset != chunk.Offset || !bytes.Equal(existing, chunk.data) {
			return false, fmt.Errorf("sudo chunk event identity conflict")
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	err = tx.QueryRowContext(ctx, `SELECT data FROM sudo_io_chunks WHERE session_id=? AND name=? AND offset=?`, sessionID, chunk.File, chunk.Offset).Scan(&existing)
	if err == nil {
		if !bytes.Equal(existing, chunk.data) {
			return false, fmt.Errorf("sudo chunk offset conflict; new generation required")
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var overlapping int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sudo_io_chunks WHERE session_id=? AND name=? AND offset<? AND offset+length(data)>?`, sessionID, chunk.File, chunk.Offset+int64(len(chunk.data)), chunk.Offset).Scan(&overlapping); err != nil {
		return false, err
	}
	if overlapping != 0 {
		return false, fmt.Errorf("overlapping sudo I/O chunks")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sudo_io_chunks(session_id,name,offset,data,machine_ip,event_id) VALUES(?,?,?,?,?,?)`, sessionID, chunk.File, chunk.Offset, chunk.data, machineIP, e.EventID); err != nil {
		return false, err
	}
	return true, nil
}

type SudoSessionFile struct {
	Name          string `json:"name"`
	Size          int64  `json:"size"`
	ReceivedBytes int64  `json:"received_bytes"`
	Complete      bool   `json:"complete"`
}
type SudoSession struct {
	ID         int64             `json:"id"`
	MachineIP  string            `json:"machine_ip"`
	Host       string            `json:"host"`
	SessionID  string            `json:"session_id"`
	Generation string            `json:"generation"`
	Time       time.Time         `json:"time"`
	ReceivedAt time.Time         `json:"received_at"`
	Files      []SudoSessionFile `json:"files"`
}

func (s *Store) SudoSessions(ctx context.Context, f Filter) (Page[SudoSession], error) {
	page := Page[SudoSession]{Items: []SudoSession{}, Page: f.Page, PageSize: f.Size}
	where := ""
	args := []any{}
	if f.MachineIP != "" {
		where = " WHERE machine_ip=?"
		args = append(args, f.MachineIP)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM sudo_sessions`+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	args = append(args, f.Size, (f.Page-1)*f.Size)
	rows, err := s.DB.QueryContext(ctx, `SELECT id,machine_ip,host,session_key,generation,time,received_at FROM sudo_sessions`+where+` ORDER BY time DESC,id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		var item SudoSession
		var at, received int64
		if err = rows.Scan(&item.ID, &item.MachineIP, &item.Host, &item.SessionID, &item.Generation, &at, &received); err != nil {
			rows.Close()
			return page, err
		}
		item.Time, item.ReceivedAt, item.Files = unstamp(at), unstamp(received), []SudoSessionFile{}
		page.Items = append(page.Items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	// Close the parent rows before querying files: the store deliberately uses
	// one SQLite connection to serialize transactions.
	for i := range page.Items {
		files, err := s.DB.QueryContext(ctx, `SELECT f.name,f.total_size,COALESCE(SUM(length(c.data)),0),f.complete_requested AND COALESCE(SUM(length(c.data)),0)=f.total_size FROM sudo_session_files f LEFT JOIN sudo_io_chunks c ON c.session_id=f.session_id AND c.name=f.name WHERE f.session_id=? GROUP BY f.name,f.total_size,f.complete_requested ORDER BY f.name`, page.Items[i].ID)
		if err != nil {
			return page, err
		}
		for files.Next() {
			var file SudoSessionFile
			if err = files.Scan(&file.Name, &file.Size, &file.ReceivedBytes, &file.Complete); err != nil {
				files.Close()
				return page, err
			}
			page.Items[i].Files = append(page.Items[i].Files, file)
		}
		err = files.Err()
		files.Close()
		if err != nil {
			return page, err
		}
	}
	return page, nil
}

func (s *Server) sudoSessions(w http.ResponseWriter, r *http.Request) {
	f, err := ParseFilter(r.URL.Query())
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	page, err := s.Store.SudoSessions(r.Context(), f)
	s.respond(w, page, err)
}

func (s *Server) sudoSessionFile(w http.ResponseWriter, r *http.Request) {
	id, ok := idFrom(w, r)
	if !ok {
		return
	}
	name := r.PathValue("file")
	if !sudoFileNames[name] {
		fail(w, 400, "sudo 会话文件名无效")
		return
	}
	var size int64
	var complete bool
	err := s.Store.DB.QueryRowContext(r.Context(), `SELECT total_size,complete_requested FROM sudo_session_files WHERE session_id=? AND name=?`, id, name).Scan(&size, &complete)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	if !complete {
		fail(w, 409, "会话文件仍在上传")
		return
	}
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT offset,data FROM sudo_io_chunks WHERE session_id=? AND name=? ORDER BY offset`, id, name)
	if err != nil {
		s.respond(w, nil, err)
		return
	}
	var data bytes.Buffer
	for rows.Next() {
		var offset int64
		var chunk []byte
		if err = rows.Scan(&offset, &chunk); err != nil {
			break
		}
		if offset != int64(data.Len()) || int64(data.Len()+len(chunk)) > size {
			err = fmt.Errorf("incomplete sudo session file")
			break
		}
		_, _ = data.Write(chunk)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil || int64(data.Len()) != size {
		fail(w, 409, "会话文件尚未完整接收")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Content-Length", fmt.Sprint(data.Len()))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data.Bytes())
}
