package server

import (
	"fmt"
	"testing"
	"time"
)

func TestCommandNotesOnlyUpdatePreservesCurrentStatus(t *testing.T) {
	store, _ := testStore(t)
	s := testServer(store)
	cookie := testLogin(t, s, DefaultPassword)
	for _, status := range []string{"open", "resolved"} {
		t.Run(status, func(t *testing.T) {
			eventID := "command-notes-" + status
			at := time.Now().UTC()
			requireIngest(t, store, testPacket(t, eventID, "command_history", "10.0.0.1", at, commandData(eventID, at)), "127.0.0.1", true)
			var id int64
			if err := store.DB.QueryRow(`SELECT id FROM events WHERE event_id=?`, eventID).Scan(&id); err != nil {
				t.Fatal(err)
			}
			path := fmt.Sprintf("/api/events/%d", id)
			if status == "resolved" {
				// Simulate another operator changing status before the note save.
				requireStatus(t, testRequest(t, s, "PATCH", path, map[string]string{"status": status}, cookie, nil), 200)
			}
			for _, notes := range []string{"operator annotation", ""} {
				w := testRequest(t, s, "PATCH", path, map[string]string{"notes": notes}, cookie, nil)
				requireStatus(t, w, 200)
				event := jsonResult[Event](t, w)
				if event.Status != status || event.Notes != notes {
					t.Fatalf("notes-only update changed status or lost notes: %+v", event)
				}
			}
		})
	}
}
