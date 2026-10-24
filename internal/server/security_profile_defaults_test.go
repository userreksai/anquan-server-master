package server

import (
	"net/http/httptest"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestSecurityProfileDefaultsCoverStandardCronPaths(t *testing.T) {
	response := httptest.NewRecorder()
	(&Server{}).securityProfileDefaults(response, httptest.NewRequest("GET", "/api/settings/security-profile/defaults", nil))
	requireStatus(t, response, 200)
	got := jsonResult[struct {
		Security struct {
			Auditd struct {
				Paths []string `json:"watch_paths"`
			} `json:"auditd"`
			FIM struct {
				Paths                 []string `json:"paths"`
				ReportChanges         bool     `json:"report_changes"`
				CaptureCreatedContent bool     `json:"capture_created_content"`
			} `json:"native_fim"`
			Policies struct {
				Mode string `json:"mode"`
			} `json:"policies"`
		} `json:"security"`
	}](t, response)
	want := []string{
		"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d",
		"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
		"/etc/cron.allow", "/etc/cron.deny", "/var/spool/cron", "/etc/anacrontab", "/etc/cron.yearly",
	}
	if !slices.Equal(got.Security.Auditd.Paths, want) || !slices.Equal(got.Security.FIM.Paths, want) {
		t.Fatalf("default auditd/FIM scopes differ from the standard cron and existing security paths: %+v", got.Security)
	}
	if got.Security.Policies.Mode != "audit" || got.Security.FIM.ReportChanges || !got.Security.FIM.CaptureCreatedContent {
		t.Fatalf("expanding cron scope changed enforcement or content-retention defaults: %+v", got.Security)
	}
	paths := defaultSecurityWatchPaths()
	paths[0] = "/mutated"
	if !slices.Equal(defaultSecurityWatchPaths(), want) {
		t.Fatal("a returned defaults slice changed future profiles")
	}
}

func TestComposeSecurityProfilePreservesExistingCronScope(t *testing.T) {
	input := "# existing deployment\nserver: []\nsecurity:\n  enabled: true\n  auditd:\n    enabled: true\n    watch_paths: [/etc/cron.d, /srv/custom-audit]\n  native_fim:\n    enabled: true\n    paths: [/srv/custom-fim]\n    report_changes: true\n  policies:\n    mode: audit\n"
	readOnly, _, err := composeProfile(input, nil)
	if err != nil || readOnly != input {
		t.Fatalf("reading an existing profile changed its text: %v", err)
	}
	output, _, err := composeProfile(input, map[string]any{"auditd": map[string]any{"audit_exec": true}})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Security struct {
			Auditd struct {
				Paths []string `yaml:"watch_paths"`
			} `yaml:"auditd"`
			FIM struct {
				Paths         []string `yaml:"paths"`
				ReportChanges bool     `yaml:"report_changes"`
			} `yaml:"native_fim"`
			Policies struct {
				Mode string `yaml:"mode"`
			} `yaml:"policies"`
		} `yaml:"security"`
	}
	if err := yaml.Unmarshal([]byte(output), &got); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Security.Auditd.Paths, []string{"/etc/cron.d", "/srv/custom-audit"}) || !slices.Equal(got.Security.FIM.Paths, []string{"/srv/custom-fim"}) || !got.Security.FIM.ReportChanges || got.Security.Policies.Mode != "audit" {
		t.Fatalf("unrelated edit overwrote an existing scope or selected a different policy/content mode: %s", output)
	}
}
