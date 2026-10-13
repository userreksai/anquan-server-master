package server

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// SetPublicOrigin configures the browser-facing origin before serving requests.
// An empty value preserves Host-based origin checks for existing deployments.
// The configured value comes from the administrator, never from proxy headers.
func (s *Server) SetPublicOrigin(value string) error {
	if value == "" {
		s.publicOrigin = nil
		return nil
	}
	u, err := url.Parse(value)
	if err != nil || !validOriginURL(u) || u.Path != "" || u.Host == "" || strings.ContainsAny(value, "?#") || strings.HasSuffix(u.Host, ":") || !validOriginAuthority(u) {
		return errors.New("public origin must be one HTTP(S) origin, without credentials, path, query, fragment, or wildcard")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("public origin port must be between 1 and 65535")
		}
	}
	s.publicOrigin = u
	return nil
}

func validOriginAuthority(u *url.URL) bool {
	host := u.Hostname()
	ip := net.ParseIP(host)
	if strings.ContainsAny(u.Host, "[]") {
		// URL brackets represent an IPv6 literal, never DNS or IPv4.
		return ip != nil && ip.To4() == nil && strings.HasPrefix(u.Host, "[")
	}
	if ip != nil && strings.Contains(host, ":") {
		return false // An IPv6 URL authority must use brackets.
	}
	return validOriginHost(host)
}

func validOriginURL(u *url.URL) bool {
	return u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/")
}

func validOriginHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}

func (s *Server) trustedOrigin(value, host string) bool {
	u, err := url.Parse(value)
	if err != nil || !validOriginURL(u) {
		return false
	}
	if s.publicOrigin == nil {
		return strings.EqualFold(u.Host, host)
	}
	// When configured, accept only the explicit public origin, even if Host
	// matches some other domain or an untrusted forwarded header claims it does.
	return !strings.ContainsAny(value, "?#") && u.Path == "" && u.Scheme == s.publicOrigin.Scheme && strings.EqualFold(u.Host, s.publicOrigin.Host)
}
