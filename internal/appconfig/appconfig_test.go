package appconfig

import (
	"slices"
	"testing"
)

func TestOriginsSeparators(t *testing.T) {
	cases := map[string]struct {
		ui      []string
		allowed []string
		want    []string
	}{
		"comma":  {ui: []string{"https://a.example.com", "https://b.example.com/"}, want: []string{"https://a.example.com", "https://b.example.com"}},
		"lines":  {ui: []string{"https://a.example.com\nhttps://b.example.com\n"}, want: []string{"https://a.example.com", "https://b.example.com"}},
		"spaces": {ui: []string{"https://a.example.com  https://b.example.com"}, want: []string{"https://a.example.com", "https://b.example.com"}},
		// the env parser splits on commas first, so an item can still hold several lines
		"commas and lines": {
			ui:   []string{"https://a.example.com", " https://b.example.com\nhttps://c.example.com"},
			want: []string{"https://a.example.com", "https://b.example.com", "https://c.example.com"},
		},
		"alias and duplicates": {
			ui: []string{"https://a.example.com"}, allowed: []string{"https://a.example.com", "https://b.example.com"},
			want: []string{"https://a.example.com", "https://b.example.com"},
		},
		"empty falls back to public url": {want: []string{"https://api.example.com"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := Gatekeeper{PublicURL: "https://api.example.com", UIOrigins: tc.ui, AllowedOrigins: tc.allowed}
			if got := c.Origins(); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestArgoCDSettingsGoTogether(t *testing.T) {
	base := Gatekeeper{Port: 8080, PublicURL: "https://api.example.com", ArgoCDURL: "http://argocd-server.argocd.svc", ArgoCDToken: "t"}
	base.Env = "production"
	if err := base.Validate(); err != nil {
		t.Fatalf("both set: %v", err)
	}
	for name, c := range map[string]Gatekeeper{
		"url only":   {Port: 8080, PublicURL: "https://api.example.com", ArgoCDURL: "http://x"},
		"token only": {Port: 8080, PublicURL: "https://api.example.com", ArgoCDToken: "t"},
	} {
		c.Env = "production"
		if c.Validate() == nil {
			t.Errorf("%s must fail", name)
		}
	}
}
