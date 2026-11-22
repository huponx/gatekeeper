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
