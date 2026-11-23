// Package status reads the state of the applications from ArgoCD (read-only API token) for the
// system status card of the admin app. Only a short summary leaves this package: no repository URLs,
// parameters or resource details.
package status

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// App is the summary of one ArgoCD application.
type App struct {
	Name string `json:"name"`
	// Sync is Synced, OutOfSync or Unknown.
	Sync string `json:"sync"`
	// Health is Healthy, Progressing, Degraded, Suspended, Missing or Unknown.
	Health   string `json:"health"`
	Revision string `json:"revision,omitempty"`
	// SyncedAt is the RFC 3339 time the last sync finished.
	SyncedAt string `json:"syncedAt,omitempty"`
}

// Config of the ArgoCD client.
type Config struct {
	// URL is the address of argocd-server (http://argocd-server.argocd.svc), without a trailing slash.
	URL string
	// Token is the API token of a read-only account.
	Token string
	// Project, when set, lists only the applications of that ArgoCD project.
	Project string
	// CacheTTL is how long an answer is reused (default 30s): opening the home page must not call ArgoCD every time.
	CacheTTL time.Duration
	// HTTP is the client used for the calls (default: 5 second timeout).
	HTTP *http.Client
}

// Client lists the applications.
type Client struct {
	cfg Config
	now func() time.Time

	mu      sync.Mutex
	cached  []App
	fetched time.Time
}

// New builds a client; it fails when the address or the token is missing or the address is not http(s).
func New(cfg Config) (*Client, error) {
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("status: ArgoCD address %q is not an http(s) URL", cfg.URL)
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("status: ArgoCD token is required")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	return &Client{cfg: cfg, now: time.Now}, nil
}

type argoList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Status struct {
			Sync struct {
				Status   string `json:"status"`
				Revision string `json:"revision"`
				// Revisions replaces Revision for an application with several sources.
				Revisions []string `json:"revisions"`
			} `json:"sync"`
			Health struct {
				Status string `json:"status"`
			} `json:"health"`
			OperationState struct {
				FinishedAt string `json:"finishedAt"`
				SyncResult struct {
					Revision  string   `json:"revision"`
					Revisions []string `json:"revisions"`
				} `json:"syncResult"`
			} `json:"operationState"`
		} `json:"status"`
	} `json:"items"`
}

// Apps returns the applications, from the cache while it is fresh. A failed call returns the error and
// keeps the previous answer for the next try.
func (c *Client) Apps(ctx context.Context) ([]App, error) {
	c.mu.Lock()
	if c.cached != nil && c.now().Sub(c.fetched) < c.cfg.CacheTTL {
		out := append([]App(nil), c.cached...)
		c.mu.Unlock()
		return out, nil
	}
	c.mu.Unlock()

	apps, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cached, c.fetched = apps, c.now()
	c.mu.Unlock()
	return append([]App(nil), apps...), nil
}

func (c *Client) fetch(ctx context.Context) ([]App, error) {
	q := url.Values{}
	// No `fields` mask: with it ArgoCD answered without items.status.health (checked against v3.3), so every
	// application looked Unknown. The full list is a few hundred KB for a dozen applications; the cache keeps
	// it to one call per CacheTTL, and only the summary below leaves this package.
	if c.cfg.Project != "" {
		q.Set("projects", c.cfg.Project)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL+"/api/v1/applications?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Accept", "application/json")
	res, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("status: ArgoCD request failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		return nil, fmt.Errorf("status: ArgoCD answered %d", res.StatusCode)
	}
	var list argoList
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("status: ArgoCD answer is not JSON: %w", err)
	}
	apps := make([]App, 0, len(list.Items))
	for _, it := range list.Items {
		apps = append(apps, App{
			Name:   it.Metadata.Name,
			Sync:   orUnknown(it.Status.Sync.Status),
			Health: orUnknown(it.Status.Health.Status),
			Revision: firstNonEmpty(it.Status.Sync.Revision, first(it.Status.Sync.Revisions),
				it.Status.OperationState.SyncResult.Revision, first(it.Status.OperationState.SyncResult.Revisions)),
			SyncedAt: it.Status.OperationState.FinishedAt,
		})
	}
	return apps, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// firstNonEmpty is the revision of the sync status, else of an application with several sources, else the one
// the last operation synced.
func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func orUnknown(s string) string {
	if s == "" {
		return "Unknown"
	}
	return s
}
