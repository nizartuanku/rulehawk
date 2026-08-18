package rulehawk

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nizartuanku/rulehawk/fwparse"
)

// Console serves RuleHawk's config endpoints: upload/replace a config, set the
// current config as the drift baseline, list configs, and delete one. The cmd
// wires OnSaved (register the scheduler target + persist + trigger an immediate
// re-audit) and OnDelete.
type Console struct {
	Store    Store
	Caps     func() int            // max configs for the tier (0 = unlimited)
	OnSaved  func(name string) error
	OnDelete func(name string)
}

// Register mounts the console routes.
func (c *Console) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/rulehawk/configs", c.handleList)
	mux.HandleFunc("POST /api/rulehawk/config", c.handleSave)
	mux.HandleFunc("DELETE /api/rulehawk/config", c.handleDelete)
	mux.HandleFunc("POST /api/rulehawk/baseline", c.handleBaseline)
}

type configView struct {
	Config
	Vendors []string `json:"vendors,omitempty"`
}

func (c *Console) handleList(w http.ResponseWriter, r *http.Request) {
	cfgs, err := c.Store.ListConfigs()
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cfgs == nil {
		cfgs = []Config{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"configs": cfgs, "vendors": vendorOptions()})
}

type vendorOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

func vendorOptions() []vendorOption {
	vs := fwparse.Vendors()
	out := make([]vendorOption, 0, len(vs))
	for _, v := range vs {
		out = append(out, vendorOption{ID: v, Label: fwparse.VendorLabel(v)})
	}
	return out
}

type saveRequest struct {
	Name   string `json:"name"`
	Vendor string `json:"vendor"`
	Config string `json:"config"`
}

func (c *Console) handleSave(w http.ResponseWriter, r *http.Request) {
	var req saveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		httpErr(w, http.StatusBadRequest, "a config name is required")
		return
	}
	if strings.TrimSpace(req.Config) == "" {
		httpErr(w, http.StatusBadRequest, "the config text is empty")
		return
	}
	if !validVendor(req.Vendor) {
		httpErr(w, http.StatusBadRequest, "unknown vendor: "+req.Vendor)
		return
	}
	parsed, err := fwparse.Parse(req.Vendor, req.Config)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}

	existing, exists, _ := c.Store.GetConfig(req.Name)
	if !exists && c.Caps != nil {
		if max := c.Caps(); max != 0 {
			if cfgs, _ := c.Store.ListConfigs(); len(cfgs) >= max {
				httpErr(w, http.StatusForbidden, "config limit reached for your tier — upgrade to add more")
				return
			}
		}
	}

	cfg := Config{Name: req.Name, Vendor: req.Vendor, Current: req.Config}
	if exists {
		cfg.Baseline = existing.Baseline // preserve any baseline across re-uploads
	}
	if err := c.Store.PutConfig(cfg); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c.OnSaved != nil {
		if err := c.OnSaved(req.Name); err != nil {
			httpErr(w, http.StatusConflict, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"saved": req.Name, "rules": len(parsed.Rules), "unparsed": len(parsed.Unparsed),
	})
}

type baselineRequest struct {
	Name string `json:"name"`
}

func (c *Console) handleBaseline(w http.ResponseWriter, r *http.Request) {
	var req baselineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cfg, ok, err := c.Store.GetConfig(strings.TrimSpace(req.Name))
	if err != nil || !ok {
		httpErr(w, http.StatusNotFound, "no such config")
		return
	}
	cfg.Baseline = cfg.Current
	if err := c.Store.PutConfig(cfg); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if c.OnSaved != nil {
		_ = c.OnSaved(cfg.Name) // re-audit against the new baseline
	}
	writeJSON(w, http.StatusOK, map[string]any{"baseline_set": cfg.Name})
}

func (c *Console) handleDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		httpErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if c.OnDelete != nil {
		c.OnDelete(name)
	}
	if err := c.Store.DeleteConfig(name); err != nil {
		httpErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name})
}

func validVendor(v string) bool {
	for _, x := range fwparse.Vendors() {
		if x == v {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
