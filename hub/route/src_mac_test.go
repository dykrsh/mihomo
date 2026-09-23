package route

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/tunnel"
)

func TestSourceMACConfigAPI(t *testing.T) {
	old := tunnel.SourceMACOptions()
	t.Cleanup(func() { _ = tunnel.SetSourceMACOptions(old.Probe, int(old.Timeout/time.Millisecond)) })
	if err := tunnel.SetSourceMACOptions(false, 1000); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body    string
		status  int
		probe   bool
		timeout int
	}{
		{`{"src-mac-probe":true}`, 204, true, 1000},
		{`{"src-mac-timeout":750}`, 204, true, 750},
		{`{"src-mac-probe":false,"src-mac-timeout":0}`, 400, true, 750},
		{`{"src-mac-probe":false}`, 204, false, 750},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("PATCH", "/", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		patchConfigs(w, r)
		if w.Code != tc.status {
			t.Fatalf("PATCH %s: %d %s", tc.body, w.Code, w.Body.String())
		}
		w = httptest.NewRecorder()
		getConfigs(w, httptest.NewRequest("GET", "/", nil))
		var got struct {
			Probe   bool `json:"src-mac-probe"`
			Timeout int  `json:"src-mac-timeout"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Probe != tc.probe || got.Timeout != tc.timeout {
			t.Fatalf("PATCH did not preserve omitted options or rejected update: %+v", got)
		}
	}
}
