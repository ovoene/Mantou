package dnsprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestCloudflareSetTXTIsIdempotentForSameNameAndValue(t *testing.T) {
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone1"}}})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodGet:
			if r.URL.Query().Get("type") != "TXT" || r.URL.Query().Get("name") != "_acme-challenge.example.com" || r.URL.Query().Get("content") != "value" {
				t.Fatalf("unexpected query: %s", r.URL.RawQuery)
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "record1"}}})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodPost:
			postCount++
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "record2"}})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	oldBase := cfAPIBase
	cfAPIBase = server.URL
	defer func() { cfAPIBase = oldBase }()

	provider := &cloudflareProvider{}
	err := provider.SetTXT(context.Background(), TXTRequest{
		Zone:    "example.com",
		FQDN:    "_acme-challenge.example.com",
		Value:   "value",
		Secrets: map[string]string{"apiToken": "token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if postCount != 0 {
		t.Fatalf("created %d duplicate records", postCount)
	}
}

func TestCloudflareSetTXTConcurrentSameNameAndValueCreatesOnce(t *testing.T) {
	var mu sync.Mutex
	records := map[string]string{}
	postCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone1"}}})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodGet:
			mu.Lock()
			id, ok := records[r.URL.Query().Get("content")]
			mu.Unlock()
			result := []map[string]string{}
			if ok {
				result = append(result, map[string]string{"id": id})
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodPost:
			var payload struct {
				Content string `json:"content"`
			}
			json.NewDecoder(r.Body).Decode(&payload)
			mu.Lock()
			postCount++
			records[payload.Content] = "record" + payload.Content
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "record"}})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	oldBase := cfAPIBase
	cfAPIBase = server.URL
	defer func() { cfAPIBase = oldBase }()

	provider := &cloudflareProvider{}
	req := TXTRequest{Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "same", Secrets: map[string]string{"apiToken": "token"}}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := provider.SetTXT(context.Background(), req); err != nil {
				t.Errorf("SetTXT failed: %v", err)
			}
		}()
	}
	wg.Wait()
	if postCount != 1 {
		t.Fatalf("expected one TXT record, created %d", postCount)
	}
}

func TestCloudflareSetTXTAllowsRootAndWildcardValuesAtSameName(t *testing.T) {
	var mu sync.Mutex
	records := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/zones":
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]string{{"id": "zone1"}}})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodGet:
			mu.Lock()
			id, ok := records[r.URL.Query().Get("content")]
			mu.Unlock()
			result := []map[string]string{}
			if ok {
				result = append(result, map[string]string{"id": id})
			}
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
		case r.URL.Path == "/zones/zone1/dns_records" && r.Method == http.MethodPost:
			var payload struct {
				Content string `json:"content"`
			}
			json.NewDecoder(r.Body).Decode(&payload)
			mu.Lock()
			records[payload.Content] = "record-" + payload.Content
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"id": "record"}})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()
	oldBase := cfAPIBase
	cfAPIBase = server.URL
	defer func() { cfAPIBase = oldBase }()

	provider := &cloudflareProvider{}
	for _, value := range []string{"root-value", "wildcard-value"} {
		err := provider.SetTXT(context.Background(), TXTRequest{
			Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: value, Secrets: map[string]string{"apiToken": "token"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(records) != 2 {
		t.Fatalf("expected both challenge values, got %v", records)
	}
}
