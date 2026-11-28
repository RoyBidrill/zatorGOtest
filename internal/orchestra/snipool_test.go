package orchestra

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSNIPoolAndSetsLifecycle(t *testing.T) {
	root := t.TempDir()
	orchDir := filepath.Join(root, "state", "orchestra")
	zatorTxt := filepath.Join(root, "extra_strats", "sni_zator.txt")
	userTxt := filepath.Join(root, "extra_strats", "sni_user.txt")
	if err := os.MkdirAll(filepath.Dir(zatorTxt), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zatorTxt, []byte("# set: google\nwww.google.com\n\n# set: google2\nfonts.googleapis.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewStore(orchDir)
	if err := s.EnsureDefaultSNIPool(); err != nil {
		t.Fatal(err)
	}
	rows, err := s.SNIPoolRows()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows["1"]) != 1 || rows["1"][0] != "@google" || rows["2"][0] != "@google" {
		t.Fatalf("unexpected default pool rows: %+v", rows)
	}

	if err := s.WriteUserSNISet(userTxt, "my", []string{"example.com", "sub.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteUserSNISet(userTxt, "my2", []string{"cdn.example.org"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AssignSNIPoolSet("1", "my2", zatorTxt, userTxt); err != nil {
		t.Fatal(err)
	}
	// @my2 используется профилем 1 — удалить @my2 нельзя, а @my (хоть префикс совпадает!) можно!
	if err := s.DeleteUserSNISet(zatorTxt, userTxt, "my2"); !errors.Is(err, ErrSNISetInUse) {
		t.Fatalf("expected ErrSNISetInUse, got %v", err)
	}
	if err := s.DeleteUserSNISet(zatorTxt, userTxt, "my"); err != nil {
		t.Fatalf("exact match delete of @my failed: %v", err)
	}
	// Проектный набор удалить нельзя.
	if err := s.DeleteUserSNISet(zatorTxt, userTxt, "google"); !errors.Is(err, ErrSNISetProtected) {
		t.Fatalf("expected ErrSNISetProtected, got %v", err)
	}

	// Custom list + policy + payload
	if err := s.SetSNIPoolCustom("3", []string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSNIPoolPolicy("3", SNIPolicyRand); err != nil {
		t.Fatal(err)
	}
	if err := s.SetOverride(OverrideSNI, "1", "300.ya.ru"); err != nil {
		t.Fatal(err)
	}

	payload, err := s.BuildSNIPayload(zatorTxt, userTxt, map[string]string{"1": "TCP 443 (YouTube)"})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Profiles) != 5 {
		t.Fatalf("profiles = %d, want 5", len(payload.Profiles))
	}
	if payload.Profiles[0].Pin != "300.ya.ru" || payload.Profiles[0].Set != "my2" {
		t.Fatalf("profile 1 = %+v", payload.Profiles[0])
	}
	if payload.Profiles[2].Policy != "rand" || len(payload.Profiles[2].Effective) != 2 {
		t.Fatalf("profile 3 = %+v", payload.Profiles[2])
	}
}

func TestLockedLuaAssetParityAndFixes(t *testing.T) {
	luaPath := filepath.Join("..", "..", "assets", "lua", "locked.lua")
	orchPath := filepath.Join("..", "..", "assets", "orchestra", "locked.lua")
	luaBytes, err := os.ReadFile(luaPath)
	if err != nil {
		t.Fatalf("read %s: %v", luaPath, err)
	}
	orchBytes, err := os.ReadFile(orchPath)
	if err != nil {
		t.Fatalf("read %s: %v", orchPath, err)
	}
	if string(luaBytes) != string(orchBytes) {
		t.Fatalf("assets/lua/locked.lua (%d B) and assets/orchestra/locked.lua (%d B) differ", len(luaBytes), len(orchBytes))
	}

	sniPoolPath := filepath.Join("..", "..", "assets", "lua", "sni-pool.lua")
	sniPoolBytes, err := os.ReadFile(sniPoolPath)
	if err != nil {
		t.Fatalf("read %s: %v", sniPoolPath, err)
	}
	sniPoolText := string(sniPoolBytes)
	if !stringsContainsAll(sniPoolText,
		"Alexander Markin",
		"https://github.com/AloofLibra/zator",
		"local SETS_TTL = 30",
		"last_sets_load",
	) {
		t.Fatalf("sni-pool.lua missing required GPL attribution or SETS_TTL cache")
	}
}

func stringsContainsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
