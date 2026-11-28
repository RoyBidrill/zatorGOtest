package customstrats

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AloofLibra/zator/internal/config"
	"github.com/AloofLibra/zator/internal/orchestra"
)

func loadSampleConfig(t *testing.T, withMarkers bool) (*config.Config, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config")
	var tplCustom, p5Custom string
	if withMarkers {
		tplCustom = "#Z2R_CUSTOM_TPL_BEGIN\n#Z2R_CUSTOM_TPL_END\n"
		p5Custom = "#Z2R_CUSTOM_P5_BEGIN\n#Z2R_CUSTOM_P5_END\n"
	}
	raw := `NFQWS2_OPT="
--lua-init=@/opt/zator/lua/locked.lua
--blob=maxru:@/opt/zator/files/fake/tls_clienthello_max_ru.bin
--blob=quic_google:@/opt/zator/files/fake/quic_initial_www_google_com.bin
--template=z2r_tcp_tls_common
--lua-desync=fake:blob=maxru:repeats=1:strategy=43
` + tplCustom + `
--lua-desync=circular_locked:key=1:strategy=1
--lua-desync=circular_locked:key=5:strategy=1
--lua-desync=fake:blob=quic_google:repeats=2:strategy=32
` + p5Custom + `
--lua-desync=circular_locked:key=6:strategy=1
"
`
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, p
}

func TestValidateRulesAndOOB(t *testing.T) {
	cfg, _ := loadSampleConfig(t, true)
	known := KnownBlobNames(cfg, "")

	validCases := []struct {
		block string
		spec  string
	}{
		{BlockTPL, "fake:blob=maxru:tcp_seq=-3000"},
		{BlockTPL, "oob:urp=midsld+1:byte=0:char=x"},
		{BlockTPL, "tls_client_hello_clone:blob=clone1:fallback=maxru:sni_snt_new=1 --lua-desync=fake:blob=clone1:repeats=2"},
		{BlockTPL, "multisplit:pos=sniext+1,midsld:seqovl=#maxru --lua-desync=http_hostcase:spell=hoSt"},
		{BlockTPL, "fake:pattern=0x160301:tls_mod=rnd,sni=%maxru"},
		{BlockP5, "fake:blob=quic_google:repeats=4:ip_ttl=4:ip_id=rnd:ipfrag:ipfrag_pos_udp=8"},
	}
	for _, tc := range validCases {
		norm, err := NormalizeSpec("--lua-desync=" + tc.spec + ":strategy=99")
		if err != nil {
			t.Fatalf("NormalizeSpec(%q): %v", tc.spec, err)
		}
		if err := Validate(tc.block, norm, known); err != nil {
			t.Errorf("Validate(%s, %q) failed: %v", tc.block, norm, err)
		}
	}

	invalidCases := []struct {
		block string
		spec  string
		want  string
	}{
		{BlockTPL, "fake:blob=nonexistent", "не объявлен"},
		{BlockP5, "multisplit:pos=1", "не работает в UDP"},
		{BlockTPL, "udplen:increment=4", "не работает в TCP"},
		{BlockTPL, "oob:urp=BAD_UPPER", "urp="},
		{BlockTPL, "http_hostcase:spell=Host1", "spell="},
		{BlockTPL, "fake:blob=maxru`id`", "Запрещённые"},
		{BlockTPL, strings.Repeat("fake:blob=maxru --lua-desync=", 9) + "fake:blob=maxru", "8 групп"},
	}
	for _, tc := range invalidCases {
		if err := Validate(tc.block, tc.spec, known); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Validate(%s, %q): want %q, got %v", tc.block, tc.spec, tc.want, err)
		}
	}
}

func TestCRUDApplyAndRemapLocks(t *testing.T) {
	cfg, cfgPath := loadSampleConfig(t, false)
	dir := t.TempDir()
	orchDir := filepath.Join(dir, "orchestra")
	orch := orchestra.NewStore(orchDir)
	autoPath := filepath.Join(orchDir, "auto_locked.tsv")

	// Seed custom_blobs.tsv so validator recognizes unapplied custom blob name.
	blobsTSV := filepath.Join(orchDir, "custom_blobs.tsv")
	if err := os.MkdirAll(orchDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blobsTSV, []byte("# hdr\n1\tmy_blob\tmy.bin\tcomment\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	st := NewStore(filepath.Join(orchDir, "custom_strategies.tsv"), blobsTSV, orch, autoPath)
	e1, err := st.Add(BlockTPL, "fake:blob=my_blob:repeats=1", "first\tnote", cfg)
	if err != nil {
		t.Fatalf("Add 1: %v", err)
	}
	e2, err := st.Add(BlockTPL, "--lua-desync=multisplit:pos=1:strategy=10 --lua-desync=send:repeats=2:strategy=10", "combo", cfg)
	if err != nil {
		t.Fatalf("Add 2: %v", err)
	}

	res, err := st.Apply(cfg)
	if err != nil || !res.Changed {
		t.Fatalf("Apply 1: %+v err=%v", res, err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	got1, _, _ := st.Get(e1.ID)
	got2, _, _ := st.Get(e2.ID)
	if got1.Assigned != 44 || got2.Assigned != 45 {
		t.Fatalf("expected assigned 44/45, got %d/%d", got1.Assigned, got2.Assigned)
	}

	// Lock profile 1 to strategy 45 and auto_locked to 45.
	if err := os.WriteFile(orch.LockedPath(), []byte("1\ttls\t45\n1\thttp\t45\n2\ttls\t44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(autoPath, []byte("tls\tyoutube.com\t45\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Disable e1 -> e2 shifts from 45 down to 44; lock 44 drops, lock 45 remaps to 44!
	if err := st.SetEnabled(e1.ID, false); err != nil {
		t.Fatal(err)
	}
	res2, err := st.ApplyFile(cfgPath)
	if err != nil || !res2.Changed {
		t.Fatalf("ApplyFile shift: %+v err=%v", res2, err)
	}
	lockedRaw, _ := os.ReadFile(orch.LockedPath())
	autoRaw, _ := os.ReadFile(autoPath)
	if !strings.Contains(string(lockedRaw), "1\ttls\t44") || !strings.Contains(string(lockedRaw), "1\thttp\t44") {
		t.Fatalf("expected profile 1 remapped to 44, got:\n%s", lockedRaw)
	}
	if strings.Contains(string(lockedRaw), "2\ttls\t") {
		t.Fatalf("expected disabled profile 2 lock dropped, got:\n%s", lockedRaw)
	}
	if !strings.Contains(string(autoRaw), "tls\tyoutube.com\t44") {
		t.Fatalf("expected auto_locked remapped to 44, got:\n%s", autoRaw)
	}

	// Verify Delete compacts IDs cleanly and drops lock above new max.
	if err := st.Delete(e1.ID); err != nil {
		t.Fatal(err)
	}
	rem, _ := st.List("")
	if len(rem) != 1 || rem[0].ID != 1 {
		t.Fatalf("expected compacted ID=1, got %+v", rem)
	}
	if cnt, _ := st.CountBlobRefs("my_blob"); cnt != 0 {
		t.Fatalf("expected 0 refs after deleting e1, got %d", cnt)
	}
}

func TestRenameBlobInSpecs(t *testing.T) {
	cfg, _ := loadSampleConfig(t, true)
	dir := t.TempDir()
	blobsTSV := filepath.Join(dir, "custom_blobs.tsv")
	_ = os.WriteFile(blobsTSV, []byte("# hdr\n1\told_fake\ta.bin\t\n2\told_fake_2\tb.bin\t\n"), 0o644)

	st := NewStore(filepath.Join(dir, "custom_strategies.tsv"), blobsTSV, nil)
	_, err := st.Add(BlockTPL, "fake:blob=old_fake:fallback=old_fake_2 --lua-desync=send:repeats=2", "rename", cfg)
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.RenameBlob("old_fake", "new_fake")
	if err != nil || n != 1 {
		t.Fatalf("RenameBlob: n=%d err=%v", n, err)
	}
	rows, _ := st.List("")
	if rows[0].Spec != "fake:blob=new_fake:fallback=old_fake_2 --lua-desync=send:repeats=2" {
		t.Fatalf("token-exact rename failed: got %q", rows[0].Spec)
	}
}

func TestApplySkipsTSVWriteWhenUnchanged(t *testing.T) {
	cfg, _ := loadSampleConfig(t, false)
	dir := t.TempDir()
	tsvPath := filepath.Join(dir, "custom_strategies.tsv")
	blobsTSV := filepath.Join(dir, "custom_blobs.tsv")
	_ = os.WriteFile(blobsTSV, []byte("# hdr\n1\tmy_blob\tmy.bin\t\n"), 0o644)

	st := NewStore(tsvPath, blobsTSV, nil)
	if _, err := st.Add(BlockTPL, "fake:blob=my_blob:repeats=1", "noop", cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	past := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(tsvPath, past, past); err != nil {
		t.Fatal(err)
	}
	res, err := st.Apply(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatalf("expected unchanged config on second Apply, got %+v", res)
	}
	info, err := os.Stat(tsvPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.ModTime().Equal(past) {
		t.Fatalf("second idempotent Apply rewrote %s unnecessarily (mtime=%v, want %v)", tsvPath, info.ModTime(), past)
	}
}
