package regkey_test

import (
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/regkey"
)

func TestStringRoundTrip(t *testing.T) {
	const sub = `Software\gha-test-regkey`
	t.Cleanup(func() { _ = regkey.DeleteValue(sub, "probe") })

	if _, ok, err := regkey.GetString(sub, "probe"); err != nil || ok {
		t.Fatalf("初始状态应为不存在（ok=%v err=%v）", ok, err)
	}
	if err := regkey.SetString(sub, "probe", `"C:\Program Files\gha.exe" run`); err != nil {
		t.Fatalf("SetString: %v", err)
	}
	got, ok, err := regkey.GetString(sub, "probe")
	if err != nil || !ok {
		t.Fatalf("GetString: ok=%v err=%v", ok, err)
	}
	if want := `"C:\Program Files\gha.exe" run`; got != want {
		t.Fatalf("got %q want %q", got, want)
	}

	// 覆盖写
	if err := regkey.SetString(sub, "probe", "short"); err != nil {
		t.Fatalf("覆盖写: %v", err)
	}
	if got, _, _ := regkey.GetString(sub, "probe"); got != "short" {
		t.Fatalf("覆盖写之后 got %q", got)
	}

	if err := regkey.DeleteValue(sub, "probe"); err != nil {
		t.Fatalf("DeleteValue: %v", err)
	}
	if _, ok, err := regkey.GetString(sub, "probe"); err != nil || ok {
		t.Fatalf("删除后仍存在（ok=%v err=%v）", ok, err)
	}
	// 幂等：删不存在的值不算错误
	if err := regkey.DeleteValue(sub, "probe"); err != nil {
		t.Fatalf("重复删除应当成功: %v", err)
	}
}
