package envvars_test

import (
	"testing"

	"github.com/503329706qq/gha-github-accelerator/internal/envvars"
)

func TestEnvVarRoundTrip(t *testing.T) {
	const name = "GHA_TEST_VAR"
	t.Cleanup(func() { _ = envvars.DeleteUser(name) })

	if err := envvars.SetUser(name, `x:\路径 带空格`); err != nil {
		t.Fatalf("SetUser: %v", err)
	}
	v, ok, err := envvars.GetUser(name)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !ok || v != `x:\路径 带空格` {
		t.Fatalf("GetUser=%q,%v", v, ok)
	}

	if err := envvars.DeleteUser(name); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, ok, err := envvars.GetUser(name); err != nil || ok {
		t.Fatalf("after delete: ok=%v err=%v", ok, err)
	}
	// 删不存在的值不应该报错，否则 uninstall 不可重复执行
	if err := envvars.DeleteUser(name); err != nil {
		t.Fatalf("second DeleteUser: %v", err)
	}
}

func TestSetUserEmptyDeletes(t *testing.T) {
	const name = "GHA_TEST_VAR_EMPTY"
	if err := envvars.SetUser(name, "v"); err != nil {
		t.Fatal(err)
	}
	if err := envvars.SetUser(name, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := envvars.GetUser(name); ok {
		t.Fatal("empty value should delete the entry")
	}
}
