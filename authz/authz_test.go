package authz

import (
	"context"
	"os"
	"testing"
)

// Needs a running SpiceDB:  make test
func engine(t *testing.T) *Engine {
	ep, key := os.Getenv("SPICEDB_ENDPOINT"), os.Getenv("SPICEDB_KEY")
	if ep == "" {
		t.Skip("SPICEDB_ENDPOINT not set; run `make test`")
	}
	e, err := New(ep, key)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../schema.zed")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.WriteSchema(context.Background(), string(schema)); err != nil {
		t.Fatal(err)
	}
	return e
}

func check(t *testing.T, e *Engine, user, perm, path string, want bool) {
	t.Helper()
	got, err := e.Can(context.Background(), user, perm, path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("%s %s %s = %v, want %v", user, perm, path, got, want)
	}
}

// Issue #1282: a deny must hold on nested folders, not just direct children.
func TestNestedDeny(t *testing.T) {
	e, ctx := engine(t), context.Background()
	must(t, e.Allow(ctx, User("bob"), "home", "reader"))
	must(t, e.Deny(ctx, User("bob"), "home/a"))
	must(t, e.EnsureFolder(ctx, "home/a/b/c"))
	check(t, e, "bob", "view", "home", true)
	for _, p := range []string{"home/a", "home/a/b", "home/a/b/c"} {
		check(t, e, "bob", "view", p, false)
	}
	// removing the deny restores access right away
	must(t, e.RemoveDeny(ctx, User("bob"), "home/a"))
	check(t, e, "bob", "view", "home/a/b/c", true)
}

// Issue #1903: a deep allow must make the path walkable without exposing siblings.
func TestDeepAllowIsNavigable(t *testing.T) {
	e, ctx := engine(t), context.Background()
	must(t, e.EnsureFolder(ctx, "home/o/dir2"))
	must(t, e.Allow(ctx, User("carol"), "home/o/dir1", "reader"))
	check(t, e, "carol", "view", "home/o/dir1", true)
	check(t, e, "carol", "browse", "home", true)
	check(t, e, "carol", "browse", "home/o", true)
	check(t, e, "carol", "view", "home/o", false)
	check(t, e, "carol", "view", "home/o/dir2", false)
	check(t, e, "carol", "browse", "home/o/dir2", false)
}

func TestGroupInheritance(t *testing.T) {
	e, ctx := engine(t), context.Background()
	must(t, e.write(ctx, 1, rel("group", "eng", "member", User("anne")))) // OPERATION_TOUCH == 1
	must(t, e.Allow(ctx, GroupMembers("eng"), "home", "reader"))
	must(t, e.EnsureFolder(ctx, "home/a/b/c"))
	check(t, e, "anne", "view", "home/a/b/c", true)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
