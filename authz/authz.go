// Package authz is a thin adapter that lets a file manager keep its path-based
// allow/deny rules in SpiceDB instead of re-implementing inheritance per endpoint.
package authz

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Subject is a user ("user", id) or a group's members ("group", id, "member").
type Subject struct{ Type, ID, Relation string }

func User(id string) Subject         { return Subject{"user", id, ""} }
func GroupMembers(id string) Subject { return Subject{"group", id, "member"} }

type Engine struct{ c *authzed.Client }

func New(endpoint, key string) (*Engine, error) {
	c, err := authzed.NewClient(endpoint,
		grpcutil.WithInsecureBearerToken(key),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Engine{c: c}, nil
}

func (e *Engine) WriteSchema(ctx context.Context, schema string) error {
	_, err := e.c.WriteSchema(ctx, &pb.WriteSchemaRequest{Schema: schema})
	return err
}

func rel(resType, resID, relation string, s Subject) *pb.Relationship {
	return &pb.Relationship{
		Resource: &pb.ObjectReference{ObjectType: resType, ObjectId: resID},
		Relation: relation,
		Subject: &pb.SubjectReference{
			Object:           &pb.ObjectReference{ObjectType: s.Type, ObjectId: s.ID},
			OptionalRelation: s.Relation,
		},
	}
}

func (e *Engine) write(ctx context.Context, op pb.RelationshipUpdate_Operation, rels ...*pb.Relationship) error {
	ups := make([]*pb.RelationshipUpdate, 0, len(rels))
	for _, r := range rels {
		ups = append(ups, &pb.RelationshipUpdate{Operation: op, Relationship: r})
	}
	_, err := e.c.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{Updates: ups})
	return err
}

// ancestors("home/o/dir1") -> ["home", "home/o"]
func ancestors(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var out []string
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// EnsureFolder writes the parent chain for path. TOUCH makes it idempotent,
// so it is safe to call on every rule change and on startup reconciliation.
func (e *Engine) EnsureFolder(ctx context.Context, path string) error {
	path = strings.Trim(path, "/")
	chain := append(ancestors(path), path)
	var rels []*pb.Relationship
	for i := 1; i < len(chain); i++ {
		rels = append(rels, rel("folder", chain[i], "parent", Subject{"folder", chain[i-1], ""}))
	}
	if len(rels) == 0 {
		return nil
	}
	return e.write(ctx, pb.RelationshipUpdate_OPERATION_TOUCH, rels...)
}

// Allow maps a Quantum allow rule. level is "reader" or "writer". It also marks every
// ancestor traversable so the tree can be walked down to a deep grant (#1903).
func (e *Engine) Allow(ctx context.Context, s Subject, path, level string) error {
	if level != "reader" && level != "writer" {
		return fmt.Errorf("level must be reader or writer, got %q", level)
	}
	path = strings.Trim(path, "/")
	if err := e.EnsureFolder(ctx, path); err != nil {
		return err
	}
	rels := []*pb.Relationship{rel("folder", path, level, s)}
	for _, a := range ancestors(path) {
		rels = append(rels, rel("folder", a, "traverser", s))
	}
	return e.write(ctx, pb.RelationshipUpdate_OPERATION_TOUCH, rels...)
}

// Deny maps a Quantum deny rule. The schema makes it apply to everything beneath path (#1282).
func (e *Engine) Deny(ctx context.Context, s Subject, path string) error {
	path = strings.Trim(path, "/")
	if err := e.EnsureFolder(ctx, path); err != nil {
		return err
	}
	return e.write(ctx, pb.RelationshipUpdate_OPERATION_TOUCH, rel("folder", path, "denied", s))
}

// RemoveDeny deletes a deny so access returns immediately.
// TODO: removing an Allow must also clean up traverser relationships that no other grant needs.
func (e *Engine) RemoveDeny(ctx context.Context, s Subject, path string) error {
	return e.write(ctx, pb.RelationshipUpdate_OPERATION_DELETE, rel("folder", strings.Trim(path, "/"), "denied", s))
}

// Can asks "can user do permission (view|edit|browse) on path?".
// FullyConsistent keeps the PoC simple; production should pass a ZedToken from the last
// write (AtLeastAsFresh) for post-write checks and use MinimizeLatency for plain browsing.
func (e *Engine) Can(ctx context.Context, userID, permission, path string) (bool, error) {
	resp, err := e.c.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Consistency: &pb.Consistency{Requirement: &pb.Consistency_FullyConsistent{FullyConsistent: true}},
		Resource:    &pb.ObjectReference{ObjectType: "folder", ObjectId: strings.Trim(path, "/")},
		Permission:  permission,
		Subject:     &pb.SubjectReference{Object: &pb.ObjectReference{ObjectType: "user", ObjectId: userID}},
	})
	if err != nil {
		return false, err
	}
	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}
