// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	v1 "github.com/in-toto/attestation/go/predicates/vsa/v1"
	spb "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/giteacontrol"
	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/vcs"
	"github.com/slsa-framework/source-tool/pkg/vcscontrol"
)

type ProvenanceAttestorOptions struct {
	VsaRetries         uint8
	UseCurrentControls bool // If true, use current branch controls instead of push-time controls
}

type ProvenanceAttestor struct {
	verifier Verifier
	conn     vcscontrol.Connection
	provider vcscontrol.ControlProvider
	Options  ProvenanceAttestorOptions
}

// NewProvenanceAttestor creates a new ProvenanceAttestor
// Accepts both GitHub connection (for backwards compatibility) and vcscontrol.VcsControl
func NewProvenanceAttestor(conn any, verifier Verifier) *ProvenanceAttestor {
	pa := &ProvenanceAttestor{verifier: verifier}

	// Check if it's a VcsControl with both connection and provider
	if vc, ok := conn.(*vcscontrol.VcsControl); ok {
		info := vc.GetControlInfo()
		pa.conn = info.Connection
		pa.provider = info.ControlProvider
	} else if ghConn, ok := conn.(*ghcontrol.GitHubConnection); ok {
		// Backwards compatibility for GitHub connections
		pa.conn = &ghControlWrapper{conn: ghConn}
		pa.provider = &ghControlProviderWrapper{conn: ghConn}
	} else if giteaConn, ok := conn.(*giteacontrol.GiteaConnection); ok {
		// Gitea connection
		pa.conn = &giteaControlWrapper{conn: giteaConn}
		pa.provider = &giteaControlProviderWrapper{conn: giteaConn}
	} else if c, ok := conn.(vcscontrol.Connection); ok {
		// It's already a vcscontrol.Connection (including backend GiteaConnection if it implements the interface)
		pa.conn = c
		// Try to use the connection as provider if it implements ControlProvider
		if p, ok := conn.(vcscontrol.ControlProvider); ok {
			pa.provider = p
		}
	}

	return pa
}

// WithOptions returns a new ProvenanceAttestor with the given options applied
func (pa *ProvenanceAttestor) WithOptions(opts ProvenanceAttestorOptions) *ProvenanceAttestor {
	pa.Options = opts
	return pa
}

// ghControlWrapper wraps a GitHub connection to implement vcscontrol.Connection
type ghControlWrapper struct {
	conn *ghcontrol.GitHubConnection
}

func (g *ghControlWrapper) VcsType() vcscontrol.VcsType { return vcscontrol.VcsTypeGitHub }
func (g *ghControlWrapper) Owner() string               { return g.conn.Owner() }
func (g *ghControlWrapper) Repo() string                { return g.conn.Repo() }
func (g *ghControlWrapper) GetFullRef() string          { return g.conn.GetFullRef() }
func (g *ghControlWrapper) GetRepoUri() string          { return g.conn.GetRepoUri() }
func (g *ghControlWrapper) GetLatestCommit(ctx context.Context, targetBranch string) (string, error) {
	return g.conn.GetLatestCommit(ctx, targetBranch)
}
func (g *ghControlWrapper) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	return g.conn.GetPriorCommit(ctx, sha)
}
func (g *ghControlWrapper) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	return g.conn.GetNotesForCommit(ctx, commit)
}
func (g *ghControlWrapper) BranchToFullRef(branch string) string {
	return ghcontrol.BranchToFullRef(branch)
}
func (g *ghControlWrapper) TagToFullRef(tag string) string {
	return ghcontrol.TagToFullRef(tag)
}

// ghControlProviderWrapper wraps a GitHub connection to implement vcscontrol.ControlProvider
type ghControlProviderWrapper struct {
	conn *ghcontrol.GitHubConnection
}

func (p *ghControlProviderWrapper) GetBranchControls(ctx context.Context, ref string) (*slsa.Controls, error) {
	return p.conn.GetBranchControls(ctx, ref)
}

func (p *ghControlProviderWrapper) GetBranchControlsAtCommit(ctx context.Context, commit, ref string) (vcscontrol.ControlStatus, error) {
	status, err := p.conn.GetBranchControlsAtCommit(ctx, commit, ref)
	if err != nil {
		return nil, err
	}
	return &ghControlStatusWrapper{status: status}, nil
}

func (p *ghControlProviderWrapper) GetTagControls(ctx context.Context) (vcscontrol.ControlStatus, error) {
	status, err := p.conn.GetTagControls(ctx, "", "")
	if err != nil {
		return nil, err
	}
	return &ghControlStatusWrapper{status: status}, nil
}

// ghControlStatusWrapper wraps GitHub control status to implement vcscontrol.ControlStatus
type ghControlStatusWrapper struct {
	status *ghcontrol.GhControlStatus
}

func (s *ghControlStatusWrapper) GetCommitPushTime() time.Time { return s.status.CommitPushTime }
func (s *ghControlStatusWrapper) GetActorLogin() string        { return s.status.ActorLogin }
func (s *ghControlStatusWrapper) GetActivityType() string      { return s.status.ActivityType }
func (s *ghControlStatusWrapper) GetControls() slsa.Controls   { return s.status.Controls }

// giteaControlWrapper wraps a Gitea connection to implement vcscontrol.Connection
type giteaControlWrapper struct {
	conn *giteacontrol.GiteaConnection
}

func (g *giteaControlWrapper) VcsType() vcscontrol.VcsType { return vcscontrol.VcsTypeGitea }
func (g *giteaControlWrapper) Owner() string               { return g.conn.Owner() }
func (g *giteaControlWrapper) Repo() string                { return g.conn.Repo() }
func (g *giteaControlWrapper) GetFullRef() string          { return g.conn.GetFullRef() }
func (g *giteaControlWrapper) GetRepoUri() string          { return g.conn.GetRepoUri() }
func (g *giteaControlWrapper) GetLatestCommit(ctx context.Context, targetBranch string) (string, error) {
	return g.conn.GetLatestCommit(ctx, targetBranch)
}
func (g *giteaControlWrapper) GetPriorCommit(ctx context.Context, sha string) (string, error) {
	return g.conn.GetPriorCommit(ctx, sha)
}
func (g *giteaControlWrapper) GetNotesForCommit(ctx context.Context, commit string) (string, error) {
	return g.conn.GetNotesForCommit(ctx, commit)
}
func (g *giteaControlWrapper) BranchToFullRef(branch string) string {
	// Use the local package's helper function for the backend GiteaConnection
	// The giteacontrol package has its own BranchToFullRef
	return giteacontrol.BranchToFullRef(branch)
}
func (g *giteaControlWrapper) TagToFullRef(tag string) string {
	return giteacontrol.TagToFullRef(tag)
}

// giteaControlProviderWrapper wraps a Gitea connection to implement vcscontrol.ControlProvider
type giteaControlProviderWrapper struct {
	conn *giteacontrol.GiteaConnection
}

func (p *giteaControlProviderWrapper) GetBranchControls(ctx context.Context, ref string) (*slsa.Controls, error) {
	return p.conn.GetBranchControls(ctx, ref)
}

func (p *giteaControlProviderWrapper) GetBranchControlsAtCommit(ctx context.Context, commit, ref string) (vcscontrol.ControlStatus, error) {
	status, err := p.conn.GetBranchControlsAtCommit(ctx, commit, ref)
	if err != nil {
		return nil, err
	}
	return &giteaControlStatusWrapper{status: status}, nil
}

func (p *giteaControlProviderWrapper) GetTagControls(ctx context.Context) (vcscontrol.ControlStatus, error) {
	status, err := p.conn.GetTagControls(ctx)
	if err != nil {
		return nil, err
	}
	return &giteaControlStatusWrapper{status: status}, nil
}

// giteaControlStatusWrapper wraps Gitea control status to implement vcscontrol.ControlStatus
type giteaControlStatusWrapper struct {
	status *giteacontrol.GiteaControlStatus
}

func (s *giteaControlStatusWrapper) GetCommitPushTime() time.Time { return s.status.CommitPushTime }
func (s *giteaControlStatusWrapper) GetActorLogin() string        { return s.status.ActorLogin }
func (s *giteaControlStatusWrapper) GetActivityType() string      { return "" }
func (s *giteaControlStatusWrapper) GetControls() slsa.Controls   { return s.status.Controls }

func GetSourceProvPred(statement *spb.Statement) (*provenance.SourceProvenancePred, error) {
	if statement == nil {
		return nil, errors.New("nil statement")
	}
	if statement.GetPredicateType() != provenance.SourceProvPredicateType {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.GetPredicateType())
	}
	if statement.GetPredicate() == nil {
		return nil, errors.New("nil predicate in statement")
	}
	predJson, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("cannot marshal predicate to JSON: %w", err)
	}

	var predStruct provenance.SourceProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = protojson.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling predicate: %w", err)
	}
	// It's valid for Controls to be empty if no controls are reported.
	// The policy evaluation logic will determine if this is acceptable.
	// For example, a policy might only require SLSA Level 1, which has no specific control requirements from this predicate.
	return &predStruct, nil
}

func GetTagProvPred(statement *spb.Statement) (*provenance.TagProvenancePred, error) {
	if statement == nil {
		return nil, errors.New("nil statement")
	}
	if statement.GetPredicateType() != provenance.TagProvPredicateType {
		return nil, fmt.Errorf("unsupported predicate type: %s", statement.GetPredicateType())
	}
	if statement.GetPredicate() == nil {
		return nil, errors.New("nil predicate in statement")
	}
	predJson, err := protojson.Marshal(statement.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("cannot marshal predicate to JSON: %w", err)
	}

	var predStruct provenance.TagProvenancePred
	// Using regular json.Unmarshal because this is just a regular struct.
	err = protojson.Unmarshal(predJson, &predStruct)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling predicate: %w", err)
	}
	// It's valid for Controls to be empty if no controls are reported.
	// The policy evaluation logic will determine if this is acceptable.
	// For example, a policy might only require SLSA Level 1, which has no specific control requirements from this predicate.
	return &predStruct, nil
}

func addPredToStatement(provPred any, predicateType, commit string) (*spb.Statement, error) {
	msg, ok := provPred.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("unable to serialize predicate as proto message")
	}
	predJson, err := protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate proto: %w", err)
	}

	sub := []*spb.ResourceDescriptor{{
		Digest: map[string]string{"gitCommit": commit},
	}}

	var predPb structpb.Struct
	err = protojson.Unmarshal(predJson, &predPb)
	if err != nil {
		return nil, err
	}

	statementPb := spb.Statement{
		Type:          spb.StatementTypeUri,
		Subject:       sub,
		PredicateType: predicateType,
		Predicate:     &predPb,
	}

	return &statementPb, nil
}

// Create provenance for the current commit without any context from the previous provenance (if any).
func (pa ProvenanceAttestor) createCurrentProvenance(ctx context.Context, commit, prevCommit, ref string) (*spb.Statement, error) {
	var controls slsa.Controls
	var actorLogin, activityType string

	if pa.Options.UseCurrentControls {
		// Use current branch controls (not push-time controls)
		currentControls, err := pa.provider.GetBranchControls(ctx, ref)
		if err != nil {
			return nil, err
		}
		controls = *currentControls
		actorLogin = ""
		activityType = ""
	} else {
		// Use push-time controls (what was enabled when commit was pushed)
		controlStatus, err := pa.provider.GetBranchControlsAtCommit(ctx, commit, ref)
		if err != nil {
			return nil, err
		}
		controls = controlStatus.GetControls()
		actorLogin = controlStatus.GetActorLogin()
		activityType = controlStatus.GetActivityType()
	}

	curTime := time.Now()

	var curProvPred provenance.SourceProvenancePred
	curProvPred.PrevCommit = prevCommit
	curProvPred.RepoUri = pa.conn.GetRepoUri()
	curProvPred.Actor = actorLogin
	curProvPred.ActivityType = activityType
	curProvPred.Branch = ref
	curProvPred.CreatedOn = timestamppb.New(curTime)
	curProvPred.Controls = controls

	// At the very least provenance is available starting now. :)
	// ... indeed, but don't set the `since`` date because doing so breaks
	// checking against policies.
	// See https://github.com/slsa-framework/source-tool/issues/272
	curProvPred.AddControl(
		&provenance.Control{
			Name: slsa.ProvenanceAvailable.String(),
		},
	)

	return addPredToStatement(&curProvPred, provenance.SourceProvPredicateType, commit)
}

// Gets provenance for the commit from git notes.
func (pa ProvenanceAttestor) GetProvenance(ctx context.Context, commit, ref string) (*spb.Statement, *provenance.SourceProvenancePred, error) {
	// Check if connection is nil
	if pa.conn == nil {
		Debugf("connection is nil, cannot get provenance for commit %s", commit)
		return nil, nil, nil
	}

	notes, err := pa.conn.GetNotesForCommit(ctx, commit)
	if notes == "" {
		Debugf("didn't find notes for commit %s", commit)
		return nil, nil, nil
	}

	if err != nil {
		log.Fatal(err)
	}

	bundleReader := NewBundleReader(bufio.NewReader(strings.NewReader(notes)), pa.verifier)

	return pa.getProvFromReader(bundleReader, commit, ref)
}

func (pa ProvenanceAttestor) getProvFromReader(reader *BundleReader, commit, ref string) (*spb.Statement, *provenance.SourceProvenancePred, error) {
	for {
		stmt, err := reader.ReadStatement(MatchesTypeAndCommit(provenance.SourceProvPredicateType, commit))
		if err != nil {
			// Ignore errors, we want to check all the lines.
			Debugf("error while processing line: %v", err)
			continue
		}

		if stmt == nil {
			// No statements left.
			break
		}

		// We know the statement is good, what about the predicate?
		provPred, err := GetSourceProvPred(stmt)
		if err != nil {
			return nil, nil, err
		}
		if pa.conn.GetRepoUri() == provPred.GetRepoUri() && (ref == vcs.AnyReference || provPred.GetBranch() == ref) {
			// Should be good!
			return stmt, provPred, nil
		} else {
			Debugf("prov '%v' does not reference commit '%s' for branch '%s', skipping", stmt, commit, ref)
		}
	}

	Debugf("didn't find commit %s for ref %s", commit, ref)
	return nil, nil, nil
}

func (pa ProvenanceAttestor) getPrevProvenance(ctx context.Context, prevAttPath, prevCommit, ref string) (*spb.Statement, *provenance.SourceProvenancePred, error) {
	if prevAttPath != "" {
		f, err := os.Open(prevAttPath)
		if err != nil {
			return nil, nil, err
		}
		return pa.getProvFromReader(NewBundleReader(bufio.NewReader(f), pa.verifier), prevCommit, ref)
	}

	// Try to get the previous bundle ourselves...
	return pa.GetProvenance(ctx, prevCommit, ref)
}

func (pa ProvenanceAttestor) CreateSourceProvenance(ctx context.Context, prevAttPath, commit, prevCommit, ref string) (*spb.Statement, error) {
	// Source provenance is based on
	// 1. The current control situation (we assume 'commit' has _just_ occurred).
	// 2. How long the properties have been enforced according to the previous provenance.

	curProv, err := pa.createCurrentProvenance(ctx, commit, prevCommit, ref)
	if err != nil {
		return nil, err
	}

	prevProvStmt, prevProvPred, err := pa.getPrevProvenance(ctx, prevAttPath, prevCommit, ref)
	if err != nil {
		return nil, err
	}

	// No prior provenance found, so we just go with current.
	if prevProvStmt == nil || prevProvPred == nil {
		Debugf("No previous provenance found, have to bootstrap\n")
		return curProv, nil
	}

	curProvPred, err := GetSourceProvPred(curProv)
	if err != nil {
		return nil, err
	}

	// There was prior provenance, so update the Since field for each property
	// to the oldest encountered.
	for i, curControl := range curProvPred.GetControls() {
		prevControl := prevProvPred.GetControl(curControl.GetName())
		// No prior version of this control
		if prevControl == nil {
			continue
		}
		curControl.Since = timestamppb.New(slsa.EarlierTime(curControl.GetSince().AsTime(), prevControl.GetSince().AsTime()))
		// Update the value.
		curProvPred.Controls[i] = curControl
	}

	return addPredToStatement(curProvPred, provenance.SourceProvPredicateType, commit)
}

func (pa ProvenanceAttestor) CreateTagProvenance(ctx context.Context, commit, ref, actor string) (*spb.Statement, error) {
	// 1. Check that the tag hygiene control is still enabled and how long it's been enabled, store it in the prov.
	// 2. Get a VSA associated with this commit, if any.
	// 3. Record the levels and branches covered by that VSA in the provenance.

	controlStatus, err := pa.provider.GetTagControls(ctx)
	if err != nil {
		return nil, err
	}

	// Find the most recent VSA for this commit. Any reference is OK.
	// TODO: in the future get all of them.
	// TODO: we should actually verify this vsa: https://github.com/slsa-framework/source-tool/issues/148
	var tries uint8
	var vsaStatement *spb.Statement
	var vsaPred *v1.VerificationSummary
	for {
		vsaStatement, vsaPred, err = GetVsa(ctx, pa.conn, pa.verifier, commit, vcs.AnyReference)
		if err != nil {
			return nil, fmt.Errorf("error fetching VSA when creating tag provenance %w", err)
		}

		tries++
		if tries >= pa.Options.VsaRetries || vsaPred != nil {
			break
		}
		time.Sleep(time.Duration(tries*5) * time.Second)
	}

	if vsaPred == nil {
		// TODO: If there's not a VSA should we still issue provenance?
		return nil, nil
	}

	vsaRefs, err := GetSourceRefsForCommit(vsaStatement, commit)
	if err != nil {
		return nil, fmt.Errorf("error getting source refs from vsa %w", err)
	}

	curProvPred := provenance.TagProvenancePred{
		RepoUri:   pa.conn.GetRepoUri(),
		Actor:     actor,
		Tag:       ref,
		CreatedOn: timestamppb.Now(),
		Controls:  controlStatus.GetControls(),
		VsaSummaries: []*provenance.VsaSummary{
			{
				SourceRefs:     vsaRefs,
				VerifiedLevels: vsaPred.GetVerifiedLevels(),
			},
		},
	}

	return addPredToStatement(&curProvPred, provenance.TagProvPredicateType, commit)
}
