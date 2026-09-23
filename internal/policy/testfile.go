package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/joshscott13/netguard/internal/classify"
)

// TestFile is the schema of a *.test.yaml file consumed by
// `netguard policy test`. It lets contributors assert policy behaviour
// without a Go toolchain.
//
//	policy: prod-approval.yaml        # relative to the test file
//	cases:
//	  - name: core write is held
//	    request:
//	      server: junos-mcp-server
//	      tool: load_and_commit_config
//	      class: WRITE_CONFIG
//	      targets: [{name: core-rtr-01, role: core}]
//	    expect: {effect: hold, rule: prod-core-needs-approval}
type TestFile struct {
	// Policy is the policy path, relative to the test file's directory.
	Policy string `yaml:"policy"`
	// Cases are the assertions.
	Cases []TestCase `yaml:"cases"`
}

// TestCase is one (request, expected decision) pair.
type TestCase struct {
	Name    string      `yaml:"name"`
	Request CaseRequest `yaml:"request"`
	Expect  Expect      `yaml:"expect"`
}

// CaseRequest mirrors Request but lets `known` default to true, since most
// test targets are meant to exist in inventory.
type CaseRequest struct {
	Server  string         `yaml:"server,omitempty"`
	Tool    string         `yaml:"tool,omitempty"`
	Class   classify.Class `yaml:"class"`
	Targets []CaseTarget   `yaml:"targets,omitempty"`
	Session Session        `yaml:"session,omitempty"`
}

// CaseTarget mirrors Target with an optional `known`.
type CaseTarget struct {
	Name  string   `yaml:"name"`
	Role  string   `yaml:"role,omitempty"`
	Tags  []string `yaml:"tags,omitempty"`
	Site  string   `yaml:"site,omitempty"`
	Known *bool    `yaml:"known,omitempty"`
}

// Expect is the expected decision. Rule and Obligations are optional.
type Expect struct {
	Effect      Effect   `yaml:"effect"`
	Rule        string   `yaml:"rule,omitempty"`
	Obligations []string `yaml:"obligations,omitempty"`
}

// CaseResult is the outcome of one case.
type CaseResult struct {
	Name     string
	Pass     bool
	Expected Expect
	Got      Decision
	// Message explains a failure in one line.
	Message string
}

// ToRequest converts the test form into a Request.
func (c CaseRequest) ToRequest() Request {
	r := Request{Server: c.Server, Tool: c.Tool, Class: c.Class, Session: c.Session}
	for _, t := range c.Targets {
		known := true
		if t.Known != nil {
			known = *t.Known
		}
		r.Targets = append(r.Targets, Target{Name: t.Name, Role: t.Role, Tags: t.Tags, Site: t.Site, Known: known})
	}
	return r
}

// ParseTestFile decodes a test file.
func ParseTestFile(b []byte) (*TestFile, error) {
	var tf TestFile
	if err := yaml.UnmarshalWithOptions(b, &tf, yaml.Strict()); err != nil {
		return nil, fmt.Errorf("policy: parse test file: %w", err)
	}
	if strings.TrimSpace(tf.Policy) == "" {
		return nil, fmt.Errorf("policy: test file: policy is required")
	}
	if len(tf.Cases) == 0 {
		return nil, fmt.Errorf("policy: test file: cases is empty")
	}
	for i, c := range tf.Cases {
		if strings.TrimSpace(c.Name) == "" {
			return nil, fmt.Errorf("policy: test file: case %d has no name", i+1)
		}
		if !c.Expect.Effect.Valid() {
			return nil, fmt.Errorf("policy: test file: case %q: bad expected effect %q", c.Name, c.Expect.Effect)
		}
		if !c.Request.Class.Valid() {
			return nil, fmt.Errorf("policy: test file: case %q: bad class %q", c.Name, c.Request.Class)
		}
	}
	return &tf, nil
}

// RunTestFile loads the test file and its policy, evaluates every case and
// returns one result per case. The error is non-nil only when the files
// themselves cannot be read or parsed; failing cases are reported in the
// results.
func RunTestFile(testPath string) ([]CaseResult, error) {
	b, err := os.ReadFile(testPath)
	if err != nil {
		return nil, fmt.Errorf("policy: read test file: %w", err)
	}
	tf, err := ParseTestFile(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", testPath, err)
	}
	policyPath := tf.Policy
	if !filepath.IsAbs(policyPath) {
		policyPath = filepath.Join(filepath.Dir(testPath), policyPath)
	}
	p, err := Load(policyPath)
	if err != nil {
		return nil, err
	}
	return RunCases(p, tf.Cases), nil
}

// RunCases evaluates cases against an already-loaded policy.
func RunCases(p *Policy, cases []TestCase) []CaseResult {
	results := make([]CaseResult, 0, len(cases))
	for _, c := range cases {
		got := Evaluate(p, c.Request.ToRequest())
		res := CaseResult{Name: c.Name, Expected: c.Expect, Got: got, Pass: true}
		switch {
		case got.Effect != c.Expect.Effect:
			res.Pass = false
			res.Message = fmt.Sprintf("effect %s (rule %s), want %s", got.Effect, got.RuleID, c.Expect.Effect)
		case c.Expect.Rule != "" && got.RuleID != c.Expect.Rule:
			res.Pass = false
			res.Message = fmt.Sprintf("rule %s, want %s", got.RuleID, c.Expect.Rule)
		case c.Expect.Obligations != nil && !sameSet(got.Obligations, c.Expect.Obligations):
			res.Pass = false
			res.Message = fmt.Sprintf("obligations %v, want %v", got.Obligations, c.Expect.Obligations)
		}
		results = append(results, res)
	}
	return results
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
