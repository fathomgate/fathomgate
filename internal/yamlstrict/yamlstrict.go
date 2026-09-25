// SPDX-License-Identifier: FSL-1.1-ALv2

// Package yamlstrict decodes the configuration files fathomgate loads (the
// policy, the inventory, the profiles) the one way they are all decoded:
// strict (an unknown key is an error), one YAML document only, and with
// errors that never quote the file.
//
// goccy/go-yaml's own error text prints the lines around the fault, so a
// policy or inventory file with a device password beside a typo would put
// the password on fathomgate's stderr (security review of PR #171, M1).
// Every error here is reduced to its position and message, and the
// message is then checked against the file: if it still carries a
// fragment of a value (a type error names the value it could not decode),
// only the position is kept.
package yamlstrict

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Unmarshal decodes b into v strictly. More than one YAML document with
// content is an error, since a decoder reads one and ignores the rest.
// So is an empty document before the content (`---` twice before it):
// goccy/go-yaml then parses nothing at all, and the file would load as an
// empty policy or inventory (security review of PR #172, L4).
func Unmarshal(b []byte, v any) error {
	if err := layout(b); err != nil {
		return err
	}
	f, err := parser.ParseBytes(b, 0)
	if err != nil {
		return clean(err, b)
	}
	if n := documents(f.Docs); n > 1 {
		return fmt.Errorf("the file holds %d YAML documents; it must hold one", n)
	}
	if err := yaml.UnmarshalWithOptions(b, v, yaml.Strict()); err != nil {
		return clean(err, b)
	}
	return nil
}

// marker is a document start marker: `---` at column 0, alone or followed
// by a space. A `---` inside a block scalar is indented, so it never
// matches.
var marker = regexp.MustCompile(`^---(?:[ \t].*)?$`)

// layout checks the document structure from the lines themselves, since
// the parser drops content after an empty document. The text is cut at
// every marker; a segment has content when it holds a line that is not
// blank, a comment or an end marker (`...`). Allowed: content only before
// the first marker, or only right after it (a leading `---`). Anything
// else is two documents, or an empty one before the content.
func layout(b []byte) error {
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	segment, contentIn, count := 0, -1, 0
	for _, l := range lines {
		if marker.MatchString(l) {
			segment++
			if strings.TrimSpace(strings.TrimPrefix(l, "---")) != "" && !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(l, "---")), "#") {
				// Content on the marker line itself (`--- {a: 1}`).
				if contentIn != segment {
					contentIn, count = segment, count+1
				}
			}
			continue
		}
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || t == "..." {
			continue
		}
		if contentIn != segment {
			contentIn, count = segment, count+1
		}
	}
	switch {
	case count > 1:
		return fmt.Errorf("the file holds %d YAML documents; it must hold one", count)
	case count == 1 && contentIn > 1:
		return errors.New("the file starts with an empty YAML document (--- with nothing after it); remove the extra ---")
	}
	return nil
}

// documents counts the documents that hold anything: a leading or
// trailing `---` with nothing after it is not a second document.
func documents(docs []*ast.DocumentNode) int {
	n := 0
	for _, d := range docs {
		if d != nil && d.Body != nil {
			n++
		}
	}
	return n
}

// position is goccy/go-yaml's "[line:column]" prefix.
var position = regexp.MustCompile(`^\[\d+:\d+\]`)

// quoted finds quoted strings in a message; they are what a message quotes
// from the file (a key, a value).
var quoted = regexp.MustCompile(`"[^"]*"|'[^']*'`)

// clean returns err as goccy/go-yaml formats it without source lines, and
// keeps only its position when the message quotes anything from the file
// other than a key the file spells as a key (`unknown field "matchh"`).
func clean(err error, b []byte) error {
	msg := yaml.FormatError(err, false, false)
	msg = strings.TrimSpace(strings.SplitN(msg, "\n", 2)[0])
	pos := position.FindString(msg)
	for _, q := range quoted.FindAllString(msg, -1) {
		body := q[1 : len(q)-1]
		if body == "" {
			continue
		}
		if !isKey(b, body) && !vocabulary.MatchString(body) {
			if pos == "" {
				return errors.New("the file is not valid (the value is not shown)")
			}
			return errors.New(pos + " the file is not valid here (the value is not shown)")
		}
	}
	return errors.New(msg)
}

// vocabulary is the shape of an upper-case vocabulary word (a class such
// as WRITE_CONFIG): quoted in a message it names what was misspelt, and a
// secret rarely has that shape (a residual, like the key rule below).
var vocabulary = regexp.MustCompile(`^[A-Z][A-Z_]{2,31}$`)

// isKey reports whether s appears in b as a mapping key (`s:` at the start
// of a line, after indentation or a sequence dash, or inside a flow
// mapping). Only a lower-case snake_case key of at most 32 characters
// qualifies, the shape of every key in the schemas: a misspelt key is
// worth naming, and a secret typed where a key belongs rarely has that
// shape (a residual: one that does is named).
func isKey(b []byte, s string) bool {
	if !keyLike.MatchString(s) {
		return false
	}
	// Compiled per call on purpose: isKey runs only on the error path, once
	// per quoted string in one error message, never while a file decodes.
	re := regexp.MustCompile(`(?m)(^[ \t-]*|[{,][ \t]*)` + regexp.QuoteMeta(s) + `[ \t]*:`)
	return re.Match(b)
}

var keyLike = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
