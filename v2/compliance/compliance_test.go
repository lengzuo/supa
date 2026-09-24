// Package compliance checks this SDK against the canonical Supabase client
// capability matrix (https://github.com/supabase/sdk), as published by
// supabase-js in sdk-compliance.yaml.
//
// upstream_features.txt lists every feature id. Each *.yaml file in this
// directory maps feature ids to the Go symbols and tests that implement
// them. TestCompliance fails when a feature is unmapped, mapped twice, or
// mapped to a symbol or test that does not exist.
package compliance

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type feature struct {
	id, file, status, reason string
	symbols, tests           []string
}

func TestCompliance(t *testing.T) {
	upstream := readUpstream(t)
	features := readMappings(t)
	symbols, tests := scanModule(t, "..")

	seen := map[string]string{}
	for _, f := range features {
		if prev, dup := seen[f.id]; dup {
			t.Errorf("%s: feature %s already mapped in %s", f.file, f.id, prev)
			continue
		}
		seen[f.id] = f.file
		if _, ok := upstream[f.id]; !ok {
			t.Errorf("%s: unknown feature id %s (not in upstream_features.txt)", f.file, f.id)
		}
		switch f.status {
		case "implemented":
			if len(f.symbols) == 0 {
				t.Errorf("%s: %s is implemented but lists no symbols", f.file, f.id)
			}
			if len(f.tests) == 0 {
				t.Errorf("%s: %s is implemented but lists no tests", f.file, f.id)
			}
			for _, s := range f.symbols {
				if !symbols[s] {
					t.Errorf("%s: %s: symbol %s does not exist", f.file, f.id, s)
				}
			}
			for _, name := range f.tests {
				if !tests[name] {
					t.Errorf("%s: %s: test %s does not exist", f.file, f.id, name)
				}
			}
		case "not_applicable":
			if len(strings.TrimSpace(f.reason)) < 20 {
				t.Errorf("%s: %s is not_applicable without a concrete reason", f.file, f.id)
			}
		default:
			t.Errorf("%s: %s has invalid status %q", f.file, f.id, f.status)
		}
	}

	var missing []string
	for id := range upstream {
		if _, ok := seen[id]; !ok {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	for _, id := range missing {
		t.Errorf("feature %s is not mapped in any compliance file", id)
	}

	implemented, na := 0, 0
	for _, f := range features {
		if f.status == "implemented" {
			implemented++
		} else {
			na++
		}
	}
	t.Logf("%d upstream features: %d implemented, %d not applicable, %d unmapped",
		len(upstream), implemented, na, len(missing))
}

func readUpstream(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("upstream_features.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, status, _ := strings.Cut(line, " ")
		out[id] = status
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// readMappings parses the restricted YAML used by the mapping files:
//
//	features:
//	  <id>:
//	    status: implemented
//	    symbols: [a, b]
//	    tests: [T1]
//	    reason: "..."
//
// Lists may also be written in block form ("- item" lines).
func readMappings(t *testing.T) []feature {
	t.Helper()
	files, err := filepath.Glob("*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no compliance mapping files found")
	}
	var out []feature
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var cur *feature
		var listKey string
		for n, raw := range strings.Split(string(data), "\n") {
			line := stripComment(raw)
			if strings.TrimSpace(line) == "" || strings.TrimSpace(line) == "features:" {
				continue
			}
			indent := len(line) - len(strings.TrimLeft(line, " "))
			text := strings.TrimSpace(line)
			switch {
			case indent == 2 && strings.HasSuffix(text, ":"):
				out = append(out, feature{id: strings.TrimSuffix(text, ":"), file: name})
				cur = &out[len(out)-1]
				listKey = ""
			case cur != nil && strings.HasPrefix(text, "- "):
				item := unquote(strings.TrimPrefix(text, "- "))
				switch listKey {
				case "symbols":
					cur.symbols = append(cur.symbols, item)
				case "tests":
					cur.tests = append(cur.tests, item)
				default:
					t.Fatalf("%s:%d: list item outside symbols/tests", name, n+1)
				}
			case cur != nil && indent >= 4:
				key, val, ok := strings.Cut(text, ":")
				if !ok {
					t.Fatalf("%s:%d: cannot parse %q", name, n+1, raw)
				}
				val = strings.TrimSpace(val)
				listKey = key
				switch key {
				case "status":
					cur.status = unquote(val)
				case "reason":
					cur.reason = unquote(val)
				case "symbols":
					cur.symbols = append(cur.symbols, inlineList(val)...)
				case "tests":
					cur.tests = append(cur.tests, inlineList(val)...)
				}
			default:
				t.Fatalf("%s:%d: unexpected line %q", name, n+1, raw)
			}
		}
	}
	return out
}

func stripComment(s string) string {
	inQuote := false
	for i, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == '#' && !inQuote && (i == 0 || s[i-1] == ' '):
			return strings.TrimRight(s[:i], " ")
		}
	}
	return s
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func inlineList(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil // block list follows
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = unquote(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// scanModule returns the exported symbols of every package under root,
// keyed "pkg.Name", "pkg.Type.Method" and "pkg.Type.Field", plus the names of all
// Test/Example functions.
func scanModule(t *testing.T, root string) (symbols, tests map[string]bool) {
	t.Helper()
	symbols, tests = map[string]bool{}, map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		pkg := file.Name.Name
		isTest := strings.HasSuffix(path, "_test.go")
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				name := d.Name.Name
				if isTest {
					if strings.HasPrefix(name, "Test") || strings.HasPrefix(name, "Example") || strings.HasPrefix(name, "Benchmark") || strings.HasPrefix(name, "Fuzz") {
						tests[name] = true
					}
					continue
				}
				if !ast.IsExported(name) {
					continue
				}
				if d.Recv == nil {
					symbols[pkg+"."+name] = true
					continue
				}
				if recv := recvName(d.Recv.List[0].Type); recv != "" {
					symbols[pkg+"."+recv+"."+name] = true
				}
			case *ast.GenDecl:
				if isTest {
					continue
				}
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if ast.IsExported(s.Name.Name) {
							symbols[pkg+"."+s.Name.Name] = true
							addInterfaceMethods(symbols, pkg, s)
							addStructFields(symbols, pkg, s)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if ast.IsExported(n.Name) {
								symbols[pkg+"."+n.Name] = true
							}
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return symbols, tests
}

func addInterfaceMethods(symbols map[string]bool, pkg string, s *ast.TypeSpec) {
	it, ok := s.Type.(*ast.InterfaceType)
	if !ok {
		return
	}
	for _, m := range it.Methods.List {
		for _, n := range m.Names {
			symbols[pkg+"."+s.Name.Name+"."+n.Name] = true
		}
	}
}

// addStructFields records exported fields (including promoted embedded
// struct names) as pkg.Type.Field.
func addStructFields(symbols map[string]bool, pkg string, s *ast.TypeSpec) {
	st, ok := s.Type.(*ast.StructType)
	if !ok {
		return
	}
	for _, f := range st.Fields.List {
		if len(f.Names) == 0 {
			if name := recvName(f.Type); ast.IsExported(name) {
				symbols[pkg+"."+s.Name.Name+"."+name] = true
			}
			continue
		}
		for _, n := range f.Names {
			if ast.IsExported(n.Name) {
				symbols[pkg+"."+s.Name.Name+"."+n.Name] = true
			}
		}
	}
}

func recvName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return recvName(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return recvName(e.X)
	case *ast.IndexListExpr:
		return recvName(e.X)
	}
	return ""
}
