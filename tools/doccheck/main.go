// Command doccheck verifies that every named Go function has a Go doc comment.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
)

// main parses each Go source path supplied by the repository documentation check
// and reports an error with the declaration location when its contract is missing.
func main() {
	failed := false
	for _, path := range os.Args[1:] {
		positions := token.NewFileSet()
		file, err := parser.ParseFile(positions, path, nil, parser.ParseComments)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed = true
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if fn.Doc == nil || !strings.HasPrefix(fn.Doc.Text(), fn.Name.Name+" ") {
				fmt.Fprintf(os.Stderr, "%s: document %s\n", positions.Position(fn.Pos()), fn.Name.Name)
				failed = true
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}
