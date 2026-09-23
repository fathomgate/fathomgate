//go:build tools

// Package tools pins modules that no production package imports yet, so that
// `go mod tidy` keeps them in go.mod. The `tools` build tag keeps this file out
// of every normal build: nothing here is compiled into bin/netguard.
//
// github.com/modelcontextprotocol/go-sdk (v1.7.x) is the transport for
// internal/proxy (M0, T0.2). Delete its import below once internal/proxy
// imports the SDK directly.
package tools

import (
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
)
