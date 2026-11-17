// Copyright 2019 the Kilo authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iptables

import (
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/coreos/go-iptables/iptables"
)

type statusExiter interface {
	ExitStatus() int
}

var _ statusExiter = (*iptables.Error)(nil)
var _ statusExiter = statusError(0)

type statusError int

func (s statusError) Error() string {
	return fmt.Sprintf("%d", s)
}

func (s statusError) ExitStatus() int {
	return int(s)
}

type fakeClient struct {
	calls   uint64
	storage []Rule
}

var _ Client = &fakeClient{}

func (f *fakeClient) InsertUnique(table, chain string, pos int, spec ...string) error {
	atomic.AddUint64(&f.calls, 1)
	exists, err := f.Exists(table, chain, spec...)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	index := pos - 1 // iptables are 1-based
	rule := &rule{table: table, chain: chain, spec: spec}
	prefix := append([]Rule{}, f.storage[:index]...)
	suffix := append([]Rule{}, f.storage[index:]...)
	prefix = append(prefix, rule)
	f.storage = append(prefix, suffix...)
	return nil
}

func (f *fakeClient) AppendUnique(table, chain string, spec ...string) error {
	atomic.AddUint64(&f.calls, 1)
	exists, err := f.Exists(table, chain, spec...)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	f.storage = append(f.storage, &rule{table: table, chain: chain, spec: spec})
	return nil
}

func (f *fakeClient) Delete(table, chain string, spec ...string) error {
	atomic.AddUint64(&f.calls, 1)
	r := &rule{table: table, chain: chain, spec: spec}
	for i := range f.storage {
		if f.storage[i].String() == r.String() {
			copy(f.storage[i:], f.storage[i+1:])
			f.storage[len(f.storage)-1] = nil
			f.storage = f.storage[:len(f.storage)-1]
			break
		}
	}
	return nil
}

func (f *fakeClient) Exists(table, chain string, spec ...string) (bool, error) {
	atomic.AddUint64(&f.calls, 1)
	r := &rule{table: table, chain: chain, spec: spec}
	for i := range f.storage {
		if f.storage[i].String() == r.String() {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeClient) List(table, chain string) ([]string, error) {
	atomic.AddUint64(&f.calls, 1)
	var rs []string
	for i := range f.storage {
		switch r := f.storage[i].(type) {
		case *rule:
			if r.table == table && r.chain == chain {
				rs = append(rs, strings.TrimSpace(strings.TrimPrefix(r.String(), table)))
			}
		}
	}
	return rs, nil
}

func (f *fakeClient) ClearChain(table, name string) error {
	atomic.AddUint64(&f.calls, 1)
	f.flushChainRules(table, name)
	_ = f.DeleteChain(table, name)
	return f.NewChain(table, name)
}

func (f *fakeClient) flushChainRules(table, name string) {
	kept := f.storage[:0]
	for _, item := range f.storage {
		if r, ok := item.(*rule); ok && r.table == table && r.chain == name {
			continue
		}
		kept = append(kept, item)
	}
	for i := len(kept); i < len(f.storage); i++ {
		f.storage[i] = nil
	}
	f.storage = kept
}

func (f *fakeClient) DeleteChain(table, name string) error {
	atomic.AddUint64(&f.calls, 1)
	for i := range f.storage {
		r, ok := f.storage[i].(*rule)
		if !ok {
			continue
		}
		if table == r.table && name == r.chain {
			return fmt.Errorf("cannot delete chain %s; rules exist", name)
		}
	}
	c := &chain{table: table, chain: name}
	for i := range f.storage {
		if f.storage[i].String() == c.String() {
			copy(f.storage[i:], f.storage[i+1:])
			f.storage[len(f.storage)-1] = nil
			f.storage = f.storage[:len(f.storage)-1]
			break
		}
	}
	return nil
}

func (f *fakeClient) NewChain(table, name string) error {
	atomic.AddUint64(&f.calls, 1)
	c := &chain{table: table, chain: name}
	for i := range f.storage {
		if f.storage[i].String() == c.String() {
			return statusError(1)
		}
	}
	f.storage = append(f.storage, c)
	return nil
}

func (f *fakeClient) ListChains(table string) ([]string, error) {
	atomic.AddUint64(&f.calls, 1)
	var cs []string
	for i := range f.storage {
		switch c := f.storage[i].(type) {
		case *chain:
			if c.table == table {
				cs = append(cs, c.chain)
			}
		}
	}
	return cs, nil
}

func (f *fakeClient) RestoreNoFlush(input string) error {
	if input == "" {
		return nil
	}
	atomic.AddUint64(&f.calls, 1)
	var table string
	for _, rawLine := range strings.Split(input, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || line == "COMMIT" {
			continue
		}
		if strings.HasPrefix(line, "*") {
			table = line[1:]
			continue
		}
		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line[1:])
			if len(fields) == 0 {
				continue
			}
			chName := fields[0]
			f.flushChainRules(table, chName)
			exists := false
			c := &chain{table: table, chain: chName}
			for _, item := range f.storage {
				if item.String() == c.String() {
					exists = true
					break
				}
			}
			if !exists {
				f.storage = append(f.storage, c)
			}
			continue
		}
		tokens := splitRestoreArgs(line)
		if len(tokens) < 2 {
			continue
		}
		switch tokens[0] {
		case "-A":
			f.storage = append(f.storage, &rule{table: table, chain: tokens[1], spec: tokens[2:]})
		case "-I":
			pos := 1
			specStart := 2
			if len(tokens) >= 3 {
				if p, err := strconv.Atoi(tokens[2]); err == nil {
					pos = p
					specStart = 3
				}
			}
			idx := pos - 1
			if idx < 0 {
				idx = 0
			}
			if idx > len(f.storage) {
				idx = len(f.storage)
			}
			r := &rule{table: table, chain: tokens[1], spec: tokens[specStart:]}
			f.storage = append(f.storage, nil)
			copy(f.storage[idx+1:], f.storage[idx:])
			f.storage[idx] = r
		case "-D":
			r := &rule{table: table, chain: tokens[1], spec: tokens[2:]}
			found := false
			for i := range f.storage {
				if f.storage[i].String() == r.String() {
					copy(f.storage[i:], f.storage[i+1:])
					f.storage[len(f.storage)-1] = nil
					f.storage = f.storage[:len(f.storage)-1]
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("bad rule (does a matching rule exist in chain %s?): %s", tokens[1], r.String())
			}
		case "-F":
			f.flushChainRules(table, tokens[1])
		case "-X":
			for i := range f.storage {
				if r, ok := f.storage[i].(*rule); ok && r.table == table && r.chain == tokens[1] {
					return fmt.Errorf("cannot delete chain %s; rules exist", tokens[1])
				}
			}
			c := &chain{table: table, chain: tokens[1]}
			for i := range f.storage {
				if f.storage[i].String() == c.String() {
					copy(f.storage[i:], f.storage[i+1:])
					f.storage[len(f.storage)-1] = nil
					f.storage = f.storage[:len(f.storage)-1]
					break
				}
			}
		}
	}
	return nil
}

func splitRestoreArgs(line string) []string {
	var args []string
	var cur strings.Builder
	inQuotes := false
	for i := range len(line) {
		ch := line[i]
		switch {
		case ch == '"':
			inQuotes = !inQuotes
		case (ch == ' ' || ch == '\t') && !inQuotes:
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	return args
}
