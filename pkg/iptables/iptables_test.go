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
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

var appendRules = []Rule{
	NewIPv4Rule("filter", "FORWARD", "-s", "10.4.0.0/16", "-j", "ACCEPT"),
	NewIPv4Rule("filter", "FORWARD", "-d", "10.4.0.0/16", "-j", "ACCEPT"),
}

var prependRules = []Rule{
	NewIPv4Rule("filter", "FORWARD", "-s", "10.5.0.0/16", "-j", "DROP"),
	NewIPv4Rule("filter", "FORWARD", "-s", "10.6.0.0/16", "-j", "DROP"),
}

func TestSet(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sets       []RuleSet
		appendOut  []Rule
		prependOut []Rule
		storageOut []Rule
		actions    []func(Client) error
	}{
		{
			name: "empty",
		},
		{
			name: "single",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0]}},
			},
			appendOut:  []Rule{appendRules[0]},
			storageOut: []Rule{appendRules[0]},
		},
		{
			name: "two rules",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0], appendRules[1]}},
			},
			appendOut:  []Rule{appendRules[0], appendRules[1]},
			storageOut: []Rule{appendRules[0], appendRules[1]},
		},
		{
			name: "multiple",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0], appendRules[1]}},
				{appendRules: []Rule{appendRules[1]}},
			},
			appendOut:  []Rule{appendRules[1]},
			storageOut: []Rule{appendRules[1]},
		},
		{
			name: "re-add",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0], appendRules[1]}},
			},
			appendOut:  []Rule{appendRules[0], appendRules[1]},
			storageOut: []Rule{appendRules[0], appendRules[1]},
			actions: []func(c Client) error{
				func(c Client) error {
					return appendRules[0].Delete(c)
				},
				func(c Client) error {
					return appendRules[1].Delete(c)
				},
			},
		},
		{
			name: "order",
			sets: []RuleSet{
				{appendRules: []Rule{appendRules[0], appendRules[1]}},
			},
			appendOut:  []Rule{appendRules[0], appendRules[1]},
			storageOut: []Rule{appendRules[0], appendRules[1]},
			actions: []func(c Client) error{
				func(c Client) error {
					return appendRules[0].Delete(c)
				},
			},
		},
		{
			name: "append and prepend",
			sets: []RuleSet{
				{
					prependRules: []Rule{prependRules[0], prependRules[1]},
					appendRules:  []Rule{appendRules[0], appendRules[1]},
				},
			},
			appendOut:  []Rule{appendRules[0], appendRules[1]},
			prependOut: []Rule{prependRules[0], prependRules[1]},
			storageOut: []Rule{prependRules[1], prependRules[0], appendRules[0], appendRules[1]},
		},
	} {
		client := &fakeClient{}
		controller, err := New(WithClients(client, client))
		if err != nil {
			t.Fatalf("test case %q: got unexpected error instantiating controller: %v", tc.name, err)
		}
		for i := range tc.sets {
			if err := controller.Set(tc.sets[i]); err != nil {
				t.Fatalf("test case %q: got unexpected error setting rule set %d: %v", tc.name, i, err)
			}
		}
		for i, f := range tc.actions {
			if err := f(controller.v4); err != nil {
				t.Fatalf("test case %q action %d: got unexpected error %v", tc.name, i, err)
			}
		}
		if err := controller.reconcile(); err != nil {
			t.Fatalf("test case %q: got unexpected error %v", tc.name, err)
		}
		if len(tc.storageOut) != len(client.storage) {
			t.Errorf("test case %q: expected %d rules in storage, got %d", tc.name, len(tc.storageOut), len(client.storage))
		} else {
			for i := range tc.storageOut {
				if tc.storageOut[i].String() != client.storage[i].String() {
					t.Errorf("test case %q: expected rule %d in storage to be equal: expected %v, got %v", tc.name, i, tc.storageOut[i], client.storage[i])
				}
			}
		}
		if len(tc.appendOut) != len(controller.appendRules) {
			t.Errorf("test case %q: expected %d appendRules in controller, got %d", tc.name, len(tc.appendOut), len(controller.appendRules))
		} else {
			for i := range tc.appendOut {
				if tc.appendOut[i].String() != controller.appendRules[i].String() {
					t.Errorf("test case %q: expected appendRule %d in controller to be equal: expected %v, got %v", tc.name, i, tc.appendOut[i], controller.appendRules[i])
				}
			}
		}
		if len(tc.prependOut) != len(controller.prependRules) {
			t.Errorf("test case %q: expected %d prependRules in controller, got %d", tc.name, len(tc.prependOut), len(controller.prependRules))
		} else {
			for i := range tc.prependOut {
				if tc.prependOut[i].String() != controller.prependRules[i].String() {
					t.Errorf("test case %q: expected prependRule %d in controller to be equal: expected %v, got %v", tc.name, i, tc.prependOut[i], controller.prependRules[i])
				}
			}
		}
	}
}

func TestCleanUp(t *testing.T) {
	for _, tc := range []struct {
		name         string
		appendRules  []Rule
		prependRules []Rule
	}{
		{
			name:        "empty",
			appendRules: nil,
		},
		{
			name:        "single append",
			appendRules: []Rule{appendRules[0]},
		},
		{
			name:        "multiple append",
			appendRules: []Rule{appendRules[0], appendRules[1]},
		},
		{
			name:         "multiple append and prepend",
			appendRules:  []Rule{appendRules[0], appendRules[1]},
			prependRules: []Rule{prependRules[0], prependRules[1]},
		},
	} {
		client := &fakeClient{}
		controller, err := New(WithClients(client, client))
		if err != nil {
			t.Fatalf("test case %q: got unexpected error instantiating controller: %v", tc.name, err)
		}
		ruleSet := RuleSet{appendRules: tc.appendRules, prependRules: tc.prependRules}
		if err := controller.Set(ruleSet); err != nil {
			t.Fatalf("test case %q: Set should not fail: %v", tc.name, err)
		}
		if len(client.storage) != len(tc.appendRules)+len(tc.prependRules) {
			t.Errorf("test case %q: expected %d rules in storage, got %d rules", tc.name, len(ruleSet.appendRules)+len(ruleSet.prependRules), len(client.storage))
		}
		if err := controller.CleanUp(); err != nil {
			t.Errorf("test case %q: got unexpected error: %v", tc.name, err)
		}
		if len(client.storage) != 0 {
			t.Errorf("test case %q: expected storage to be empty, got %d rules", tc.name, len(client.storage))
		}
	}
}

func TestReconcile(t *testing.T) {
	for _, tc := range []struct {
		name         string
		appendRules  []Rule
		prependRules []Rule
		storageOut   []Rule
	}{
		{
			name:         "append and prepend rules",
			appendRules:  []Rule{appendRules[0], appendRules[1]},
			prependRules: []Rule{prependRules[0], prependRules[1]},
			storageOut:   []Rule{prependRules[1], prependRules[0], appendRules[0], appendRules[1]},
		},
	} {
		client := &fakeClient{}
		controller, err := New(WithClients(client, client))
		if err != nil {
			t.Fatalf("test case %q: got unexpected error instantiating controller: %v", tc.name, err)
		}
		controller.appendRules = tc.appendRules
		controller.prependRules = tc.prependRules

		err = controller.reconcile()
		if err != nil {
			t.Fatalf("test case %q: unexpected error during reconcile: %v", tc.name, err)
		}

		if len(tc.storageOut) != len(client.storage) {
			t.Errorf("test case %q: expected %d rules in storage, got %d", tc.name, len(tc.storageOut), len(client.storage))
		} else {
			for i := range tc.storageOut {
				if tc.storageOut[i].String() != client.storage[i].String() {
					t.Errorf("test case %q: expected rule %d in storage to be equal: expected %v, got %v", tc.name, i, tc.storageOut[i], client.storage[i])
				}
			}
		}
	}
}

func TestBatchRestoreKiloNAT(t *testing.T) {
	v4 := &fakeClient{}
	v6 := &fakeClient{}
	controller, err := New(WithClients(v4, v6))
	if err != nil {
		t.Fatalf("unexpected error instantiating controller: %v", err)
	}

	// Pre-populate an unrelated external POSTROUTING rule that must never be flushed.
	externalRule := NewIPv4Rule("nat", "POSTROUTING", "-s", "172.17.0.0/16", "-j", "MASQUERADE")
	if err := externalRule.Append(v4); err != nil {
		t.Fatalf("failed to seed external rule: %v", err)
	}

	buildNatSet := func(nodeCount int) RuleSet {
		rs := RuleSet{}
		rs.AddToAppend(NewIPv4Chain("nat", "KILO-NAT"))
		rs.AddToPrepend(NewIPv4Rule("nat", "POSTROUTING", "!", "-s", "192.168.102.0/23", "-d", "192.168.102.0/23", "-m", "comment", "--comment", "Kilo: jump to NAT chain", "-j", "KILO-NAT"))
		for i := range nodeCount {
			hi := i / 256
			lo := i % 256
			rs.AddToPrepend(NewIPv4Rule("nat", "KILO-NAT", "-d", fmt.Sprintf("100.66.%d.%d/32", hi, lo), "-m", "comment", "--comment", "Kilo: do not NAT packets destined for WireGuared IPs", "-j", "RETURN"))
			rs.AddToPrepend(NewIPv4Rule("nat", "KILO-NAT", "-d", fmt.Sprintf("10.246.%d.0/24", i%256), "-m", "comment", "--comment", "Kilo: do not NAT packets destined for known IPs", "-j", "RETURN"))
		}
		rs.AddToAppend(NewIPv4Rule("nat", "KILO-NAT", "-m", "comment", "--comment", "Kilo: NAT remaining packets", "-j", "MASQUERADE"))
		return rs
	}

	v4.calls = 0
	set200 := buildNatSet(200)
	if err := controller.Set(set200); err != nil {
		t.Fatalf("Set(200 nodes) failed: %v", err)
	}
	// Expect 1 List(POSTROUTING) + 1 RestoreNoFlush = 2 calls, instead of >800 per-rule calls.
	if v4.calls > 2 {
		t.Fatalf("expected <= 2 iptables invocations for 400+ KILO-NAT rules, got %d", v4.calls)
	}

	// Idempotent Set must do 0 client calls.
	v4.calls = 0
	if err := controller.Set(set200); err != nil {
		t.Fatalf("idempotent Set(200 nodes) failed: %v", err)
	}
	if v4.calls != 0 {
		t.Fatalf("expected 0 calls on unchanged RuleSet, got %d", v4.calls)
	}

	// Scaling from 200 to 205 nodes should rebuild KILO-NAT in a single RestoreNoFlush call (POSTROUTING unchanged).
	v4.calls = 0
	set205 := buildNatSet(205)
	if err := controller.Set(set205); err != nil {
		t.Fatalf("Set(205 nodes) failed: %v", err)
	}
	if v4.calls != 1 {
		t.Fatalf("expected exactly 1 RestoreNoFlush call when updating KILO-NAT, got %d", v4.calls)
	}

	// External POSTROUTING rule must still be intact.
	foundExternal := false
	for _, r := range v4.storage {
		if r.String() == externalRule.String() {
			foundExternal = true
			break
		}
	}
	if !foundExternal {
		t.Fatalf("external POSTROUTING rule was lost during KILO-NAT RestoreNoFlush")
	}

	// CleanUp must remove KILO-NAT chain and Kilo's POSTROUTING jump while keeping external POSTROUTING rule.
	if err := controller.CleanUp(); err != nil {
		t.Fatalf("CleanUp failed: %v", err)
	}
	if len(v4.storage) != 1 || v4.storage[0].String() != externalRule.String() {
		t.Fatalf("expected only external rule after CleanUp, got %v", v4.storage)
	}
}

func TestLiveRestoreClient(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live iptables-restore test requires linux")
	}
	if _, err := exec.LookPath("iptables-restore"); err != nil {
		t.Skip("iptables-restore binary not installed")
	}
	if err := exec.Command("iptables", "-t", "nat", "-S").Run(); err != nil {
		t.Skipf("insufficient privileges for live iptables test: %v", err)
	}

	c, err := New(WithClients(nil, &fakeClient{}))
	if err != nil {
		t.Fatalf("New controller failed: %v", err)
	}
	defer func() { _ = c.CleanUp() }()

	rs := RuleSet{}
	rs.AddToAppend(NewIPv4Chain("nat", "KILO-TEST-NAT"))
	rs.AddToPrepend(NewIPv4Rule("nat", "POSTROUTING", "!", "-s", "192.168.102.0/23", "-d", "192.168.102.0/23", "-m", "comment", "--comment", "Kilo: jump to NAT chain", "-j", "KILO-TEST-NAT"))
	rs.AddToPrepend(NewIPv4Rule("nat", "KILO-TEST-NAT", "-d", "100.66.0.1/32", "-m", "comment", "--comment", "Kilo: do not NAT packets destined for WireGuared IPs", "-j", "RETURN"))
	rs.AddToAppend(NewIPv4Rule("nat", "KILO-TEST-NAT", "-m", "comment", "--comment", "Kilo: NAT remaining packets", "-j", "MASQUERADE"))

	if err := c.Set(rs); err != nil {
		t.Fatalf("live Set failed: %v", err)
	}
	if err := c.reconcile(); err != nil {
		t.Fatalf("live reconcile failed: %v", err)
	}
	out, err := exec.Command("iptables", "-t", "nat", "-S", "KILO-TEST-NAT").CombinedOutput()
	if err != nil {
		t.Fatalf("listing KILO-TEST-NAT failed: %v (%s)", err, string(out))
	}
	if !strings.Contains(string(out), "100.66.0.1/32") || !strings.Contains(string(out), "MASQUERADE") {
		t.Fatalf("unexpected KILO-TEST-NAT contents:\n%s", string(out))
	}
	if err := c.CleanUp(); err != nil {
		t.Fatalf("live CleanUp failed: %v", err)
	}
	if err := exec.Command("iptables", "-t", "nat", "-S", "KILO-TEST-NAT").Run(); err == nil {
		t.Fatalf("expected KILO-TEST-NAT chain to be deleted after CleanUp")
	}
}
