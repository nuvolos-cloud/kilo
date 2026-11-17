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
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

const ipv6ModuleDisabledPath = "/sys/module/ipv6/parameters/disable"

func ipv6Disabled() (bool, error) {
	f, err := os.Open(ipv6ModuleDisabledPath)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	disabled := make([]byte, 1)
	if _, err = io.ReadFull(f, disabled); err != nil {
		return false, err
	}
	return disabled[0] == '1', nil
}

// Protocol represents an IP protocol.
type Protocol byte

type RuleSet struct {
	appendRules  []Rule // Rules to append to the chain - order matters.
	prependRules []Rule // Rules to prepend to the chain - order does not matter.
}

const (
	// ProtocolIPv4 represents the IPv4 protocol.
	ProtocolIPv4 Protocol = iota
	// ProtocolIPv6 represents the IPv6 protocol.
	ProtocolIPv6
)

func (rs *RuleSet) AddToAppend(rule Rule) {
	rs.appendRules = append(rs.appendRules, rule)
}

func (rs *RuleSet) AddToPrepend(rule Rule) {
	rs.prependRules = append(rs.prependRules, rule)
}

func (rs *RuleSet) AppendRuleSet(other RuleSet) RuleSet {
	return RuleSet{
		appendRules:  append(rs.appendRules, other.appendRules...),
		prependRules: append(rs.prependRules, other.prependRules...),
	}
}

// GetProtocol will return a protocol from the length of an IP address.
func GetProtocol(ip net.IP) Protocol {
	if len(ip) == net.IPv4len || ip.To4() != nil {
		return ProtocolIPv4
	}
	return ProtocolIPv6
}

// Client represents any type that can administer iptables rules.
type Client interface {
	AppendUnique(table string, chain string, rule ...string) error
	InsertUnique(table, chain string, pos int, rule ...string) error
	Delete(table string, chain string, rule ...string) error
	Exists(table string, chain string, rule ...string) (bool, error)
	List(table string, chain string) ([]string, error)
	ClearChain(table string, chain string) error
	DeleteChain(table string, chain string) error
	NewChain(table string, chain string) error
	ListChains(table string) ([]string, error)
	RestoreNoFlush(input string) error
}

// Rule is an interface for interacting with iptables objects.
type Rule interface {
	Append(Client) error
	Prepend(Client) error
	Delete(Client) error
	Exists(Client) (bool, error)
	String() string
	Proto() Protocol
}

// rule represents an iptables rule.
type rule struct {
	table string
	chain string
	spec  []string
	proto Protocol
}

// NewRule creates a new iptables or ip6tables rule in the given table and chain
// depending on the given protocol.
func NewRule(proto Protocol, table, chain string, spec ...string) Rule {
	return &rule{table, chain, spec, proto}
}

// NewIPv4Rule creates a new iptables rule in the given table and chain.
func NewIPv4Rule(table, chain string, spec ...string) Rule {
	return &rule{table, chain, spec, ProtocolIPv4}
}

// NewIPv6Rule creates a new ip6tables rule in the given table and chain.
func NewIPv6Rule(table, chain string, spec ...string) Rule {
	return &rule{table, chain, spec, ProtocolIPv6}
}

func (r *rule) Prepend(client Client) error {
	if err := client.InsertUnique(r.table, r.chain, 1, r.spec...); err != nil {
		return fmt.Errorf("failed to add iptables rule: %v", err)
	}
	return nil
}

func (r *rule) Append(client Client) error {
	if err := client.AppendUnique(r.table, r.chain, r.spec...); err != nil {
		return fmt.Errorf("failed to add iptables rule: %v", err)
	}
	return nil
}

func (r *rule) Delete(client Client) error {
	// Ignore the returned error as an error likely means
	// that the rule doesn't exist, which is fine.
	_ = client.Delete(r.table, r.chain, r.spec...)
	return nil
}

func (r *rule) Exists(client Client) (bool, error) {
	return client.Exists(r.table, r.chain, r.spec...)
}

func (r *rule) String() string {
	if r == nil {
		return ""
	}
	return r.table + " " + r.specString("-A")
}

func (r *rule) specString(op string) string {
	if r == nil {
		return ""
	}
	spec := op + " " + r.chain
	for i, s := range r.spec {
		spec += " "
		// If this is the content of a comment, wrap the value in quotes.
		if i > 0 && r.spec[i-1] == "--comment" {
			spec += `"` + s + `"`
		} else {
			spec += s
		}
	}
	return spec
}

func (r *rule) Proto() Protocol {
	return r.proto
}

// chain represents an iptables chain.
type chain struct {
	table string
	chain string
	proto Protocol
}

// NewIPv4Chain creates a new iptables chain in the given table.
func NewIPv4Chain(table, name string) Rule {
	return &chain{table, name, ProtocolIPv4}
}

// NewIPv6Chain creates a new ip6tables chain in the given table.
func NewIPv6Chain(table, name string) Rule {
	return &chain{table, name, ProtocolIPv6}
}

func (c *chain) Prepend(client Client) error {
	return c.Append(client)
}

func (c *chain) Append(client Client) error {
	// Note: `ClearChain` creates a chain if it does not exist.
	if err := client.ClearChain(c.table, c.chain); err != nil {
		return fmt.Errorf("failed to add iptables chain: %v", err)
	}
	return nil
}

func (c *chain) Delete(client Client) error {
	// The chain must be empty before it can be deleted.
	if err := client.ClearChain(c.table, c.chain); err != nil {
		return fmt.Errorf("failed to clear iptables chain: %v", err)
	}
	// Ignore the returned error as an error likely means
	// that the chain doesn't exist, which is fine.
	_ = client.DeleteChain(c.table, c.chain)
	return nil
}

func (c *chain) Exists(client Client) (bool, error) {
	// The code for "chain already exists".
	existsErr := 1
	err := client.NewChain(c.table, c.chain)
	se, ok := err.(statusExiter)
	switch {
	case err == nil:
		// If there was no error adding a new chain, then it did not exist.
		// Delete it and return false.
		_ = client.DeleteChain(c.table, c.chain)
		return false, nil
	case ok && se.ExitStatus() == existsErr:
		return true, nil
	default:
		return false, err
	}
}

func (c *chain) String() string {
	if c == nil {
		return ""
	}
	return chainToString(c.table, c.chain)
}

func (c *chain) Proto() Protocol {
	return c.proto
}

func chainToString(table, chain string) string {
	return fmt.Sprintf("%s -N %s", table, chain)
}

// restoreClient wraps a go-iptables client with atomic iptables-restore --noflush support.
type restoreClient struct {
	*iptables.IPTables
	restorePath string
	hasWait     bool
}

func newRestoreClient(proto iptables.Protocol) (Client, error) {
	ipt, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return nil, err
	}
	cmd := "iptables-restore"
	if proto == iptables.ProtocolIPv6 {
		cmd = "ip6tables-restore"
	}
	path, err := exec.LookPath(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to find %s: %v", cmd, err)
	}
	v1, v2, v3 := ipt.GetIptablesVersion()
	hasWait := v1 > 1 || (v1 == 1 && v2 > 6) || (v1 == 1 && v2 == 6 && v3 >= 2)
	return &restoreClient{
		IPTables:    ipt,
		restorePath: path,
		hasWait:     hasWait,
	}, nil
}

func (r *restoreClient) RestoreNoFlush(input string) error {
	if input == "" {
		return nil
	}
	args := []string{"--noflush"}
	if r.hasWait {
		args = append(args, "--wait")
	}
	var stderr bytes.Buffer
	cmd := exec.Command(r.restorePath, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s %s: %v: %s", r.restorePath, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// Controller is able to reconcile a given set of iptables rules.
type Controller struct {
	v4           Client
	v6           Client
	errors       chan error
	logger       log.Logger
	resyncPeriod time.Duration
	registerer   prometheus.Registerer

	sync.Mutex
	appendRules  []Rule
	prependRules []Rule
	subscribed   bool
}

// ControllerOption modifies the controller's configuration.
type ControllerOption func(h *Controller)

// WithLogger adds a logger to the controller.
func WithLogger(logger log.Logger) ControllerOption {
	return func(c *Controller) {
		c.logger = logger
	}
}

// WithResyncPeriod modifies how often the controller reconciles.
func WithResyncPeriod(resyncPeriod time.Duration) ControllerOption {
	return func(c *Controller) {
		c.resyncPeriod = resyncPeriod
	}
}

// WithClients adds iptables clients to the controller.
func WithClients(v4, v6 Client) ControllerOption {
	return func(c *Controller) {
		c.v4 = v4
		c.v6 = v6
	}
}

func WithRegisterer(registerer prometheus.Registerer) ControllerOption {
	return func(c *Controller) {
		c.registerer = registerer
	}
}

// New generates a new iptables rules controller.
// If no options are given, IPv4 and IPv6 clients
// will be instantiated using the regular iptables backend.
func New(opts ...ControllerOption) (*Controller, error) {
	c := &Controller{
		errors: make(chan error),
		logger: log.NewNopLogger(),
	}
	for _, o := range opts {
		o(c)
	}
	if c.v4 == nil {
		v4, err := newRestoreClient(iptables.ProtocolIPv4)
		if err != nil {
			return nil, fmt.Errorf("failed to create iptables IPv4 client: %v", err)
		}
		c.v4 = wrapWithMetrics(v4, "IPv4", c.registerer)
	}
	if c.v6 == nil {
		disabled, err := ipv6Disabled()
		if err != nil {
			return nil, fmt.Errorf("failed to check IPv6 status: %v", err)
		}
		if disabled {
			_ = level.Info(c.logger).Log("msg", "IPv6 is disabled in the kernel; disabling the IPv6 iptables controller")
			c.v6 = &fakeClient{}
		} else {
			v6, err := newRestoreClient(iptables.ProtocolIPv6)
			if err != nil {
				return nil, fmt.Errorf("failed to create iptables IPv6 client: %v", err)
			}
			c.v6 = wrapWithMetrics(v6, "IPv6", c.registerer)
		}
	}
	return c, nil
}

// Run watches for changes to iptables rules and reconciles
// the rules against the desired state.
func (c *Controller) Run(stop <-chan struct{}) (<-chan error, error) {
	c.Lock()
	if c.subscribed {
		c.Unlock()
		return c.errors, nil
	}
	// Ensure a given instance only subscribes once.
	c.subscribed = true
	c.Unlock()
	go func() {
		t := time.NewTimer(c.resyncPeriod)
		defer close(c.errors)
		for {
			select {
			case <-t.C:
				if err := c.reconcile(); err != nil {
					nonBlockingSend(c.errors, fmt.Errorf("failed to reconcile rules: %v", err))
				}
				t.Reset(c.resyncPeriod)
			case <-stop:
				return
			}
		}
	}()
	return c.errors, nil
}

// reconcile makes sure that every rule is still in the backend.
// It does not ensure that the order in the backend is correct.
// If any rule is missing, that rule and all following rules are
// re-added.
func (c *Controller) reconcile() error {
	c.Lock()
	defer c.Unlock()
	var rc ruleCache
	for _, proto := range []Protocol{ProtocolIPv4, ProtocolIPv6} {
		if err := c.reconcileProto(proto, &rc); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) reconcileProto(proto Protocol, rc *ruleCache) error {
	owned := ownedChainsForProto(proto, c.appendRules, c.prependRules)

	firstMissingAppend := -1
	var missingAppendTables map[string]struct{}
	for i, r := range c.appendRules {
		if r.Proto() != proto {
			continue
		}
		ok, err := rc.exists(c.client(proto), r)
		if err != nil {
			return fmt.Errorf("failed to check if rule exists: %v", err)
		}
		if !ok {
			if firstMissingAppend == -1 {
				firstMissingAppend = i
				missingAppendTables = make(map[string]struct{})
			}
		}
		if firstMissingAppend != -1 {
			missingAppendTables[ruleTable(r)] = struct{}{}
		}
	}

	rebuildTables := make(map[string]struct{})
	for t := range missingAppendTables {
		if len(owned[t]) > 0 {
			rebuildTables[t] = struct{}{}
		}
	}

	var missingPrepends []*rule
	for _, r := range c.prependRules {
		if r.Proto() != proto {
			continue
		}
		ok, err := rc.exists(c.client(proto), r)
		if err != nil {
			return fmt.Errorf("failed to check if rule exists: %v", err)
		}
		if !ok {
			ru, isRule := r.(*rule)
			if !isRule {
				continue
			}
			if owned[ru.table][ru.chain] {
				rebuildTables[ru.table] = struct{}{}
			} else {
				missingPrepends = append(missingPrepends, ru)
			}
		}
	}

	if firstMissingAppend == -1 && len(rebuildTables) == 0 && len(missingPrepends) == 0 {
		return nil
	}

	tables := make(map[string]*tableBatch)
	getBatch := func(table string) *tableBatch {
		b, ok := tables[table]
		if !ok {
			b = &tableBatch{flushedChains: make(map[string]bool)}
			tables[table] = b
		}
		return b
	}

	// Atomically rebuild owned chains in affected tables via :CHAIN - [0:0].
	for table := range rebuildTables {
		b := getBatch(table)
		for ch := range owned[table] {
			b.flushedChains[ch] = true
		}
		for _, r := range c.prependRules {
			if r.Proto() != proto {
				continue
			}
			if ru, ok := r.(*rule); ok && ru.table == table && owned[table][ru.chain] {
				b.lines = append(b.lines, insertSpecString(ru, 1))
			}
		}
		for _, r := range c.appendRules {
			if r.Proto() != proto {
				continue
			}
			if ru, ok := r.(*rule); ok && ru.table == table && owned[table][ru.chain] {
				b.lines = append(b.lines, ru.specString("-A"))
			}
		}
	}

	// Re-prepend missing rules on non-owned chains (e.g. POSTROUTING, FORWARD).
	for _, ru := range missingPrepends {
		b := getBatch(ru.table)
		b.lines = append(b.lines, insertSpecString(ru, 1))
	}

	// Re-apply missing append rules from firstMissingAppend on non-owned chains (e.g. INPUT).
	if firstMissingAppend != -1 {
		_ = level.Info(c.logger).Log("msg", fmt.Sprintf("applying %d iptables rules", len(c.appendRules)-firstMissingAppend))
		for j := firstMissingAppend; j < len(c.appendRules); j++ {
			r := c.appendRules[j]
			if r.Proto() != proto {
				continue
			}
			if ch, ok := r.(*chain); ok {
				if _, rebuilt := rebuildTables[ch.table]; !rebuilt {
					b := getBatch(ch.table)
					b.flushedChains[ch.chain] = true
				}
				continue
			}
			ru := r.(*rule)
			if owned[ru.table][ru.chain] {
				continue
			}
			exists, err := rc.exists(c.client(proto), ru)
			if err != nil {
				return fmt.Errorf("failed to check if rule exists: %v", err)
			}
			b := getBatch(ru.table)
			if exists {
				b.lines = append(b.lines, ru.specString("-D"))
			}
			b.lines = append(b.lines, ru.specString("-A"))
		}
	}

	return c.restoreTables(proto, tables)
}

// Set idempotently overwrites any iptables rules previously defined
// for the controller with the given set of rules.
func (c *Controller) Set(rules RuleSet) error {
	c.Lock()
	defer c.Unlock()
	if rulesEqual(c.appendRules, rules.appendRules) && rulesEqualUnordered(c.prependRules, rules.prependRules) {
		return nil
	}
	for _, proto := range []Protocol{ProtocolIPv4, ProtocolIPv6} {
		if err := c.setProto(proto, rules.appendRules, rules.prependRules); err != nil {
			return err
		}
	}
	c.appendRules = append([]Rule(nil), rules.appendRules...)
	c.prependRules = append([]Rule(nil), rules.prependRules...)
	return nil
}

func (c *Controller) setProto(proto Protocol, newAppendAll, newPrependAll []Rule) error {
	oldAppend := filterByProto(proto, c.appendRules)
	newAppend := filterByProto(proto, newAppendAll)
	oldPrepend := filterByProto(proto, c.prependRules)
	newPrepend := filterByProto(proto, newPrependAll)

	if rulesEqual(oldAppend, newAppend) && rulesEqualUnordered(oldPrepend, newPrepend) {
		return nil
	}

	var rc ruleCache
	oldOwned := ownedChainsForProto(proto, oldAppend, oldPrepend)
	newOwned := ownedChainsForProto(proto, newAppend, newPrepend)

	tables := make(map[string]*tableBatch)
	getBatch := func(table string) *tableBatch {
		b, ok := tables[table]
		if !ok {
			b = &tableBatch{
				flushedChains: make(map[string]bool),
				deletedChains: make(map[string]bool),
			}
			tables[table] = b
		}
		return b
	}

	// Determine which owned chains changed and need atomic flush + repopulate.
	for table, chains := range newOwned {
		for ch := range chains {
			if !oldOwned[table][ch] ||
				!chainRulesEqual(table, ch, oldAppend, newAppend) ||
				!chainRulesEqualUnordered(table, ch, oldPrepend, newPrepend) {
				b := getBatch(table)
				b.flushedChains[ch] = true
				for _, r := range newPrepend {
					if ru, ok := r.(*rule); ok && ru.table == table && ru.chain == ch {
						b.lines = append(b.lines, insertSpecString(ru, 1))
					}
				}
				for _, r := range newAppend {
					if ru, ok := r.(*rule); ok && ru.table == table && ru.chain == ch {
						b.lines = append(b.lines, ru.specString("-A"))
					}
				}
			}
		}
	}

	// Handle non-owned append rules (e.g. INPUT jumps).
	oldNonOwnedAppend := filterNonOwnedRules(oldAppend, oldOwned)
	newNonOwnedAppend := filterNonOwnedRules(newAppend, newOwned)
	if !rulesEqual(oldNonOwnedAppend, newNonOwnedAppend) {
		diverge := 0
		for diverge < len(oldNonOwnedAppend) && diverge < len(newNonOwnedAppend) &&
			oldNonOwnedAppend[diverge].String() == newNonOwnedAppend[diverge].String() {
			diverge++
		}
		for j := diverge; j < len(oldNonOwnedAppend); j++ {
			ru := oldNonOwnedAppend[j].(*rule)
			exists, err := rc.exists(c.client(proto), ru)
			if err != nil {
				return fmt.Errorf("failed to check if rule exists: %v", err)
			}
			if exists {
				getBatch(ru.table).lines = append(getBatch(ru.table).lines, ru.specString("-D"))
			}
		}
		for j := diverge; j < len(newNonOwnedAppend); j++ {
			ru := newNonOwnedAppend[j].(*rule)
			exists, err := rc.exists(c.client(proto), ru)
			if err != nil {
				return fmt.Errorf("failed to check if rule exists: %v", err)
			}
			// Avoid duplicate if rule already exists in kernel and wasn't scheduled for deletion above.
			deletedAbove := false
			for k := diverge; k < len(oldNonOwnedAppend); k++ {
				if oldNonOwnedAppend[k].String() == ru.String() {
					deletedAbove = true
					break
				}
			}
			if !exists || deletedAbove {
				getBatch(ru.table).lines = append(getBatch(ru.table).lines, ru.specString("-A"))
			}
		}
	}

	// Handle non-owned prepend rules (e.g. POSTROUTING jumps, FORWARD rules):
	// add new ones first, then delete obsolete ones before deleting any owned chains they referenced.
	for _, r := range newPrepend {
		ru, ok := r.(*rule)
		if !ok || newOwned[ru.table][ru.chain] {
			continue
		}
		if !containsRule(oldPrepend, r) {
			exists, err := rc.exists(c.client(proto), ru)
			if err != nil {
				return fmt.Errorf("failed to check if rule exists: %v", err)
			}
			if !exists {
				getBatch(ru.table).lines = append(getBatch(ru.table).lines, insertSpecString(ru, 1))
			}
		}
	}
	for _, r := range oldPrepend {
		ru, ok := r.(*rule)
		if !ok || oldOwned[ru.table][ru.chain] || newOwned[ru.table][ru.chain] {
			continue
		}
		if !containsRule(newPrepend, r) {
			exists, err := rc.exists(c.client(proto), ru)
			if err != nil {
				return fmt.Errorf("failed to check if rule exists: %v", err)
			}
			if exists {
				getBatch(ru.table).lines = append(getBatch(ru.table).lines, ru.specString("-D"))
			}
		}
	}

	// Delete owned chains that are no longer desired (after jump rules in that table were removed).
	for table, chains := range oldOwned {
		for ch := range chains {
			if !newOwned[table][ch] {
				chainRule := &chain{table: table, chain: ch, proto: proto}
				exists, err := rc.exists(c.client(proto), chainRule)
				if err != nil {
					return fmt.Errorf("failed to check if chain exists: %v", err)
				}
				if exists {
					b := getBatch(table)
					b.deletedChains[ch] = true
				}
			}
		}
	}

	return c.restoreTables(proto, tables)
}

type tableBatch struct {
	flushedChains map[string]bool
	deletedChains map[string]bool
	lines         []string
}

func (c *Controller) restoreTables(proto Protocol, tables map[string]*tableBatch) error {
	if len(tables) == 0 {
		return nil
	}
	tableNames := make([]string, 0, len(tables))
	for t := range tables {
		tableNames = append(tableNames, t)
	}
	sort.Strings(tableNames)

	var buf strings.Builder
	for _, table := range tableNames {
		b := tables[table]
		if len(b.flushedChains) == 0 && len(b.deletedChains) == 0 && len(b.lines) == 0 {
			continue
		}
		buf.WriteByte('*')
		buf.WriteString(table)
		buf.WriteByte('\n')

		if len(b.flushedChains) > 0 {
			chains := make([]string, 0, len(b.flushedChains))
			for ch := range b.flushedChains {
				chains = append(chains, ch)
			}
			sort.Strings(chains)
			for _, ch := range chains {
				buf.WriteByte(':')
				buf.WriteString(ch)
				buf.WriteString(" - [0:0]\n")
			}
		}
		for _, line := range b.lines {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
		if len(b.deletedChains) > 0 {
			chains := make([]string, 0, len(b.deletedChains))
			for ch := range b.deletedChains {
				chains = append(chains, ch)
			}
			sort.Strings(chains)
			for _, ch := range chains {
				buf.WriteString("-F ")
				buf.WriteString(ch)
				buf.WriteByte('\n')
				buf.WriteString("-X ")
				buf.WriteString(ch)
				buf.WriteByte('\n')
			}
		}
		buf.WriteString("COMMIT\n")
	}
	payload := buf.String()
	if payload == "" {
		return nil
	}
	if err := c.client(proto).RestoreNoFlush(payload); err != nil {
		return fmt.Errorf("failed to restore iptables rules: %v", err)
	}
	return nil
}

func insertSpecString(r *rule, pos int) string {
	spec := fmt.Sprintf("-I %s %d", r.chain, pos)
	for i, s := range r.spec {
		spec += " "
		if i > 0 && r.spec[i-1] == "--comment" {
			spec += `"` + s + `"`
		} else {
			spec += s
		}
	}
	return spec
}

func ruleTable(r Rule) string {
	switch v := r.(type) {
	case *chain:
		return v.table
	case *rule:
		return v.table
	default:
		return ""
	}
}

func filterByProto(proto Protocol, rules []Rule) []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Proto() == proto {
			out = append(out, r)
		}
	}
	return out
}

func ownedChainsForProto(proto Protocol, ruleSets ...[]Rule) map[string]map[string]bool {
	owned := make(map[string]map[string]bool)
	for _, rs := range ruleSets {
		for _, r := range rs {
			if r.Proto() != proto {
				continue
			}
			if ch, ok := r.(*chain); ok {
				if owned[ch.table] == nil {
					owned[ch.table] = make(map[string]bool)
				}
				owned[ch.table][ch.chain] = true
			}
		}
	}
	return owned
}

func filterNonOwnedRules(rules []Rule, owned map[string]map[string]bool) []Rule {
	var out []Rule
	for _, r := range rules {
		ru, ok := r.(*rule)
		if !ok {
			continue
		}
		if owned[ru.table][ru.chain] {
			continue
		}
		out = append(out, r)
	}
	return out
}

func rulesEqual(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Proto() != b[i].Proto() || a[i].String() != b[i].String() {
			return false
		}
	}
	return true
}

func rulesEqualUnordered(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, r := range a {
		counts[fmt.Sprintf("%d:%s", r.Proto(), r.String())]++
	}
	for _, r := range b {
		k := fmt.Sprintf("%d:%s", r.Proto(), r.String())
		counts[k]--
		if counts[k] < 0 {
			return false
		}
	}
	return true
}

func chainRulesEqual(table, ch string, a, b []Rule) bool {
	var ra, rb []Rule
	for _, r := range a {
		if ru, ok := r.(*rule); ok && ru.table == table && ru.chain == ch {
			ra = append(ra, r)
		}
	}
	for _, r := range b {
		if ru, ok := r.(*rule); ok && ru.table == table && ru.chain == ch {
			rb = append(rb, r)
		}
	}
	return rulesEqual(ra, rb)
}

func chainRulesEqualUnordered(table, ch string, a, b []Rule) bool {
	var ra, rb []Rule
	for _, r := range a {
		if ru, ok := r.(*rule); ok && ru.table == table && ru.chain == ch {
			ra = append(ra, r)
		}
	}
	for _, r := range b {
		if ru, ok := r.(*rule); ok && ru.table == table && ru.chain == ch {
			rb = append(rb, r)
		}
	}
	return rulesEqualUnordered(ra, rb)
}

func containsRule(haystack []Rule, needle Rule) bool {
	for _, element := range haystack {
		if element.String() == needle.String() {
			return true
		}
	}
	return false
}

// CleanUp will clean up any rules created by the controller.
func (c *Controller) CleanUp() error {
	return c.Set(RuleSet{})
}

func (c *Controller) client(p Protocol) Client {
	switch p {
	case ProtocolIPv4:
		return c.v4
	case ProtocolIPv6:
		return c.v6
	default:
		panic("unknown protocol")
	}
}

func nonBlockingSend(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}
