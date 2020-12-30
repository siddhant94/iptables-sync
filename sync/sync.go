package sync

import (
	"encoding/json"
	"fmt"
	"github.com/blang/semver"
	"github.com/coreos/go-iptables/iptables"
)
// https://netfilter.org/projects/iptables/files/changes-iptables-1.6.2.txt:
// iptables-restore: support acquiring the lock.
var restoreWaitSupportedMinVersion = semver.Version{Major: 1, Minor: 6, Patch: 2}

const (
	// Built-in tables
	TableNAT string = "nat"
	TableRAW string = "raw"
	TableFilter string = "filter"
	TableMangle string = "mangle"

	// Chains
	PreRoutingChain string = "PREROUTING"
	ForwardChain string  = "FORWARD"
	PostRoutingChain string = "POSTROUTING"
	OutputChain string = "OUTPUT"
)

var iptData map[string][]map[string][]string

func init() {
	iptData = make(map[string][]map[string][]string)
}


type Client struct {
	ipts []*iptables.IPTables
	// restoreWaitSupported indicates whether iptables-restore (or ip6tables-restore) supports --wait flag.
	restoreWaitSupported bool
}

func New(enableIPV4, enableIPV6 bool) (*Client, error) {
	var ipts []*iptables.IPTables
	var restoreWaitSupported bool
	if enableIPV4 {
		ipt, err := iptables.New()
		if err != nil {
			return nil, fmt.Errorf("error creating IPTables instance: %v", err)
		}
		ipts = append(ipts, ipt)
		restoreWaitSupported = isRestoreWaitSupported(ipt)
	}
	if enableIPV6 {
		ip6t, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return nil, fmt.Errorf("error creating IPTables instance for IPv6: %v", err)
		}
		ipts = append(ipts, ip6t)
		if !restoreWaitSupported {
			restoreWaitSupported = isRestoreWaitSupported(ip6t)
		}
	}
	return &Client{ipts: ipts, restoreWaitSupported: restoreWaitSupported}, nil
}
func isRestoreWaitSupported(ipt *iptables.IPTables) bool {
	major, minor, patch := ipt.GetIptablesVersion()
	version := semver.Version{Major: uint64(major), Minor: uint64(minor), Patch: uint64(patch)}
	return version.GE(restoreWaitSupportedMinVersion)
}

func(c *Client) SaveTable(tblName string) {
	//intialize for v4 and v6 both . TODO

	// Range iptables for IPv4 & IPv6
	for _, iptable := range c.ipts {
		oriChains, err := iptable.ListChains(tblName)
		if err != nil {
			fmt.Errorf("error listing existing chains in table %s: %v", tblName, err)
			return
		}

		for _, chain := range oriChains {
			oriRules, err := iptable.List(string(tblName), chain)
			if err != nil {
				fmt.Errorf("error listing existing rules in chain(%s) in table(%s): %v", tblName, chain, err)
				continue
			}
			m := make(map[string][]string)
			m[chain] = oriRules
			iptData[tblName] = append(iptData[tblName], m)
		}
	}
}

func(c *Client) PrintIpTableData() {
	fmt.Println("Printing IPTables data")
	//fmt.Printf("%+v\n", iptData)
	r, err := json.MarshalIndent(iptData, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Print(string(r))
}

func(c *Client) GetTables() []string {
	return []string{TableNAT, TableRAW, TableFilter, TableMangle}
}

