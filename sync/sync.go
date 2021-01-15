package sync

import (
	"encoding/json"
	"fmt"
	"github.com/blang/semver"
	"github.com/coreos/go-iptables/iptables"
	"os/exec"
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

	// Antrea managed ipset.
	// antreaPodIPSet contains all Pod CIDRs of this cluster.
	antreaPodIPSet = "ANTREA-POD-IP"
	// antreaPodIP6Set contains all IPv6 Pod CIDRs of this cluster.
	antreaPodIP6Set = "ANTREA-POD-IP6"

	// Antrea managed iptables chains.
	antreaForwardChain     = "ANTREA-FORWARD"
	antreaPreRoutingChain  = "ANTREA-PREROUTING"
	antreaPostRoutingChain = "ANTREA-POSTROUTING"
	antreaOutputChain      = "ANTREA-OUTPUT"
	antreaMangleChain      = "ANTREA-MANGLE"
)

//type RuleSpec string
//type Chain string
//type Table string

//var iptablesData map[Table][]map[Chain][]RuleSpec
var iptData map[string][]map[string][]string
var rulesToEnsure []string

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

func(c * Client) SaveEntireIPTable() ([]byte, error) {
	// Save calls iptables-saves to dump chains and tables in iptables.
		var output []byte
		for idx := range c.ipts {
			var cmd string
			ipt := c.ipts[idx]
			switch ipt.Proto() {
			case iptables.ProtocolIPv6:
				cmd = "ip6tables-save"
			default:
				cmd = "iptables-save"
			}
			//data, err := exec.Command(cmd, "-c").CombinedOutput()
			data, err := exec.Command(cmd).CombinedOutput()
			if err != nil {
				return nil, err
			}
			output = append(output, data...)
		}
		return output, nil
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
			fmt.Println("RUles for table/chain: " + string(tblName) + "/" + chain)
			for _, v := range oriRules {
				fmt.Printf("\n%+v\n", v)
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

	//fmt.Println("\n\n\n\n")
	//jumpRules := []struct{ table, srcChain, dstChain, comment string }{
	//	{TableRAW, PreRoutingChain, antreaPreRoutingChain, "Antrea: jump to Antrea prerouting rules"},
	//	{TableRAW, OutputChain, antreaOutputChain, "Antrea: jump to Antrea output rules"},
	//	{TableFilter, ForwardChain, antreaForwardChain, "Antrea: jump to Antrea forwarding rules"},
	//	{TableNAT, PostRoutingChain, antreaPostRoutingChain, "Antrea: jump to Antrea postrouting rules"},
	//	{TableMangle, PreRoutingChain, antreaMangleChain, "Antrea: jump to Antrea mangle rules"},
	//}
	//for _, rule := range jumpRules {
	//	//fmt.Printf("Table:%v, Chain: %v\n", rule.table, rule.dstChain)
	//	ruleSpec := []string{"-j", rule.dstChain, "-m", "comment", "--comment", rule.comment}
	//	fmt.Printf("Table: %s, Chain: %s, rulespec: %v\n", rule.table, rule.srcChain, ruleSpec)
	//}
}

func(c *Client) GetTables() []string {
	return []string{TableNAT, TableRAW, TableFilter, TableMangle}
}

//func addRulesforCheck() {
//	iptablesData := bytes.NewBuffer(nil)
//	//for table
//	writeLine(iptablesData, []string{
//		"-A", antreaPreRoutingChain,
//		"-m", "comment", "--comment", `"Antrea: do not track incoming encapsulation packets"`,
//		"-m", "udp", "-p", "udp", "--dport", strconv.Itoa(6508),
//		"-m", "addrtype", "--dst-type", "LOCAL",
//		"-j", "NOTRACK",
//	}...)
//	writeLine(iptablesData, []string{
//		"-A", antreaOutputChain,
//		"-m", "comment", "--comment", `"Antrea: do not track outgoing encapsulation packets"`,
//		"-m", "udp", "-p", "udp", "--dport", strconv.Itoa(7052),
//		"-m", "addrtype", "--src-type", "LOCAL",
//		"-j", "NOTRACK",
//	}...)
//	// for table Filter
//	writeLine(iptablesData, []string{
//		"-A", antreaForwardChain,
//		"-m", "comment", "--comment", `"Antrea: accept packets from local pods"`,
//		"-i", hostGateway,
//		"-j", iptables.AcceptTarget,
//	}...)
//	writeLine(iptablesData, []string{
//		"-A", antreaForwardChain,
//		"-m", "comment", "--comment", `"Antrea: accept packets to local pods"`,
//		"-o", hostGateway,
//		"-j", iptables.AcceptTarget,
//	}...)
//	fmt.Println("RULE:")
//	fmt.Printf("%+v\n", iptablesData)
//}
//
//// Join all words with spaces, terminate with newline and write to buf.
//func writeLine(buf *bytes.Buffer, words ...string) {
//	// We avoid strings.Join for performance reasons.
//	for i := range words {
//		buf.WriteString(words[i])
//		if i < len(words)-1 {
//			buf.WriteByte(' ')
//		} else {
//			buf.WriteByte('\n')
//		}
//	}
//}
