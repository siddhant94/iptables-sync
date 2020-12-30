package main

import (
	"fmt"
	"siddhant94/iptables-sync/sync"
)
var (
	v4Enabled bool = true
	v6Enabled bool = false
)

func main() {
	fmt.Println("Iptables SYNC")
	syncClient, err := sync.New(v4Enabled, v6Enabled)
	if err != nil {
		fmt.Errorf("error creating IPTables instance: %v", err)
		return
	}
	tblList := syncClient.GetTables()

	for _, v := range tblList {
		fmt.Println("Running for Table:")
		fmt.Println(v)
		syncClient.SaveTable(string(v))
	}
	syncClient.PrintIpTableData()
}

//func main() {
//	fmt.Println("Iptables SYNC")
//	ipt, err := iptables.New()
//	if err != nil {
//		fmt.Printf("Failed to create new iptables datastructure: %v", err)
//		return
//	}
//	fmt.Printf("\n%+v\n", ipt)
//	// Listing existing chains per table
//	//TODO: Make an array for tables raw, mangle etc
//	originaListChain, err := ipt.ListChains("filter")
//	if err != nil {
//		fmt.Printf("ListChains of Initial failed: %v", err)
//		return
//	}
//	fmt.Println("Original ListChain")
//	fmt.Printf("\n%+v\n", originaListChain)
//
//	// List each rule
//	for _, v := range originaListChain {
//		rules, err := ipt.List("filter", v)
//		if err != nil {
//			fmt.Printf("Error in listing rules: %v", err)
//			return
//		}
//		fmt.Printf("\nRules:\n%+v", rules)
//	}
//}
