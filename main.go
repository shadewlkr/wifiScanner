package main

import (
	"flag"
	"fmt"
	"os"

	"wifiscanner/scanner"
	"wifiscanner/ui"
)

func main() {
	demo := flag.Bool("demo", false, "Run with simulated network data (no root required)")
	iface := flag.String("interface", "", "Wireless interface (auto-detected if omitted)")
	flag.StringVar(iface, "i", "", "Wireless interface (shorthand)")
	flag.Parse()

	if !*demo && os.Geteuid() != 0 {
		fmt.Println()
		fmt.Println("  [!] SPECTR//SCAN requires root privileges for live WiFi scanning.")
		fmt.Println("  [>] Run with:  sudo go run .")
		fmt.Println("  [>] Or try:    go run . --demo")
		fmt.Println()
		os.Exit(1)
	}

	s, err := scanner.New(*iface, *demo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  [!] %v\n\n", err)
		os.Exit(1)
	}

	app := ui.New(s)
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n  [!] UI error: %v\n\n", err)
		os.Exit(1)
	}
}
