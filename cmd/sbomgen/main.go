// Package main provides the CLI entry point for sbomgen.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hallucinaut/sbomgen/pkg/analyzer"
	"github.com/hallucinaut/sbomgen/pkg/formatter"
	"github.com/hallucinaut/sbomgen/pkg/sbom"
)

const (
	version = "1.0.0"
	appName = "sbomgen"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return printUsage()
	}

	command := args[0]
	switch command {
	case "gen":
		return generate(args[1:])
	case "analyze":
		return analyze(args[1:])
	case "version":
		fmt.Printf("%s version %s\n", appName, version)
		return nil
	case "help", "--help", "-h":
		return printUsage()
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

func printUsage() error {
	fmt.Printf(`%s - Software Bill of Materials Generator

Usage:
  %s <command> [options]

Commands:
  gen       Generate SBOM from a project directory
  analyze   Analyze a project and list dependencies
  version   Show version information
  help      Show this help message

Options for 'gen':
  -o, --output <file>     Output file (default: stdout)
  -f, --format <format>   Output format: json, yaml, markdown, table, spdx, cyclonedx (default: json)
  -d, --dir <dir>         Project directory (default: current directory)
  
Examples:
  %s gen -o sbom.json -f json ./myproject
  %s gen --format markdown --dir ./myapp
  %s analyze ./myproject

For more information, visit: https://github.com/hallucinaut/sbomgen
`, appName, appName, appName, appName, appName)
	return nil
}

func generate(args []string) error {
	var outputFile, outputFormat, projectDir string
	
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "-f", "--format":
			if i+1 < len(args) {
				outputFormat = args[i+1]
				i++
			}
		case "-d", "--dir":
			if i+1 < len(args) {
				projectDir = args[i+1]
				i++
			}
		}
	}

	if projectDir == "" {
		projectDir = "."
	}
	
	absDir, err := filepath.Abs(projectDir)
	if err != nil {
		return fmt.Errorf("failed to resolve directory path: %w", err)
	}
	
	projectType := analyzer.DetectProjectType(absDir)
	fmt.Printf("Detected project type: %s\n", projectType)
	
	gen := sbom.New(appName, version, "sbom-001")
	
	analyzer := analyzer.NewProjectAnalyzer()
	components, err := analyzer.AnalyzeDir(absDir)
	if err != nil {
		return fmt.Errorf("failed to analyze directory: %w", err)
	}
	
	fmt.Printf("Found %d components\n", len(components))
	
	for _, comp := range components {
		gen.AddComponent(comp)
	}
	
	var fmt formatter.Formatter
	if outputFormat == "" {
		outputFormat = "json"
	}
	fmt = formatter.GetFormatter(formatter.Format(outputFormat))
	
	output, err := fmt.Format(gen)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}
	
	if outputFile != "" {
		err = os.WriteFile(outputFile, []byte(output), 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("SBOM written to %s\n", outputFile)
	} else {
		fmt.Println(output)
	}
	
	return nil
}

func analyze(args []string) error {
	var projectDir string
	
	for i := 0; i < len(args); i++ {
		if args[i] != "-d" && args[i] != "--dir" {
			continue
		}
		if i+1 < len(args) {
			projectDir = args[i+1]
			i++
		}
	}

	if projectDir == "" {
		projectDir = "."
	}
	
	absDir, err := filepath.Abs(projectDir)
	if err != nil {
		return fmt.Errorf("failed to resolve directory path: %w", err)
	}
	
	projectType := analyzer.DetectProjectType(absDir)
	fmt.Printf("Project: %s\n", absDir)
	fmt.Printf("Type: %s\n", projectType)
	
	analyzer := analyzer.NewProjectAnalyzer()
	components, err := analyzer.AnalyzeDir(absDir)
	if err != nil {
		return fmt.Errorf("failed to analyze directory: %w", err)
	}
	
	fmt.Printf("\nFound %d components:\n\n", len(components))
	fmt.Printf("%-30s %-20s %-15s %-12s\n", "NAME", "VERSION", "SUPPLIER", "PURL")
	fmt.Println(strings.Repeat("-", 80))
	
	for _, comp := range components {
		purl := comp.PURL
		if len(purl) > 12 {
			purl = purl[:9] + "..."
		}
		fmt.Printf("%-30s %-20s %-15s %-12s\n", 
			truncate(comp.Name, 30), 
			truncate(comp.Version, 20), 
			truncate(comp.Supplier, 15),
			truncate(purl, 12))
	}
	
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}