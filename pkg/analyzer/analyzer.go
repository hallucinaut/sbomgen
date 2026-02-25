// Package analyzer provides functionality to analyze projects and extract dependencies.
package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hallucinaut/sbomgen/pkg/sbom"
)

// Analyzer interface for extracting dependencies from different package managers.
type Analyzer interface {
	ShouldAnalyze(path string) bool
	Name() string
	Analyze(path string) ([]sbom.Component, error)
}

// ProjectAnalyzer analyzes various project types and extracts dependencies.
type ProjectAnalyzer struct {
	analyzers []Analyzer
}

// NewProjectAnalyzer creates a new project analyzer with all available analyzers.
func NewProjectAnalyzer() *ProjectAnalyzer {
	return &ProjectAnalyzer{
		analyzers: []Analyzer{
			NewNPMAnalyzer(),
			NewPyPIAnalyzer(),
			NewGoAnalyzer(),
			NewCargoAnalyzer(),
			NewMavenAnalyzer(),
		},
	}
}

// AnalyzeDir scans a directory and extracts all dependencies.
func (p *ProjectAnalyzer) AnalyzeDir(dir string) ([]sbom.Component, error) {
	var allComponents []sbom.Component

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == "node_modules" || info.Name() == "vendor" ||
				info.Name() == ".git" || info.Name() == "dist" || info.Name() == "build" {
				return filepath.SkipDir
			}
		}

		for _, analyzer := range p.analyzers {
			if analyzer.ShouldAnalyze(path) {
				components, err := analyzer.Analyze(path)
				if err != nil {
					continue
				}
				allComponents = append(allComponents, components...)
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("directory walk failed: %w", err)
	}

	return allComponents, nil
}

// DetectProjectType detects the type of project in a directory.
func DetectProjectType(dir string) string {
	files, err := os.ReadDir(dir)
	if err != nil {
		return "unknown"
	}

	for _, file := range files {
		name := file.Name()
		switch {
		case name == "package.json":
			return "npm"
		case name == "requirements.txt" || name == "setup.py" || name == "pyproject.toml":
			return "pypi"
		case name == "go.mod":
			return "go"
		case name == "Cargo.toml":
			return "cargo"
		case name == "pom.xml":
			return "maven"
		}
	}
	return "unknown"
}

// NPMAnalyzer analyzes Node.js projects.
type NPMAnalyzer struct{}

func NewNPMAnalyzer() *NPMAnalyzer {
	return &NPMAnalyzer{}
}

func (a *NPMAnalyzer) Name() string {
	return "npm"
}

func (a *NPMAnalyzer) ShouldAnalyze(path string) bool {
	return filepath.Base(path) == "package.json"
}

func (a *NPMAnalyzer) Analyze(path string) ([]sbom.Component, error) {
	var pkg struct {
		Name        string            `json:"name"`
		Version     string            `json:"version"`
		Dependencies map[string]string `json:"dependencies"`
		DevDeps      map[string]string `json:"devDependencies"`
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	var components []sbom.Component

	for name, version := range pkg.Dependencies {
		components = append(components, sbom.Component{
			Name:     name,
			Version:  version,
			Supplier: "npm",
			PURL:     fmt.Sprintf("pkg:npm/%s@%s", name, version),
		})
	}

	for name, version := range pkg.DevDeps {
		components = append(components, sbom.Component{
			Name:     name,
			Version:  version,
			Supplier: "npm",
			PURL:     fmt.Sprintf("pkg:npm/%s@%s", name, version),
			Metadata: sbom.Metadata{
				Description: "development dependency",
			},
		})
	}

	return components, nil
}

// PyPIAnalyzer analyzes Python projects.
type PyPIAnalyzer struct{}

func NewPyPIAnalyzer() *PyPIAnalyzer {
	return &PyPIAnalyzer{}
}

func (a *PyPIAnalyzer) Name() string {
	return "pypi"
}

func (a *PyPIAnalyzer) ShouldAnalyze(path string) bool {
	return filepath.Base(path) == "requirements.txt"
}

func (a *PyPIAnalyzer) Analyze(path string) ([]sbom.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var components []sbom.Component
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "==")
		if len(parts) < 2 {
			parts = strings.Split(line, ">=")
		}
		if len(parts) < 2 {
			parts = strings.Split(line, "<=")
		}

		if len(parts) >= 2 {
			name := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])

			components = append(components, sbom.Component{
				Name:     name,
				Version:  version,
				Supplier: "pypi",
				PURL:     fmt.Sprintf("pkg:pypi/%s@%s", name, version),
			})
		}
	}

	return components, nil
}

// GoAnalyzer analyzes Go projects.
type GoAnalyzer struct{}

func NewGoAnalyzer() *GoAnalyzer {
	return &GoAnalyzer{}
}

func (a *GoAnalyzer) Name() string {
	return "go"
}

func (a *GoAnalyzer) ShouldAnalyze(path string) bool {
	return filepath.Base(path) == "go.mod"
}

func (a *GoAnalyzer) Analyze(path string) ([]sbom.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var components []sbom.Component
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require ") || (line != "" && strings.Contains(line, " ")) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.TrimSpace(parts[1])
				components = append(components, sbom.Component{
					Name:     filepath.Base(name),
					Version:  version,
					Supplier: "go",
					PURL:     fmt.Sprintf("pkg:go/%s@%s", filepath.Base(name), version),
				})
			}
		}
	}

	return components, nil
}

// CargoAnalyzer analyzes Rust projects.
type CargoAnalyzer struct{}

func NewCargoAnalyzer() *CargoAnalyzer {
	return &CargoAnalyzer{}
}

func (a *CargoAnalyzer) Name() string {
	return "cargo"
}

func (a *CargoAnalyzer) ShouldAnalyze(path string) bool {
	return filepath.Base(path) == "Cargo.toml"
}

func (a *CargoAnalyzer) Analyze(path string) ([]sbom.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var components []sbom.Component
	lines := strings.Split(string(data), "\n")
	inDependencies := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[dependencies]") {
			inDependencies = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDependencies = false
			continue
		}
		if inDependencies && line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				versionPart := strings.TrimSpace(parts[1])
				if strings.HasPrefix(versionPart, "{") {
					versionStart := strings.Index(versionPart, `"`)
					if versionStart >= 0 {
						versionEnd := strings.Index(versionPart[versionStart+1:], `"`)
						if versionEnd >= 0 {
							version := versionPart[versionStart+1 : versionStart+versionEnd+1]
							components = append(components, sbom.Component{
								Name:     name,
								Version:  version,
								Supplier: "cargo",
								PURL:     fmt.Sprintf("pkg:cargo/%s@%s", name, version),
							})
						}
					}
				} else {
					version := strings.Trim(versionPart, `"`)
					components = append(components, sbom.Component{
						Name:     name,
						Version:  version,
						Supplier: "cargo",
						PURL:     fmt.Sprintf("pkg:cargo/%s@%s", name, version),
					})
				}
			}
		}
	}

	return components, nil
}

// MavenAnalyzer analyzes Java/Maven projects.
type MavenAnalyzer struct{}

func NewMavenAnalyzer() *MavenAnalyzer {
	return &MavenAnalyzer{}
}

func (a *MavenAnalyzer) Name() string {
	return "maven"
}

func (a *MavenAnalyzer) ShouldAnalyze(path string) bool {
	return filepath.Base(path) == "pom.xml"
}

func (a *MavenAnalyzer) Analyze(path string) ([]sbom.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return parsePomXML(string(data)), nil
}

func parsePomXML(xmlContent string) []sbom.Component {
	var components []sbom.Component
	lines := strings.Split(xmlContent, "\n")
	inDependencies := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "<dependencies>") {
			inDependencies = true
			continue
		}
		if strings.Contains(line, "</dependencies>") {
			inDependencies = false
			continue
		}
		if inDependencies {
			if strings.Contains(line, "<artifactId>") && strings.Contains(line, "</artifactId>") {
				artifactId := extractTag(line, "artifactId")
				version := extractTag(line, "version")
				if artifactId != "" && version != "" {
					components = append(components, sbom.Component{
						Name:     artifactId,
						Version:  version,
						Supplier: "maven",
						PURL:     fmt.Sprintf("pkg:maven/%s@%s", artifactId, version),
					})
				}
			}
		}
	}

	return components
}

func extractTag(line, tag string) string {
	startTag := fmt.Sprintf("<%s>", tag)
	endTag := fmt.Sprintf("</%s>", tag)

	start := strings.Index(line, startTag)
	if start < 0 {
		return ""
	}
	start += len(startTag)

	end := strings.Index(line[start:], endTag)
	if end < 0 {
		return ""
	}

	return line[start : start+end]
}