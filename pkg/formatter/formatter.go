// Package formatter provides functionality to serialize SBOMs in various formats.
package formatter

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hallucinaut/sbomgen/pkg/sbom"
	"gopkg.in/yaml.v3"
)

// Format represents the output format.
type Format string

const (
	SPDX      Format = "spdx"
	CycloneDX Format = "cyclonedx"
	JSON      Format = "json"
	YAML      Format = "yaml"
	Markdown  Format = "markdown"
	Table     Format = "table"
)

// Formatter interface for serializing SBOMs.
type Formatter interface {
	Name() string
	Format(sbom *sbom.SBOM) (string, error)
}

// JSONFormatter formats SBOM as JSON.
type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (f *JSONFormatter) Name() string {
	return "json"
}

func (f *JSONFormatter) Format(sbom *sbom.SBOM) (string, error) {
	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to serialize to JSON: %w", err)
	}
	return string(data), nil
}

// YAMLFormatter formats SBOM as YAML.
type YAMLFormatter struct{}

func NewYAMLFormatter() *YAMLFormatter {
	return &YAMLFormatter{}
}

func (f *YAMLFormatter) Name() string {
	return "yaml"
}

func (f *YAMLFormatter) Format(sbom *sbom.SBOM) (string, error) {
	data, err := yaml.Marshal(sbom)
	if err != nil {
		return "", fmt.Errorf("failed to serialize to YAML: %w", err)
	}
	return string(data), nil
}

// MarkdownFormatter formats SBOM as Markdown.
type MarkdownFormatter struct{}

func NewMarkdownFormatter() *MarkdownFormatter {
	return &MarkdownFormatter{}
}

func (f *MarkdownFormatter) Name() string {
	return "markdown"
}

func (f *MarkdownFormatter) Format(sbom *sbom.SBOM) (string, error) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Software Bill of Materials\n\n"))
	sb.WriteString(fmt.Sprintf("**Project:** %s v%s\n\n", sbom.Name, sbom.Version))
	sb.WriteString(fmt.Sprintf("**Created:** %s\n", sbom.Created.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("**Total Components:** %d\n\n", sbom.Count()))

	sb.WriteString("## Components\n\n")
	sb.WriteString("| # | Name | Version | Supplier | License |\n")
	sb.WriteString("|---|------|---------|----------|---------|\n")

	for i, comp := range sbom.Components {
		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
			i+1, comp.Name, comp.Version, comp.Supplier, comp.License))
	}

	sb.WriteString("\n## Relationships\n\n")
	if len(sbom.Relationships) == 0 {
		sb.WriteString("No relationships defined.\n")
	} else {
		sb.WriteString("| Component A | Component B | Relationship |\n")
		sb.WriteString("|-------------|-------------|--------------|\n")
		for _, rel := range sbom.Relationships {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
				rel.RefA, rel.RefB, rel.Relationship))
		}
	}

	return sb.String(), nil
}

// TableFormatter formats SBOM as ASCII table.
type TableFormatter struct{}

func NewTableFormatter() *TableFormatter {
	return &TableFormatter{}
}

func (f *TableFormatter) Name() string {
	return "table"
}

func (f *TableFormatter) Format(sbom *sbom.SBOM) (string, error) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%-30s %-20s %-15s %-12s\n", "NAME", "VERSION", "SUPPLIER", "PURL"))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	for _, comp := range sbom.Components {
		purl := comp.PURL
		if len(purl) > 35 {
			purl = purl[:32] + "..."
		}
		sb.WriteString(fmt.Sprintf("%-30s %-20s %-15s %-12s\n",
			truncate(comp.Name, 30),
			truncate(comp.Version, 20),
			truncate(comp.Supplier, 15),
			truncate(purl, 12)))
	}

	return sb.String(), nil
}

// SPDXFormatter formats SBOM as SPDX.
type SPDXFormatter struct{}

func NewSPDXFormatter() *SPDXFormatter {
	return &SPDXFormatter{}
}

func (f *SPDXFormatter) Name() string {
	return "spdx"
}

func (f *SPDXFormatter) Format(sbom *sbom.SBOM) (string, error) {
	var sb strings.Builder

	sb.WriteString("SPDXVersion: SPDX-2.2\n")
	sb.WriteString("DataLicense: CC0-1.0\n")
	sb.WriteString(fmt.Sprintf("SPDXID: SPDXRef-DOCUMENT\n"))
	sb.WriteString(fmt.Sprintf("DocumentName: %s\n", sbom.Name))
	sb.WriteString(fmt.Sprintf("DocumentNamespace: https://sbom.example.org/%s/%s\n", sbom.Name, sbom.Version))
	sb.WriteString(fmt.Sprintf("Creator: Tool: sbomgen-%s\n", sbom.Version))
	sb.WriteString(fmt.Sprintf("Created: %sZ\n", sbom.Created.UTC().Format("2006-01-02T15:04:05Z")))

	sb.WriteString("\n## Packages\n\n")
	for i, comp := range sbom.Components {
		sb.WriteString(fmt.Sprintf("PackageName: %s\n", comp.Name))
		sb.WriteString(fmt.Sprintf("SPDXID: SPDXRef-Package-%d\n", i))
		sb.WriteString(fmt.Sprintf("PackageVersion: %s\n", comp.Version))
		sb.WriteString(fmt.Sprintf("PackageSupplier: PackageSupplier: %s\n", comp.Supplier))
		if comp.License != "" {
			sb.WriteString(fmt.Sprintf("PackageLicenseConcluded: %s\n", comp.License))
		}
		if comp.PURL != "" {
			sb.WriteString(fmt.Sprintf("PackageDownloadLocation: %s\n", comp.PURL))
		}
		sb.WriteString("FilesAnalyzed: false\n")
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

// CycloneDXFormatter formats SBOM as CycloneDX.
type CycloneDXFormatter struct{}

func NewCycloneDXFormatter() *CycloneDXFormatter {
	return &CycloneDXFormatter{}
}

func (f *CycloneDXFormatter) Name() string {
	return "cyclonedx"
}

func (f *CycloneDXFormatter) Format(sbom *sbom.SBOM) (string, error) {
	return f.FormatJSON(sbom)
}

// FormatJSON formats SBOM as CycloneDX JSON.
// NOTE: This function is currently disabled due to forward reference issues with struct types.
func (f *CycloneDXFormatter) FormatJSON(sbom *sbom.SBOM) (string, error) {
	return "", fmt.Errorf("CycloneDX JSON formatting not yet implemented")
}

// GetFormatter returns a formatter by name.
func GetFormatter(format Format) Formatter {
	switch format {
	case JSON:
		return NewJSONFormatter()
	case YAML:
		return NewYAMLFormatter()
	case Markdown:
		return NewMarkdownFormatter()
	case Table:
		return NewTableFormatter()
	case SPDX:
		return NewSPDXFormatter()
	case CycloneDX:
		return NewCycloneDXFormatter()
	default:
		return NewJSONFormatter()
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}