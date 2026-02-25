package formatter

import (
	"strings"
	"testing"

	"github.com/hallucinaut/sbomgen/pkg/sbom"
)

func TestGetFormatter(t *testing.T) {
	tests := []struct {
		name     string
		format   Format
		expected string
	}{
		{"JSON", JSON, "json"},
		{"YAML", YAML, "yaml"},
		{"Markdown", Markdown, "markdown"},
		{"Table", Table, "table"},
		{"SPDX", SPDX, "spdx"},
		{"CycloneDX", CycloneDX, "cyclonedx"},
		{"Unknown", "unknown", "json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := GetFormatter(tt.format)
			if f == nil {
				t.Errorf("Expected non-nil formatter for format %s", tt.format)
				return
			}
			if f.Name() != tt.expected {
				t.Errorf("Expected formatter name '%s', got '%s'", tt.expected, f.Name())
			}
		})
	}
}

func TestJSONFormatter(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{
		Name:     "lib-a",
		Version:  "1.0.0",
		Supplier: "npm",
		License:  "MIT",
	})

	f := NewJSONFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "test-app") {
		t.Error("Expected output to contain 'test-app'")
	}
	if !strings.Contains(output, "lib-a") {
		t.Error("Expected output to contain 'lib-a'")
	}
	if !strings.Contains(output, "MIT") {
		t.Error("Expected output to contain 'MIT'")
	}
}

func TestYAMLFormatter(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{
		Name:     "lib-a",
		Version:  "1.0.0",
		Supplier: "npm",
	})

	f := NewYAMLFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "test-app") {
		t.Error("Expected output to contain 'test-app'")
	}
	if !strings.Contains(output, "lib-a") {
		t.Error("Expected output to contain 'lib-a'")
	}
}

func TestMarkdownFormatter(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{
		Name:     "lib-a",
		Version:  "1.0.0",
		Supplier: "npm",
		License:  "MIT",
	})
	sbom.AddComponent(sbom.Component{
		Name:     "lib-b",
		Version:  "2.0.0",
		Supplier: "pypi",
	})

	f := NewMarkdownFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "| # | Name | Version | Supplier | License |") {
		t.Error("Expected markdown table header")
	}
	if !strings.Contains(output, "lib-a") {
		t.Error("Expected output to contain 'lib-a'")
	}
	if !strings.Contains(output, "lib-b") {
		t.Error("Expected output to contain 'lib-b'")
	}
}

func TestTableFormatter(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{
		Name:     "lib-a",
		Version:  "1.0.0",
		Supplier: "npm",
		PURL:     "pkg:npm/lib-a@1.0.0",
	})
	sbom.AddComponent(sbom.Component{
		Name:     "lib-b",
		Version:  "2.0.0",
		Supplier: "pypi",
		PURL:     "pkg:pypi/lib-b@2.0.0",
	})

	f := NewTableFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "NAME") {
		t.Error("Expected table header 'NAME'")
	}
	if !strings.Contains(output, "lib-a") {
		t.Error("Expected output to contain 'lib-a'")
	}
	if !strings.Contains(output, "lib-b") {
		t.Error("Expected output to contain 'lib-b'")
	}
}

func TestSPDXFormatter(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{
		Name:     "lib-a",
		Version:  "1.0.0",
		Supplier: "npm",
		License:  "MIT",
	})

	f := NewSPDXFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "SPDXVersion: SPDX-2.2") {
		t.Error("Expected SPDX-2.2 version")
	}
	if !strings.Contains(output, "test-app") {
		t.Error("Expected output to contain 'test-app'")
	}
	if !strings.Contains(output, "lib-a") {
		t.Error("Expected output to contain 'lib-a'")
	}
}

func TestCycloneDXFormatter(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{
		Name:     "lib-a",
		Version:  "1.0.0",
		Supplier: "npm",
	})
	sbom.AddComponent(sbom.Component{
		Name:     "lib-b",
		Version:  "2.0.0",
		Supplier: "pypi",
	})

	f := NewCycloneDXFormatter()
	output, err := f.FormatJSON(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "CycloneDX") {
		t.Error("Expected CycloneDX format")
	}
	if !strings.Contains(output, "lib-a") {
		t.Error("Expected output to contain 'lib-a'")
	}
	if !strings.Contains(output, "lib-b") {
		t.Error("Expected output to contain 'lib-b'")
	}
}

func TestJSONFormatter_EmptySBOM(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")

	f := NewJSONFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format empty SBOM: %v", err)
	}

	if !strings.Contains(output, "test-app") {
		t.Error("Expected output to contain project name")
	}
}

func TestMarkdownFormatter_NoRelationships(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{Name: "lib-a"})

	f := NewMarkdownFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "No relationships defined") {
		t.Error("Expected 'No relationships defined' message")
	}
}

func TestMarkdownFormatter_WithRelationships(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{Name: "lib-a"})
	sbom.AddComponent(sbom.Component{Name: "lib-b"})
	sbom.AddRelationship("ref-a", "ref-b", "depends_on")

	f := NewMarkdownFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "ref-a") {
		t.Error("Expected output to contain 'ref-a'")
	}
	if !strings.Contains(output, "depends_on") {
		t.Error("Expected output to contain 'depends_on'")
	}
}

func TestTableFormatter_LongNames(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")
	sbom.AddComponent(sbom.Component{
		Name:     "very-long-package-name-that-exceeds-limit",
		Version:  "very-long-version-number-that-exceeds-limit",
		Supplier: "npm",
		PURL:     "pkg:npm/very-long-package-name-that-exceeds-limit@1.0.0",
	})

	f := NewTableFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if strings.Contains(output, "very-long-package-name-that-exceeds-limit") {
		t.Error("Expected long name to be truncated")
	}
}

func TestFormatter_Default(t *testing.T) {
	f := GetFormatter("unknown")
	if f.Name() != "json" {
		t.Errorf("Expected default formatter to be JSON, got '%s'", f.Name())
	}
}

func TestMarkdownFormatter_ComponentCount(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")

	for i := 0; i < 5; i++ {
		sbom.AddComponent(sbom.Component{
			Name:     "lib",
			Version:  "1.0.0",
			Supplier: "npm",
			License:  "MIT",
		})
	}

	f := NewMarkdownFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	count := strings.Count(output, "lib")
	if count < 5 {
		t.Errorf("Expected at least 5 component mentions, got %d", count)
	}
}

func TestTableFormatter_EmptySBOM(t *testing.T) {
	sbom := sbom.New("test-app", "1.0.0", "serial-001")

	f := NewTableFormatter()
	output, err := f.Format(sbom)
	if err != nil {
		t.Fatalf("Failed to format: %v", err)
	}

	if !strings.Contains(output, "NAME") {
		t.Error("Expected table header even with no components")
	}
}