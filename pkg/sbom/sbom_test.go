package sbom

import (
	"testing"
)

func TestNew(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	if sbom.Name != "test-app" {
		t.Errorf("Expected name 'test-app', got '%s'", sbom.Name)
	}
	if sbom.Version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", sbom.Version)
	}
	if sbom.SerialNumber != "serial-001" {
		t.Errorf("Expected serial 'serial-001', got '%s'", sbom.SerialNumber)
	}
	if sbom.Count() != 0 {
		t.Errorf("Expected count 0, got %d", sbom.Count())
	}
}

func TestAddComponent(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	comp := Component{
		Name:     "test-lib",
		Version:  "2.0.0",
		Supplier: "npm",
		License:  "MIT",
		PURL:     "pkg:npm/test-lib@2.0.0",
	}

	sbom.AddComponent(comp)

	if sbom.Count() != 1 {
		t.Errorf("Expected count 1, got %d", sbom.Count())
	}

	if sbom.Components[0].Name != "test-lib" {
		t.Errorf("Expected component name 'test-lib', got '%s'", sbom.Components[0].Name)
	}
}

func TestGetComponentByPURL(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	sbom.AddComponent(Component{
		Name:     "lib-a",
		Version:  "1.0.0",
		Supplier: "npm",
		PURL:     "pkg:npm/lib-a@1.0.0",
	})

	sbom.AddComponent(Component{
		Name:     "lib-b",
		Version:  "2.0.0",
		Supplier: "pypi",
		PURL:     "pkg:pypi/lib-b@2.0.0",
	})

	found := sbom.GetComponentByPURL("pkg:npm/lib-a@1.0.0")
	if found == nil {
		t.Error("Expected to find component, got nil")
	}
	if found.Name != "lib-a" {
		t.Errorf("Expected 'lib-a', got '%s'", found.Name)
	}

	notFound := sbom.GetComponentByPURL("pkg:npm/nonexistent@1.0.0")
	if notFound != nil {
		t.Errorf("Expected nil for non-existent component, got '%s'", notFound.Name)
	}
}

func TestGetComponentsByLicense(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	sbom.AddComponent(Component{
		Name:     "lib-a",
		Version:  "1.0.0",
		License:  "MIT",
		Supplier: "npm",
	})

	sbom.AddComponent(Component{
		Name:     "lib-b",
		Version:  "2.0.0",
		License:  "Apache-2.0",
		Supplier: "pypi",
	})

	sbom.AddComponent(Component{
		Name:     "lib-c",
		Version:  "3.0.0",
		License:  "MIT",
		Supplier: "go",
	})

	mitComponents := sbom.GetComponentsByLicense("MIT")
	if len(mitComponents) != 2 {
		t.Errorf("Expected 2 MIT components, got %d", len(mitComponents))
	}

	unknownComponents := sbom.GetComponentsByLicense("GPL-3.0")
	if len(unknownComponents) != 0 {
		t.Errorf("Expected 0 components for GPL-3.0, got %d", len(unknownComponents))
	}
}

func TestCount(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	sbom.AddComponent(Component{Name: "lib-a"})
	sbom.AddComponent(Component{Name: "lib-b"})
	sbom.AddComponent(Component{Name: "lib-c"})

	if sbom.Count() != 3 {
		t.Errorf("Expected count 3, got %d", sbom.Count())
	}
}

func TestHasVulnerableLicense(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	sbom.AddComponent(Component{
		Name:     "lib-a",
		License:  "MIT",
		Supplier: "npm",
	})

	sbom.AddComponent(Component{
		Name:     "lib-b",
		License:  "GPL-2.0",
		Supplier: "pypi",
	})

	vulnerable := []string{"GPL-2.0", "AGPL-3.0"}
	if !sbom.HasVulnerableLicense(vulnerable) {
		t.Error("Expected to detect vulnerable license")
	}

	nonVulnerable := []string{"BSD-3-Clause", "ISC"}
	if sbom.HasVulnerableLicense(nonVulnerable) {
		t.Error("Expected no vulnerable license")
	}
}

func TestAddRelationship(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	sbom.AddRelationship("ref-a", "ref-b", "depends_on")
	sbom.AddRelationship("ref-b", "ref-c", "depends_on")

	if len(sbom.Relationships) != 2 {
		t.Errorf("Expected 2 relationships, got %d", len(sbom.Relationships))
	}

	if sbom.Relationships[0].RefA != "ref-a" {
		t.Errorf("Expected ref-a, got '%s'", sbom.Relationships[0].RefA)
	}

	if sbom.Relationships[0].Relationship != "depends_on" {
		t.Errorf("Expected 'depends_on', got '%s'", sbom.Relationships[0].Relationship)
	}
}

func TestComponentWithHashes(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	comp := Component{
		Name:     "test-lib",
		Version:  "1.0.0",
		Hashes: []Hash{
			{Algorithm: "SHA-256", Value: "abc123"},
			{Algorithm: "MD5", Value: "def456"},
		},
	}

	sbom.AddComponent(comp)

	if len(sbom.Components[0].Hashes) != 2 {
		t.Errorf("Expected 2 hashes, got %d", len(sbom.Components[0].Hashes))
	}

	if sbom.Components[0].Hashes[0].Algorithm != "SHA-256" {
		t.Errorf("Expected 'SHA-256', got '%s'", sbom.Components[0].Hashes[0].Algorithm)
	}
}

func TestComponentWithMetadata(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	comp := Component{
		Name:     "test-lib",
		Version:  "1.0.0",
		Supplier: "npm",
		Metadata: Metadata{
			Author:      "John Doe",
			Publisher:   "Example Corp",
			Description: "A test library",
			HomepageURL: "https://example.com",
		},
	}

	sbom.AddComponent(comp)

	if sbom.Components[0].Metadata.Author != "John Doe" {
		t.Errorf("Expected author 'John Doe', got '%s'", sbom.Components[0].Metadata.Author)
	}

	if sbom.Components[0].Metadata.Description != "A test library" {
		t.Errorf("Expected description, got '%s'", sbom.Components[0].Metadata.Description)
	}
}

func TestEmptySBOM(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	if sbom.Count() != 0 {
		t.Errorf("Expected count 0 for empty SBOM, got %d", sbom.Count())
	}

	if len(sbom.Components) != 0 {
		t.Errorf("Expected empty components slice, got %d", len(sbom.Components))
	}

	if len(sbom.Relationships) != 0 {
		t.Errorf("Expected empty relationships slice, got %d", len(sbom.Relationships))
	}
}

func TestAddDuplicateComponent(t *testing.T) {
	sbom := New("test-app", "1.0.0", "serial-001")

	sbom.AddComponent(Component{Name: "lib-a", Version: "1.0.0"})
	sbom.AddComponent(Component{Name: "lib-a", Version: "2.0.0"})

	if sbom.Count() != 2 {
		t.Errorf("Expected count 2, got %d", sbom.Count())
	}
}