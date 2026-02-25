// Package sbom provides Software Bill of Materials data structures and utilities.
package sbom

import (
	"time"
)

// Component represents a software component in the SBOM.
type Component struct {
	Name         string    `json:"name" yaml:"name"`
	Version      string    `json:"version" yaml:"version"`
	Supplier     string    `json:"supplier,omitempty" yaml:"supplier,omitempty"`
	License      string    `json:"license,omitempty" yaml:"license,omitempty"`
	PURL         string    `json:"purl,omitempty" yaml:"purl,omitempty"`
	CPE          string    `json:"cpe,omitempty" yaml:"cpe,omitempty"`
	Metadata     Metadata  `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Dependencies []string  `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Hashes       []Hash    `json:"hashes,omitempty" yaml:"hashes,omitempty"`
}

// Metadata contains additional information about a component.
type Metadata struct {
	Author       string    `json:"author,omitempty" yaml:"author,omitempty"`
	Publisher    string    `json:"publisher,omitempty" yaml:"publisher,omitempty"`
	Description  string    `json:"description,omitempty" yaml:"description,omitempty"`
	HomepageURL  string    `json:"homepage_url,omitempty" yaml:"homepage_url,omitempty"`
	SourceURL    string    `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	LastModified time.Time `json:"last_modified,omitempty" yaml:"last_modified,omitempty"`
}

// Hash represents a cryptographic hash of a component.
type Hash struct {
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	Value     string `json:"value" yaml:"value"`
}

// SBOM represents the complete Software Bill of Materials.
type SBOM struct {
	SpecVersion   string      `json:"specVersion" yaml:"specVersion"`
	Name          string      `json:"name" yaml:"name"`
	Version       string      `json:"version" yaml:"version"`
	SerialNumber  string      `json:"serialNumber" yaml:"serialNumber"`
	Created       time.Time   `json:"created" yaml:"created"`
	Author        string      `json:"author,omitempty" yaml:"author,omitempty"`
	Provider      string      `json:"provider,omitempty" yaml:"provider,omitempty"`
	Description   string      `json:"description,omitempty" yaml:"description,omitempty"`
	Components    []Component `json:"components" yaml:"components"`
	Relationships []Relationship `json:"relationships,omitempty" yaml:"relationships,omitempty"`
	Annotations   []Annotation `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// Relationship represents a relationship between components.
type Relationship struct {
	RefA         string `json:"refA" yaml:"refA"`
	RefB         string `json:"refB" yaml:"refB"`
	Relationship string `json:"relationship" yaml:"relationship"`
}

// Annotation represents an annotation on the SBOM.
type Annotation struct {
	ComponentRef string    `json:"componentRef" yaml:"componentRef"`
	EventType    string    `json:"eventType" yaml:"eventType"`
	Time         time.Time `json:"time" yaml:"time"`
	Summary      string    `json:"summary" yaml:"summary"`
}

// New creates a new empty SBOM instance.
func New(name, version, serialNumber string) *SBOM {
	return &SBOM{
		SpecVersion:   "0.24.0",
		Name:          name,
		Version:       version,
		SerialNumber:  serialNumber,
		Created:       time.Now().UTC(),
		Components:    make([]Component, 0),
		Relationships: make([]Relationship, 0),
		Annotations:   make([]Annotation, 0),
	}
}

// AddComponent adds a component to the SBOM.
func (s *SBOM) AddComponent(component Component) {
	s.Components = append(s.Components, component)
}

// AddRelationship adds a relationship between components.
func (s *SBOM) AddRelationship(refA, refB, relationship string) {
	s.Relationships = append(s.Relationships, Relationship{
		RefA:         refA,
		RefB:         refB,
		Relationship: relationship,
	})
}

// GetComponentByPURL finds a component by its package URL.
func (s *SBOM) GetComponentByPURL(purl string) *Component {
	for i := range s.Components {
		if s.Components[i].PURL == purl {
			return &s.Components[i]
		}
	}
	return nil
}

// GetComponentsByLicense returns components matching a license.
func (s *SBOM) GetComponentsByLicense(license string) []Component {
	var result []Component
	for _, comp := range s.Components {
		if comp.License == license {
			result = append(result, comp)
		}
	}
	return result
}

// Count returns the total number of components.
func (s *SBOM) Count() int {
	return len(s.Components)
}

// HasVulnerableLicense checks if any component has a vulnerable license.
func (s *SBOM) HasVulnerableLicense(licenses []string) bool {
	for _, comp := range s.Components {
		for _, vuln := range licenses {
			if comp.License == vuln {
				return true
			}
		}
	}
	return false
}