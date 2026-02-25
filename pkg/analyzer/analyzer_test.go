package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectProjectType(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		expected string
	}{
		{"npm project", []string{"package.json"}, "npm"},
		{"pypi project", []string{"requirements.txt"}, "pypi"},
		{"go project", []string{"go.mod"}, "go"},
		{"cargo project", []string{"Cargo.toml"}, "cargo"},
		{"maven project", []string{"pom.xml"}, "maven"},
		{"unknown project", []string{"README.md"}, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "detect-project-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			for _, file := range tt.files {
				if err := os.WriteFile(filepath.Join(tmpDir, file), []byte("test"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
			}

			result := DetectProjectType(tmpDir)
			if result != tt.expected {
				t.Errorf("Expected project type '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestNPMAnalyzer(t *testing.T) {
	analyzer := NewNPMAnalyzer()

	packageJSON := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.0",
			"lodash": "~4.17.0"
		},
		"devDependencies": {
			"jest": "^29.0.0",
			"typescript": "~5.0.0"
		}
	}`

	tmpDir, err := os.MkdirTemp("", "npm-analyzer-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(path, []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	components, err := analyzer.Analyze(path)
	if err != nil {
		t.Fatalf("Failed to analyze: %v", err)
	}

	if len(components) != 4 {
		t.Errorf("Expected 4 components, got %d", len(components))
	}

	if len(components) > 0 {
		if components[0].Supplier != "npm" {
			t.Errorf("Expected supplier 'npm', got '%s'", components[0].Supplier)
		}
		if components[0].PURL == "" {
			t.Error("Expected PURL to be set")
		}
	}
}

func TestNPMAnalyzer_Name(t *testing.T) {
	analyzer := NewNPMAnalyzer()
	if analyzer.Name() != "npm" {
		t.Errorf("Expected name 'npm', got '%s'", analyzer.Name())
	}
}

func TestPyPIAnalyzer(t *testing.T) {
	analyzer := NewPyPIAnalyzer()

	requirements := `requests>=2.28.0
flask==2.2.0
numpy~=1.23.0`

	tmpDir, err := os.MkdirTemp("", "pypi-analyzer-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(path, []byte(requirements), 0644); err != nil {
		t.Fatalf("Failed to write requirements.txt: %v", err)
	}

	components, err := analyzer.Analyze(path)
	if err != nil {
		t.Fatalf("Failed to analyze: %v", err)
	}

	if len(components) != 3 {
		t.Errorf("Expected 3 components, got %d", len(components))
	}

	if len(components) > 0 {
		if components[0].Supplier != "pypi" {
			t.Errorf("Expected supplier 'pypi', got '%s'", components[0].Supplier)
		}
	}
}

func TestPyPIAnalyzer_Name(t *testing.T) {
	analyzer := NewPyPIAnalyzer()
	if analyzer.Name() != "pypi" {
		t.Errorf("Expected name 'pypi', got '%s'", analyzer.Name())
	}
}

func TestGoAnalyzer(t *testing.T) {
	analyzer := NewGoAnalyzer()

	goMod := `module github.com/hallucinaut/test

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
	github.com/go-redis/redis/v8 v8.11.0
)`

	tmpDir, err := os.MkdirTemp("", "go-analyzer-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(path, []byte(goMod), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	components, err := analyzer.Analyze(path)
	if err != nil {
		t.Fatalf("Failed to analyze: %v", err)
	}

	if len(components) != 2 {
		t.Errorf("Expected 2 components, got %d", len(components))
	}

	if len(components) > 0 {
		if components[0].Supplier != "go" {
			t.Errorf("Expected supplier 'go', got '%s'", components[0].Supplier)
		}
	}
}

func TestGoAnalyzer_Name(t *testing.T) {
	analyzer := NewGoAnalyzer()
	if analyzer.Name() != "go" {
		t.Errorf("Expected name 'go', got '%s'", analyzer.Name())
	}
}

func TestCargoAnalyzer(t *testing.T) {
	analyzer := NewCargoAnalyzer()

	cargoToml := `[package]
name = "test-project"
version = "0.1.0"

[dependencies]
serde = { version = "1.0.0" }
tokio = "1.28.0"`

	tmpDir, err := os.MkdirTemp("", "cargo-analyzer-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "Cargo.toml")
	if err := os.WriteFile(path, []byte(cargoToml), 0644); err != nil {
		t.Fatalf("Failed to write Cargo.toml: %v", err)
	}

	components, err := analyzer.Analyze(path)
	if err != nil {
		t.Fatalf("Failed to analyze: %v", err)
	}

	if len(components) != 2 {
		t.Errorf("Expected 2 components, got %d", len(components))
	}

	if len(components) > 0 {
		if components[0].Name != "serde" {
			t.Errorf("Expected 'serde', got '%s'", components[0].Name)
		}
	}
}

func TestCargoAnalyzer_Name(t *testing.T) {
	analyzer := NewCargoAnalyzer()
	if analyzer.Name() != "cargo" {
		t.Errorf("Expected name 'cargo', got '%s'", analyzer.Name())
	}
}

func TestMavenAnalyzer(t *testing.T) {
	analyzer := NewMavenAnalyzer()

	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>3.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>`

	tmpDir, err := os.MkdirTemp("", "maven-analyzer-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	path := filepath.Join(tmpDir, "pom.xml")
	if err := os.WriteFile(path, []byte(pomXML), 0644); err != nil {
		t.Fatalf("Failed to write pom.xml: %v", err)
	}

	components := analyzer.Analyze(path)

	if len(components) != 2 {
		t.Errorf("Expected 2 components, got %d", len(components))
	}

	if len(components) > 0 {
		if components[0].Name != "spring-boot-starter-web" {
			t.Errorf("Expected 'spring-boot-starter-web', got '%s'", components[0].Name)
		}
	}
}

func TestMavenAnalyzer_Name(t *testing.T) {
	analyzer := NewMavenAnalyzer()
	if analyzer.Name() != "maven" {
		t.Errorf("Expected name 'maven', got '%s'", analyzer.Name())
	}
}

func TestNewProjectAnalyzer(t *testing.T) {
	analyzer := NewProjectAnalyzer()

	if analyzer == nil {
		t.Error("Expected non-nil analyzer")
	}
}

func TestProjectAnalyzer_AnalyzeDir(t *testing.T) {
	analyzer := NewProjectAnalyzer()

	tmpDir, err := os.MkdirTemp("", "analyze-dir-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.0"
		}
	}`

	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	components, err := analyzer.AnalyzeDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to analyze directory: %v", err)
	}

	if len(components) != 1 {
		t.Errorf("Expected 1 component, got %d", len(components))
	}
}

func TestProjectAnalyzer_AnalyzeDir_SkipsNodeModules(t *testing.T) {
	analyzer := NewProjectAnalyzer()

	tmpDir, err := os.MkdirTemp("", "analyze-dir-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	packageJSON := `{
		"name": "test-project",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.0"
		}
	}`

	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	nodeModulesDir := filepath.Join(tmpDir, "node_modules")
	if err := os.MkdirAll(nodeModulesDir, 0755); err != nil {
		t.Fatalf("Failed to create node_modules: %v", err)
	}

	components, err := analyzer.AnalyzeDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to analyze directory: %v", err)
	}

	if len(components) != 1 {
		t.Errorf("Expected 1 component (skipping node_modules), got %d", len(components))
	}
}