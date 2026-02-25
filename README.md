# sbomgen - Software Bill of Materials Generator

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Generate comprehensive Software Bill of Materials (SBOM) from any project directory.**

Generate SBOMs in multiple formats (SPDX, CycloneDX, JSON, YAML, Markdown) for security auditing, compliance reporting, and supply chain transparency.

## 🚀 Features

- **Multi-format Support**: Generate SBOMs in SPDX, CycloneDX, JSON, YAML, Markdown, and table formats
- **Multi-language Detection**: Automatically detects and analyzes npm, PyPI, Go, Cargo, and Maven projects
- **Recursive Scanning**: Scans directories recursively, intelligently skipping common non-project directories
- **Dependency Tracking**: Tracks direct and transitive dependencies with relationships
- **Compliance Ready**: Generates reports for security audits and regulatory compliance (NIST, PCI-DSS, etc.)
- **Package URL Support**: Includes pURLs for standard component identification
- **Dual Mode**: Use as CLI tool or import as Go module in your projects

## 📦 Installation

### Download Binary

```bash
# Download from releases
curl -LO https://github.com/hallucinaut/sbomgen/releases/download/v1.0.0/sbomgen-linux-amd64
chmod +x sbomgen-linux-amd64
sudo mv sbomgen-linux-amd64 /usr/local/bin/sbomgen
```

### Build from Source

```bash
git clone https://github.com/hallucinaut/sbomgen.git
cd sbomgen
go build -o sbomgen ./cmd/sbomgen
sudo mv sbomgen /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/sbomgen/cmd/sbomgen@latest
```

## 🎯 Usage

### Generate SBOM

```bash
# Basic usage - generates JSON to stdout
sbomgen gen ./myproject

# Output to file in JSON format
sbomgen gen -o sbom.json -f json ./myproject

# Generate in Markdown format
sbomgen gen --format markdown --dir ./myapp -o sbom.md

# Generate CycloneDX format
sbomgen gen -f cyclonedx ./myproject

# Generate SPDX format
sbomgen gen -f spdx ./myproject
```

### Analyze Project

```bash
# Quick analysis - lists all dependencies
sbomgen analyze ./myproject

# Analyze with specific directory
sbomgen analyze --dir ./myapp
```

### Available Formats

| Format | Flag | Use Case |
|--------|------|----------|
| JSON | `json` | Programmatic processing, CI/CD integration |
| YAML | `yaml` | Human-readable, configuration files |
| Markdown | `markdown` | Documentation, reports |
| Table | `table` | Terminal output, quick review |
| SPDX | `spdx` | Standard compliance, regulatory |
| CycloneDX | `cyclonedx` | Security scanning, supply chain |

## 🔧 Programmatic Usage

Import sbomgen as a Go module in your projects:

```go
package main

import (
    "fmt"
    "os"
    
    "github.com/hallucinaut/sbomgen/pkg/analyzer"
    "github.com/hallucinaut/sbomgen/pkg/formatter"
    "github.com/hallucinaut/sbomgen/pkg/sbom"
)

func main() {
    // Create analyzer
    projAnalyzer := analyzer.NewProjectAnalyzer()
    
    // Analyze directory
    components, err := projAnalyzer.AnalyzeDir("./myproject")
    if err != nil {
        panic(err)
    }
    
    // Create SBOM
    sbom := sbom.New("myproject", "1.0.0", "serial-001")
    for _, comp := range components {
        sbom.AddComponent(comp)
    }
    
    // Format output
    jsonFormatter := formatter.NewJSONFormatter()
    output, err := jsonFormatter.Format(sbom)
    if err != nil {
        panic(err)
    }
    
    os.WriteFile("sbom.json", []byte(output), 0644)
    fmt.Println("SBOM generated successfully!")
}
```

## 📋 Supported Package Managers

| Package Manager | Files Detected | Example |
|----------------|----------------|---------|
| npm/yarn | `package.json` | `"express": "^4.18.0"` |
| PyPI/pip | `requirements.txt` | `requests>=2.28.0` |
| Go modules | `go.mod` | `github.com/gin-gonic/gin v1.9.0` |
| Rust/Cargo | `Cargo.toml` | `serde = { version = "1.0.0" }` |
| Maven/Gradle | `pom.xml` | `<artifactId>spring-boot-starter-web</artifactId>` |

## 🏗️ Architecture

```
sbomgen/
├── cmd/
│   └── sbomgen/
│       └── main.go          # CLI entry point
├── pkg/
│   ├── sbom/
│   │   ├── sbom.go          # SBOM data structures
│   │   └── sbom_test.go     # Unit tests
│   ├── analyzer/
│   │   ├── analyzer.go      # Project analyzers
│   │   └── analyzer_test.go # Unit tests
│   └── formatter/
│       ├── formatter.go     # Output formatters
│       └── formatter_test.go # Unit tests
└── README.md
```

## 🧪 Testing

Run all tests:

```bash
go test ./...
go test -v ./pkg/...
```

Run with coverage:

```bash
go test -cover ./...
```

## 📊 Example Output

### JSON Format
```json
{
  "specVersion": "0.24.0",
  "name": "myproject",
  "version": "1.0.0",
  "serialNumber": "serial-001",
  "created": "2024-02-25T12:00:00Z",
  "components": [
    {
      "name": "express",
      "version": "^4.18.0",
      "supplier": "npm",
      "purl": "pkg:npm/express@^4.18.0"
    }
  ]
}
```

### Markdown Format
```markdown
# Software Bill of Materials

**Project:** myproject v1.0.0

**Created:** 2024-02-25 12:00:00 UTC

**Total Components:** 5

## Components

| # | Name | Version | Supplier | License |
|---|------|---------|----------|---------|
| 1 | express | ^4.18.0 | npm | MIT |
| 2 | lodash | ~4.17.0 | npm | MIT |
```

## 🔒 Security Considerations

- SBOMs contain dependency information - handle according to your security policies
- For sensitive projects, consider filtering out internal dependencies
- Regularly update scanned dependencies to identify known vulnerabilities
- Integrate with vulnerability databases (NVD, GitHub Advisory DB) for security scanning

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- SPDX Working Group for SBOM specification
- CycloneDX specification
- Community contributors who made package managers analysis possible

## 🔗 Resources

- [SBOM Specification](https://spdx.github.io/spdx-spec/v2.3/)
- [CycloneDX](https://cyclonedx.org/)
- [OWASP SBOM Guide](https://owasp.org/www-project-sbom/)

---

**Built with ❤️ by [hallucinaut](https://github.com/hallucinaut)**