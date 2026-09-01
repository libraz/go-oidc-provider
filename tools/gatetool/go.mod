// Module gatetool implements the gate-topology check used by
// scripts/gates.sh and `make gates`. It is a separate Go module so its
// YAML dependency does not bleed into the main module's go.sum, and so
// the gate can run while the main module is mid-edit.
module github.com/libraz/go-oidc-provider/tools/gatetool

go 1.25.0

toolchain go1.27.0

require gopkg.in/yaml.v3 v3.0.1
