// Module scenariotool implements the catalog validator and coverage
// reporter used by scripts/scenario.sh and `make scenario-*`. It is a
// separate Go module so its YAML / JSON-Schema dependencies do not
// bleed into the main module's go.sum.
module github.com/libraz/go-oidc-provider/tools/scenariotool

go 1.25.0

toolchain go1.26.4

require gopkg.in/yaml.v3 v3.0.1
