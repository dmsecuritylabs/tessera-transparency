module github.com/dmsecuritylabs/tessera-transparency 

go 1.24.0

toolchain go1.24.4

replace golang.org/x/crypto => github.com/golang/crypto v0.48.0

replace golang.org/x/mod => github.com/golang/mod v0.33.0

replace golang.org/x/sync => github.com/golang/sync v0.19.0

replace k8s.io/klog/v2 => github.com/kubernetes/klog/v2 v2.130.1

replace go.opentelemetry.io/otel => github.com/open-telemetry/opentelemetry-go v1.40.0

replace go.opentelemetry.io/otel/metric => github.com/open-telemetry/opentelemetry-go/metric v1.40.0

replace go.opentelemetry.io/otel/trace => github.com/open-telemetry/opentelemetry-go/trace v1.40.0

replace go.opentelemetry.io/auto/sdk => github.com/open-telemetry/opentelemetry-go-instrumentation/sdk v1.2.1

require (
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/transparency-dev/formats v0.0.0-20251017110053-404c0d5b696c // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	github.com/transparency-dev/tessera v1.0.2 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.40.0 // indirect
	go.opentelemetry.io/otel/metric v1.40.0 // indirect
	go.opentelemetry.io/otel/trace v1.40.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20240325151524-a685a6edb6d8 // indirect
	golang.org/x/mod v0.33.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
)

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20240325151524-a685a6edb6d8
