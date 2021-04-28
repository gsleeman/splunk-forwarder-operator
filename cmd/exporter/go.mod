module audit-log-exporter

go 1.13

require (
	github.com/fsnotify/fsnotify v1.4.9
	github.com/hashicorp/golang-lru v0.5.4
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.10.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/sys v0.0.0-20210426230700-d19ff857e887 // indirect
	k8s.io/apimachinery v0.21.0
	k8s.io/apiserver v0.21.0
)
