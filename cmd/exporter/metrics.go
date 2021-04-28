package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	metrics "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"
	audit "k8s.io/apiserver/pkg/apis/audit"
)

const namespace string = "splunkforwarder"
const subsystem string = "audit_policy"

var (
	parsedCounters = metrics.NewCounter(
		metrics.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "events_total",
			Help:      "count of events parsed",
		})

	acceptCounter = metrics.NewCounterVec(
		metrics.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "events_accepted",
			Help:      "count of accepted events",
		}, []string{"verb", "resource"})

	droppedCounter = metrics.NewCounterVec(
		metrics.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "events_dropped",
			Help:      "count of dropped events",
		}, []string{"verb", "resource"})

	processedCounter = metrics.NewCounterVec(
		metrics.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "events_processed_total",
			Help:      "count of processed events",
		}, []string{"verdict"})

	errorCounter = metrics.NewCounter(
		metrics.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "errors_total",
			Help:      "count of encoding or decoding errors",
		})

	queueDepth = metrics.NewGauge(
		metrics.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "queue_depth",
			Help:      "number of events waiting to be processed",
		})
)

var registry *prometheus.Registry

func initMetrics() {

	prometheus.MustRegister(parsedCounters, acceptCounter, droppedCounter, errorCounter, processedCounter)
	prometheus.Register(queueDepth)

	http.Handle("/metrics", promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		Registry: prometheus.DefaultRegisterer,
	}))
	go http.ListenAndServe(":9090", nil)

}

func printMetrics() {
	mfs, _ := prometheus.DefaultGatherer.Gather()
	w := expfmt.NewEncoder(os.Stderr, expfmt.FmtOpenMetrics)
	for _, mf := range mfs {
		if err := w.Encode(mf); err != nil {
			panic(err)
		}
	}
}

func CounterLabels(e *audit.Event) prometheus.Labels {
	r := e.RequestURI
	if e.ObjectRef != nil {
		r = e.ObjectRef.Resource
		if e.ObjectRef.Subresource != "" {
			r = r + "/" + e.ObjectRef.Subresource
		}
	}
	return prometheus.Labels(map[string]string{
		"verb":     e.Verb,
		"resource": r,
	})
}

func CounterInc(e *audit.Event, counter *prometheus.CounterVec) {
	counter.With(CounterLabels(e)).Inc()
}

func Drop(e *audit.Event) bool {
	droppedCounter.With(CounterLabels(e)).Inc()
	processedCounter.WithLabelValues("drop").Inc()
	return true
}

func Keep(e *audit.Event) bool {
	acceptCounter.With(CounterLabels(e)).Inc()
	processedCounter.WithLabelValues("accept").Inc()
	return false
}
