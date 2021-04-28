package main

import (
	"bufio"
	"os"
	"runtime"
	"sync"

	"github.com/spf13/pflag"

	kruntime "k8s.io/apimachinery/pkg/runtime"
	audit "k8s.io/apiserver/pkg/apis/audit"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"

	auditpkg "k8s.io/apiserver/pkg/audit"
)

var nofilter bool
var nofollow bool
var numworkers int
var maxlinelength int

func main() {

	nofilter = false
	nofollow = false

	numworkers = runtime.NumCPU()

	maxlinelength = 1000000

	policyfile := "/run/configmaps/forwarder-policy/policy.yaml"

	inputfiles := []string{
		"/host/var/log/kube-apiserver/audit.log",
		"/host/var/log/openshift-apiserver/audit.log",
		"/host/var/log/oauth-apiserver/audit.log",
	}

	pflag.StringSliceVar(&inputfiles, "input", inputfiles, "audit log file(s) to monitor (can be repeated)")
	pflag.StringVar(&policyfile, "policy", policyfile, "path to forwarder policy")
	pflag.IntVar(&numworkers, "workers", numworkers, "number of filter workers")
	pflag.IntVar(&maxlinelength, "max-line-length", maxlinelength, "reduce level for records larger than this")
	pflag.BoolVar(&nofilter, "no-filter", nofilter, "don't filter any events (for testing)")
	pflag.BoolVar(&nofollow, "no-follow", nofollow, "exit after reaching EOF, don't reopen rotated files")

	pflag.Parse()

	initMetrics()

	LoadPolicy(policyfile)

	lines := OpenFiles(inputfiles...)
	decoded := make(chan audit.Event)
	filtered := make(chan audit.Event)

	go Decode(lines, decoded)
	go Filter(decoded, filtered)
	Encode(filtered)

	printMetrics()

}

// opens fi
func OpenFiles(paths ...string) <-chan []byte {

	var wg sync.WaitGroup
	output := make(chan []byte)

	mux := func(f *RotatingReader, output chan []byte) {
		defer wg.Done()
		reader := bufio.NewReaderSize(f, maxlinelength)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if nofollow {
					return
				}
				continue
			}
			output <- line[:]
			queueDepth.Inc()
		}
	}

	wg.Add(len(paths))
	for _, path := range paths {
		go mux(NewRotatingReader(path), output)
	}

	go func() {
		defer close(output)
		wg.Wait()
	}()

	return output
}

func Decode(in <-chan []byte, out chan audit.Event) {
	defer close(out)
	wg := sync.WaitGroup{}
	for i := 0; i < numworkers; i++ {
		wg.Add(1)
		go func(codec kruntime.Codec) {
			gvk := (&auditv1.Event{}).TypeMeta.GroupVersionKind()
			defer wg.Done()
			for line := range in {
				event := &audit.Event{}
				_, _, err := codec.Decode(line, &gvk, event)
				if err != nil || event == nil {
					queueDepth.Dec()
					errorCounter.Inc()
					continue
				}
				out <- *event
				parsedCounters.Inc()
			}
		}(auditpkg.Codecs.LegacyCodec())
	}
	wg.Wait()
}

func Filter(in chan audit.Event, out chan audit.Event) {
	defer close(out)
	wg := sync.WaitGroup{}
	for i := 0; i < numworkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for event := range in {
				if FilterEvent(&event) && !nofilter {
					queueDepth.Dec()
					continue
				}
				out <- event
			}
		}()
	}
	wg.Wait()
}

func Encode(in chan audit.Event) {
	wg := sync.WaitGroup{}
	for i := 0; i < numworkers; i++ {
		wg.Add(1)
		go func(codec kruntime.Codec) {
			defer wg.Done()
			for event := range in {
				codec.Encode(&event, os.Stdout)
				queueDepth.Dec()
			}
		}(auditpkg.Codecs.LegacyCodec(auditv1.SchemeGroupVersion))
	}
	wg.Wait()
}
