package main

import (
	"bytes"
	"strings"
	_ "unsafe"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	jsonp "k8s.io/apimachinery/pkg/util/jsonmergepatch"

	lru "github.com/hashicorp/golang-lru"
	audit "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit/event"
	"k8s.io/apiserver/pkg/audit/policy"
	authz "k8s.io/apiserver/pkg/authorization/authorizer"
)

func FilterEvent(event *audit.Event) bool {

	// check the policy first
	if MatchesPolicy(event, filterPolicy) {

		if event.Level == audit.LevelNone {
			return Drop(event) // policy says drop
		}

	} else {

		// rules for events that aren't covered by the policy

		// drop non-resource read-only requests (like openapi discovery)
		if event.ObjectRef == nil && Attributes(event).IsReadOnly() {
			return Drop(event)
		}

		// keep all user events
		if event.User.Username != "" && !(strings.HasPrefix(event.User.Username, "system:")) {
			return Keep(event)
		}

		// drop read-only system events
		if Attributes(event).IsReadOnly() {
			return Drop(event)
		}

		// drop metadata-level system events in openshift-* namespaces
		// this broadly maintains compatibility with the current implementation
		if event.Level.Less(audit.LevelRequest) && event.ObjectRef != nil &&
			strings.HasPrefix(event.ObjectRef.Namespace, "openshift-") {
			return Drop(event)
		}

		// rules for system configmap updates & patches
		if (event.Verb == "update" || event.Verb == "create") &&
			event.ObjectRef.Resource == "configmaps" &&
			event.RequestObject != nil {

			// ca-bundles tend to be too large for splunk
			if event.ObjectRef.Name == "kube-root-ca.crt" ||
				strings.HasSuffix(event.ObjectRef.Name, "-ca") ||
				strings.HasSuffix(event.ObjectRef.Name, "bundle") ||
				bytes.Contains(event.RequestObject.Raw, []byte("ca-bundle.crt")) {
				return Drop(event)
			}

			// leader leases renewals are the 2nd most frequent write request
			if strings.HasSuffix(event.ObjectRef.Name, "-lock") ||
				strings.HasSuffix(event.ObjectRef.Name, "-leader") ||
				bytes.Contains(event.RequestObject.Raw, []byte("kubernetes.io/leader")) {
				return Drop(event)
			}
		}
	}

	// drop conflicts and temporary errors
	if event.ResponseStatus != nil &&
		event.ResponseStatus.Code == 404 || // operators trying to delete non-existent resources
		event.ResponseStatus.Code == 409 || // update conflicts (resource version too old)
		event.ResponseStatus.Code == 422 { // server busy
		return Drop(event)
	}

	// attempt to reduce an update to a patch based the previous update
	if event.Verb == "update" && event.RequestObject != nil && ReduceToPatch(event) {
		event.Annotations["converted-to-patch"] = "true"
	}

	// patch body was '{}', 'null', or empty
	if IsEmptyPatch(event) {
		return Drop(event)
	}

	// downgrade RequestResponse level to Request for updates and patches
	if (event.Verb == "update" || event.Verb == "patch") &&
		event.Level.GreaterOrEqual(audit.LevelRequestResponse) {
		event.Level = audit.LevelRequest
		event.ResponseObject = nil
	}

	// if it's still too big, remove last-applied-configuration annotation
	if EstimateOutputSize(event) > maxlinelength && event.RequestObject != nil {
		event.RequestObject.Raw = RemoveObjectField(
			event.RequestObject.Raw, "metadata", "annotations")
	}

	// if it's STILL too big, reduce level to Metadata and pray
	if EstimateOutputSize(event) > maxlinelength {
		event.Level = audit.LevelMetadata
		event.RequestObject = nil
		event.ResponseObject = nil
	}

	return Keep(event)

}

var filterPolicy *audit.Policy

func LoadPolicy(path string) *audit.Policy {
	var err error
	if filterPolicy == nil {
		filterPolicy, err = policy.LoadPolicyFromFile(path)
		if err != nil {
			panic("error loading policy: " + err.Error())
		}
		if !nofollow {
			go WatchPolicyPath(path)
		}
	}
	return filterPolicy
}

func MatchesPolicy(e *audit.Event, p *audit.Policy) bool {
	for i := range p.Rules {
		r := p.Rules[i]
		if ruleMatches(&r, Attributes(e)) {
			e.Level = audit.Level(r.Level)
			if e.Level.Less(audit.LevelRequestResponse) {
				e.ResponseObject = nil
			}
			if r.Level.Less(audit.LevelRequest) {
				e.RequestObject = nil
			}
			return true
		}
	}
	return false
}

func Attributes(e *audit.Event) authz.Attributes {
	a, _ := event.NewAttributes(e)
	return a
}

//go:linkname ruleMatches k8s.io/apiserver/pkg/audit/policy.ruleMatches
func ruleMatches(*audit.PolicyRule, authz.Attributes) bool

func ReduceToPatch(e *audit.Event) bool {
	if now, then, ok := GetPreviousVersion(e); ok {
		patch, err := jsonp.CreateThreeWayJSONMergePatch(then, now, then)
		if err != nil {
			return false
		}
		e.Verb, e.RequestObject.Raw = "patch", patch
		return true
	}
	return false
}

var cache *lru.Cache

func GetPreviousVersion(e *audit.Event) ([]byte, []byte, bool) {
	if cache == nil {
		cache, _ = lru.New(1000)
	}
	key := strings.SplitN(e.RequestURI, "?", 2)[0]
	now := RemoveObjectField(e.RequestObject.Raw, "metadata")
	now = RemoveObjectField(now, "status")
	defer cache.Add(key, now)
	if val, ok := cache.Get(key); ok {
		if then, ok := val.([]byte); ok {
			return now, then, ok
		}
	}
	return now, nil, false
}

func RemoveObjectField(data []byte, field ...string) []byte {
	obj := &unstructured.Unstructured{}
	obj.UnmarshalJSON([]byte(data))
	unstructured.RemoveNestedField(obj.Object, field...)
	body, _ := obj.MarshalJSON()
	return body
}

func IsEmptyPatch(e *audit.Event) bool {
	if e.Level.GreaterOrEqual(audit.LevelRequest) &&
		e.Verb == "patch" || e.Verb == "update" {
		if e.RequestObject == nil {
			return true
		} else if e.RequestObject.Raw == nil {
			return true
		} else {
			raw := string(e.RequestObject.Raw)
			return raw == "{}" || raw == "null" || raw == ""
		}
	} else if e.Level.GreaterOrEqual(audit.LevelMetadata) {
		return false
	}
	return true
}

// estimate final line size before encoding
func EstimateOutputSize(e *audit.Event) int {
	n := 2000
	if e.RequestObject != nil {
		n = n + len(e.RequestObject.Raw)
	}
	if e.ResponseObject != nil {
		n = n + len(e.ResponseObject.Raw)
	}
	return n
}
