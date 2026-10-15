/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package policy

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/pod-security-admission/api"
)

/*
Host field is restricted in the probes and lifecycle handlers.

**Restricted Fields:**

* spec.containers[*].livenessProbe.httpGet.host
* spec.containers[*].readinessProbe.httpGet.host
* spec.containers[*].startupProbe.httpGet.host
* spec.containers[*].livenessProbe.tcpSocket.host
* spec.containers[*].readinessProbe.tcpSocket.host
* spec.containers[*].startupProbe.tcpSocket.host
* spec.containers[*].lifecycle.postStart.tcpSocket.host // Deprecated. TCPSocket is NOT supported as a LifecycleHandler and kept for backward compatibility.
* spec.containers[*].lifecycle.preStop.tcpSocket.host // Deprecated. TCPSocket is NOT supported as a LifecycleHandler and kept for backward compatibility.
* spec.containers[*].lifecycle.postStart.httpGet.host
* spec.containers[*].lifecycle.preStop.httpGet.host
* spec.initContainers[*].livenessProbe.httpGet.host
* spec.initContainers[*].readinessProbe.httpGet.host
* spec.initContainers[*].startupProbe.httpGet.host
* spec.initContainers[*].livenessProbe.tcpSocket.host
* spec.initContainers[*].readinessProbe.tcpSocket.host
* spec.initContainers[*].startupProbe.tcpSocket.host
* spec.initContainers[*].lifecycle.postStart.tcpSocket.host // Deprecated. TCPSocket is NOT supported as a LifecycleHandler and kept for backward compatibility.
* spec.initContainers[*].lifecycle.preStop.tcpSocket.host // Deprecated. TCPSocket is NOT supported as a LifecycleHandler and kept for backward compatibility.
* spec.initContainers[*].lifecycle.postStart.httpGet.host
* spec.initContainers[*].lifecycle.preStop.httpGet.host

Allowed Values: "", undefined/null
*/

func init() {
	addCheck(CheckHostProbesAndHostLifecycle)
}

// CheckHostProbesAndHostLifecycle returns a baseline level check
// that forbids setting host field in probes and lifecycle handlers in 1.34+
func CheckHostProbesAndHostLifecycle() Check {
	return Check{
		ID:    "hostProbesAndHostLifecycle",
		Level: api.LevelBaseline,
		Versions: []VersionedCheck{
			{
				MinimumVersion: api.MajorMinorVersion(1, 34),
				CheckPod:       withOptions(hostProbesAndHostLifecycleV1Dot34),
			},
		},
	}
}

func hostProbesAndHostLifecycleV1Dot34(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	badContainers := sets.New[string]()
	forbiddenHosts := sets.New[string]()
	var errs field.ErrorList
	visitContainers(podSpec, opts, func(container *corev1.Container, path *field.Path) {
		// Check probes
		if badHosts, probeErrs := getForbiddenHostProbes(container.LivenessProbe, path.Child("livenessProbe"), opts.withFieldErrors); len(badHosts) > 0 {
			badContainers.Insert(container.Name)
			forbiddenHosts.Insert(badHosts...)
			errs = append(errs, probeErrs...)
		}
		if badHosts, probeErrs := getForbiddenHostProbes(container.ReadinessProbe, path.Child("readinessProbe"), opts.withFieldErrors); len(badHosts) > 0 {
			badContainers.Insert(container.Name)
			forbiddenHosts.Insert(badHosts...)
			errs = append(errs, probeErrs...)
		}
		if badHosts, probeErrs := getForbiddenHostProbes(container.StartupProbe, path.Child("startupProbe"), opts.withFieldErrors); len(badHosts) > 0 {
			badContainers.Insert(container.Name)
			forbiddenHosts.Insert(badHosts...)
			errs = append(errs, probeErrs...)
		}

		// Check lifecycle handlers
		if container.Lifecycle != nil {
			if badHosts, lifecycleErrs := getForbiddenHostLifecycle(container.Lifecycle.PostStart, path.Child("lifecycle", "postStart"), opts.withFieldErrors); len(badHosts) > 0 {
				badContainers.Insert(container.Name)
				forbiddenHosts.Insert(badHosts...)
				errs = append(errs, lifecycleErrs...)
			}
			if badHosts, lifecycleErrs := getForbiddenHostLifecycle(container.Lifecycle.PreStop, path.Child("lifecycle", "preStop"), opts.withFieldErrors); len(badHosts) > 0 {
				badContainers.Insert(container.Name)
				forbiddenHosts.Insert(badHosts...)
				errs = append(errs, lifecycleErrs...)
			}
		}
	})

	if len(badContainers) > 0 {
		result := CheckResult{
			Allowed:         false,
			ForbiddenReason: "probe or lifecycle host",
			ForbiddenDetail: fmt.Sprintf(
				"%s %s %s %s %s",
				pluralize("container", "containers", len(badContainers)),
				joinQuote(sets.List(badContainers)),
				pluralize("uses", "use", len(badContainers)),
				pluralize("probe or lifecycle host", "probe or lifecycle hosts", len(forbiddenHosts)),
				joinQuote(sets.List(forbiddenHosts)),
			),
		}
		if opts.withFieldErrors {
			result.ErrList = &errs
		}
		return result
	}
	return CheckResult{Allowed: true}
}

func getForbiddenHostProbes(probe *corev1.Probe, path *field.Path, withFieldErrors bool) ([]string, field.ErrorList) {
	var badHosts []string
	var errs field.ErrorList
	if probe == nil {
		return nil, nil
	}
	if probe.HTTPGet != nil && probe.HTTPGet.Host != "" {
		badHosts = append(badHosts, probe.HTTPGet.Host)
		if withFieldErrors {
			errs = append(errs, withBadValue(forbidden(path.Child("httpGet", "host")), probe.HTTPGet.Host))
		}
	}
	if probe.TCPSocket != nil && probe.TCPSocket.Host != "" {
		badHosts = append(badHosts, probe.TCPSocket.Host)
		if withFieldErrors {
			errs = append(errs, withBadValue(forbidden(path.Child("tcpSocket", "host")), probe.TCPSocket.Host))
		}
	}
	return badHosts, errs
}

func getForbiddenHostLifecycle(handler *corev1.LifecycleHandler, path *field.Path, withFieldErrors bool) ([]string, field.ErrorList) {
	var badHosts []string
	var errs field.ErrorList
	if handler == nil {
		return nil, nil
	}
	if handler.HTTPGet != nil && handler.HTTPGet.Host != "" {
		badHosts = append(badHosts, handler.HTTPGet.Host)
		if withFieldErrors {
			errs = append(errs, withBadValue(forbidden(path.Child("httpGet", "host")), handler.HTTPGet.Host))
		}
	}
	if handler.TCPSocket != nil && handler.TCPSocket.Host != "" {
		badHosts = append(badHosts, handler.TCPSocket.Host)
		if withFieldErrors {
			errs = append(errs, withBadValue(forbidden(path.Child("tcpSocket", "host")), handler.TCPSocket.Host))
		}
	}
	return badHosts, errs
}
