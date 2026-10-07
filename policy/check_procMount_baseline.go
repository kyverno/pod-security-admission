/*
Copyright 2021 The Kubernetes Authors.

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

The default /proc masks are set up to reduce attack surface, and should be required
by the baseline policy unless the pod is in a user namespace ("hostUsers: false").

**Restricted Fields:**
spec.containers[*].securityContext.procMount
spec.initContainers[*].securityContext.procMount

**Allowed Values:** undefined/null, "Default" (or any value if "hostUsers" is false)
*/

func init() {
	addCheck(CheckProcMountBaseline)
}

// CheckProcMountBaseline returns a baseline level check that restricts
// setting the value of securityContext.procMount to DefaultProcMount
// in 1.0+.
// Starting in 1.35+, any value is allowed if the pod is in a user namespace ("hostUsers: false").
func CheckProcMountBaseline() Check {
	return Check{
		ID:    "procMount",
		Level: api.LevelBaseline,
		Versions: []VersionedCheck{
			{
				MinimumVersion: api.MajorMinorVersion(1, 0),
				CheckPod:       withOptions(procMount_1_0),
			},
			{
				MinimumVersion: api.MajorMinorVersion(1, 35),
				CheckPod:       withOptions(procMount1_35baseline),
			},
		},
	}
}

// procMount1_35baseline blocks unmasked procMount for pods that are not in a user namespace
func procMount1_35baseline(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	if relaxPolicyForUserNamespacePod(podSpec) {
		return CheckResult{Allowed: true}
	}
	// If the pod is not in a user namespace, treat it as restricted.
	return procMount_1_0(podMetadata, podSpec, opts)
}

// procMount_1_0 blocks unmasked procMount unconditionally
func procMount_1_0(podMetadata *metav1.ObjectMeta, podSpec *corev1.PodSpec, opts options) CheckResult {
	badContainers := NewViolations(opts.withFieldErrors)

	forbiddenProcMountTypes := sets.NewString()
	visitContainers(podSpec, opts, func(container *corev1.Container, path *field.Path) {
		// allow if the security context is nil.
		if container.SecurityContext == nil {
			return
		}
		// allow if proc mount is not set.
		if container.SecurityContext.ProcMount == nil {
			return
		}
		// check if the value of the proc mount type is valid.
		if *container.SecurityContext.ProcMount != corev1.DefaultProcMount {
			if opts.withFieldErrors {
				badContainers.Add(container.Name, withBadValue(forbidden(path.Child("securityContext", "procMount")), string(*container.SecurityContext.ProcMount)))
			} else {
				badContainers.Add(container.Name)
			}
			forbiddenProcMountTypes.Insert(string(*container.SecurityContext.ProcMount))
		}
	})
	if !badContainers.Empty() {
		return CheckResult{
			Allowed:         false,
			ForbiddenReason: "procMount",
			ForbiddenDetail: fmt.Sprintf(
				"%s %s must not set securityContext.procMount to %s",
				pluralize("container", "containers", badContainers.Len()),
				joinQuote(badContainers.Data()),
				joinQuote(forbiddenProcMountTypes.List()),
			),
			ErrList: badContainers.Errs(),
		}
	}
	return CheckResult{Allowed: true}
}
