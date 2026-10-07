/*
Copyright 2025 The Kubernetes Authors.

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
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestProcMountRestricted(t *testing.T) {
	defaultValue := corev1.DefaultProcMount
	unmaskedValue := corev1.UnmaskedProcMount
	otherValue := corev1.ProcMountType("other")

	for _, hostUsers := range []bool{true, false} {
		pod := &corev1.Pod{Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "a", SecurityContext: nil},
				{Name: "b", SecurityContext: &corev1.SecurityContext{}},
				{Name: "c", SecurityContext: &corev1.SecurityContext{ProcMount: &defaultValue}},
				{Name: "d", SecurityContext: &corev1.SecurityContext{ProcMount: &unmaskedValue}},
				{Name: "e", SecurityContext: &corev1.SecurityContext{ProcMount: &otherValue}},
			},
			HostUsers: &hostUsers,
		}}
		// the restricted check uses the unconditional 1.0 logic
		result := CheckProcMountRestricted().Versions[0].CheckPod(&pod.ObjectMeta, &pod.Spec)
		if result.Allowed {
			t.Fatalf("hostUsers=%v: expected Allowed to be false", hostUsers)
		}
		if e, a := `procMount`, result.ForbiddenReason; e != a {
			t.Errorf("hostUsers=%v: expected\n%s\ngot\n%s", hostUsers, e, a)
		}
		if e, a := `containers "d", "e" must not set securityContext.procMount to "Unmasked", "other"`, result.ForbiddenDetail; e != a {
			t.Errorf("hostUsers=%v: expected\n%s\ngot\n%s", hostUsers, e, a)
		}
	}
}
