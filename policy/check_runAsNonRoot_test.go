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
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	utilpointer "k8s.io/utils/pointer"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRunAsNonRoot(t *testing.T) {
	tests := []struct {
		name           string
		pod            *corev1.Pod
		opts           options
		expectReason   string
		expectDetail   string
		expectErrList  field.ErrorList
		expectAllowed  bool
		relaxForUserNS bool
	}{
		{
			name: "no explicit runAsNonRoot",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "a"},
				},
			}},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `pod or container "a" must set securityContext.runAsNonRoot=true`,
		},
		{
			name: "no explicit runAsNonRoot, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "a"},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `pod or container "a" must set securityContext.runAsNonRoot=true`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeRequired, Field: "spec.containers[0].securityContext.runAsNonRoot", BadValue: ""},
			},
		},
		{
			name: "pod runAsNonRoot=false",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: utilpointer.Bool(false)},
				Containers: []corev1.Container{
					{Name: "a", SecurityContext: nil},
				},
			}},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `pod must not set securityContext.runAsNonRoot=false
pod or container "a" must set securityContext.runAsNonRoot=true`,
		},
		{
			name: "pod runAsNonRoot=false, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: utilpointer.Bool(false)},
				Containers: []corev1.Container{
					{Name: "a", SecurityContext: nil},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `pod must not set securityContext.runAsNonRoot=false
pod or container "a" must set securityContext.runAsNonRoot=true`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeForbidden, Field: "spec.securityContext.runAsNonRoot", BadValue: false},
				{Type: field.ErrorTypeRequired, Field: "spec.containers[0].securityContext.runAsNonRoot", BadValue: ""},
			},
		},
		{
			name: "containers runAsNonRoot=false",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: utilpointer.Bool(true)},
				Containers: []corev1.Container{
					{Name: "a", SecurityContext: nil},
					{Name: "b", SecurityContext: &corev1.SecurityContext{}},
					{Name: "c", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(false)}},
					{Name: "d", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(false)}},
					{Name: "e", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(true)}},
					{Name: "f", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(true)}},
				},
			}},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `containers "c", "d" must not set securityContext.runAsNonRoot=false`,
		},
		{
			name: "containers runAsNonRoot=false, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: utilpointer.Bool(true)},
				Containers: []corev1.Container{
					{Name: "a", SecurityContext: nil},
					{Name: "b", SecurityContext: &corev1.SecurityContext{}},
					{Name: "c", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(false)}},
					{Name: "d", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(false)}},
					{Name: "e", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(true)}},
					{Name: "f", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(true)}},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `containers "c", "d" must not set securityContext.runAsNonRoot=false`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeForbidden, Field: "spec.containers[2].securityContext.runAsNonRoot", BadValue: false},
				{Type: field.ErrorTypeForbidden, Field: "spec.containers[3].securityContext.runAsNonRoot", BadValue: false},
			},
		},
		{
			name: "pod nil, container fallthrough",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "a", SecurityContext: nil},
					{Name: "b", SecurityContext: &corev1.SecurityContext{}},
					{Name: "d", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(true)}},
					{Name: "e", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(true)}},
				},
			}},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `pod or containers "a", "b" must set securityContext.runAsNonRoot=true`,
		},
		{
			name: "pod nil, container fallthrough, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "a", SecurityContext: nil},
					{Name: "b", SecurityContext: &corev1.SecurityContext{}},
					{Name: "d", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(true)}},
					{Name: "e", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(true)}},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `pod or containers "a", "b" must set securityContext.runAsNonRoot=true`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeRequired, Field: "spec.containers[0].securityContext.runAsNonRoot", BadValue: ""},
				{Type: field.ErrorTypeRequired, Field: "spec.containers[1].securityContext.runAsNonRoot", BadValue: ""},
			},
		},
		{
			name: "pod nil, container nil, initContainer runAsNonRoot=false",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "i", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(false)}},
				},
				Containers: []corev1.Container{
					{Name: "a", SecurityContext: nil},
				},
			}},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `container "i" must not set securityContext.runAsNonRoot=false
pod or container "a" must set securityContext.runAsNonRoot=true`,
		},
		{
			name: "pod nil, container nil, initContainer runAsNonRoot=false, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{Name: "i", SecurityContext: &corev1.SecurityContext{RunAsNonRoot: utilpointer.Bool(false)}},
				},
				Containers: []corev1.Container{
					{Name: "a", SecurityContext: nil},
				},
			}},
			opts: options{
				withFieldErrors: true,
			},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `container "i" must not set securityContext.runAsNonRoot=false
pod or container "a" must set securityContext.runAsNonRoot=true`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeForbidden, Field: "spec.initContainers[0].securityContext.runAsNonRoot", BadValue: false},
				{Type: field.ErrorTypeRequired, Field: "spec.containers[0].securityContext.runAsNonRoot", BadValue: ""},
			},
		},
		{
			name: "UserNamespacesPodSecurityStandards enabled without HostUsers",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				HostUsers: utilpointer.Bool(false),
			}},
			expectAllowed:  true,
			relaxForUserNS: true,
		},
		{
			name: "UserNamespacesPodSecurityStandards enabled without HostUsers, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				HostUsers: utilpointer.Bool(false),
			}},
			opts: options{
				withFieldErrors: true,
			},
			expectAllowed:  true,
			relaxForUserNS: true,
		},
		{
			name: "UserNamespacesPodSecurityStandards enabled with HostUsers",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "a"},
				},
				HostUsers: utilpointer.Bool(true),
			}},
			expectReason:   `runAsNonRoot != true`,
			expectDetail:   `pod or container "a" must set securityContext.runAsNonRoot=true`,
			expectAllowed:  false,
			relaxForUserNS: true,
		},
		{
			name: "UserNamespacesPodSecurityStandards enabled with HostUsers, enable field error list",
			pod: &corev1.Pod{Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "a"},
				},
				HostUsers: utilpointer.Bool(true),
			}},
			opts: options{
				withFieldErrors: true,
			},
			expectReason: `runAsNonRoot != true`,
			expectDetail: `pod or container "a" must set securityContext.runAsNonRoot=true`,
			expectErrList: field.ErrorList{
				{Type: field.ErrorTypeRequired, Field: "spec.containers[0].securityContext.runAsNonRoot", BadValue: ""},
			},
			expectAllowed:  false,
			relaxForUserNS: true,
		},
	}

	cmpOpts := []cmp.Option{cmpopts.IgnoreFields(field.Error{}, "Detail"), cmpopts.SortSlices(func(a, b *field.Error) bool { return a.Error() < b.Error() })}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.relaxForUserNS {
				RelaxPolicyForUserNamespacePods(true)
				t.Cleanup(func() {
					RelaxPolicyForUserNamespacePods(false)
				})
			}
			result := runAsNonRootV1Dot0(&tc.pod.ObjectMeta, &tc.pod.Spec, tc.opts)
			if result.Allowed != tc.expectAllowed {
				t.Fatalf("expected Allowed to be %v was %v", tc.expectAllowed, result.Allowed)
			}
			if e, a := tc.expectReason, result.ForbiddenReason; e != a {
				t.Errorf("expected\n%s\ngot\n%s", e, a)
			}
			if e, a := tc.expectDetail, result.ForbiddenDetail; e != a {
				t.Errorf("expected\n%s\ngot\n%s", e, a)
			}
			if result.ErrList != nil {
				if diff := cmp.Diff(tc.expectErrList, *result.ErrList, cmpOpts...); diff != "" {
					t.Errorf("unexpected field errors (-want,+got):\n%s", diff)
				}
			}
		})
	}
}
