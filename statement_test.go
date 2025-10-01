// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

import "testing"

type fakeSubject struct {
	name, uri string
	digest    map[string]string
}

func (fs *fakeSubject) GetName() string {
	return fs.name
}

func (fs *fakeSubject) GetUri() string {
	return fs.uri
}

func (fs *fakeSubject) GetDigest() map[string]string {
	return fs.digest
}

func TestSubjectsMatch(t *testing.T) {
	tests := []struct {
		name     string
		s1       Subject
		s2       Subject
		expected bool
	}{
		{
			name:     "single-identical",
			s1:       &fakeSubject{digest: map[string]string{"sha256": "abc123"}},
			s2:       &fakeSubject{digest: map[string]string{"sha256": "abc123"}},
			expected: true,
		},
		{
			name:     "identical-multiple-match",
			s1:       &fakeSubject{digest: map[string]string{"sha256": "abc123", "sha512": "def456"}},
			s2:       &fakeSubject{digest: map[string]string{"sha256": "abc123", "sha512": "def456"}},
			expected: true,
		},
		{
			name:     "hash-mismatch",
			s1:       &fakeSubject{digest: map[string]string{"sha256": "abc123"}},
			s2:       &fakeSubject{digest: map[string]string{"sha256": "xyz789"}},
			expected: false,
		},
		{
			name:     "no-common",
			s1:       &fakeSubject{digest: map[string]string{"sha256": "abc123"}},
			s2:       &fakeSubject{digest: map[string]string{"sha512": "def456"}},
			expected: false,
		},
		{
			name:     "empty-s1",
			s1:       &fakeSubject{digest: map[string]string{}},
			s2:       &fakeSubject{digest: map[string]string{"sha256": "abc123"}},
			expected: false,
		},
		{
			name:     "partial-overlap-with-match",
			s1:       &fakeSubject{digest: map[string]string{"sha256": "abc123", "sha512": "def456"}},
			s2:       &fakeSubject{digest: map[string]string{"sha256": "abc123", "md5": "ghi789"}},
			expected: true,
		},
		{
			name:     "partial-overlap-with-mismatch",
			s1:       &fakeSubject{digest: map[string]string{"sha256": "abc123", "sha512": "def456"}},
			s2:       &fakeSubject{digest: map[string]string{"sha256": "different", "md5": "ghi789"}},
			expected: false,
		},
		{
			name:     "s2-subset-s1-with-match",
			s1:       &fakeSubject{digest: map[string]string{"sha256": "abc123", "sha512": "def456", "md5": "ghi789"}},
			s2:       &fakeSubject{digest: map[string]string{"sha256": "abc123"}},
			expected: true,
		},
		{
			name:     "multiple-common-with-mismatch",
			s1:       &fakeSubject{digest: map[string]string{"sha256": "abc123", "sha512": "def456"}},
			s2:       &fakeSubject{digest: map[string]string{"sha256": "abc123", "sha512": "wrong"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SubjectsMatch(tt.s1, tt.s2)
			if result != tt.expected {
				t.Errorf("SubjectsMatch() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
