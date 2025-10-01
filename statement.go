// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package attestation

// PredicateType overloads basic string to express predicate types.
type PredicateType string

// Statement mimica the in-toto statement in an interface to access its contents.
// and extends it to retrieve any signature verification data.
type Statement interface {
	GetSubjects() []Subject
	GetPredicate() Predicate
	GetPredicateType() PredicateType
	GetType() string
	GetVerification() Verification
}

// Predicate defines the methods that predicate handlers should implement to
// be compatible with the framework.
type Predicate interface {
	GetType() PredicateType
	SetType(PredicateType) error
	GetParsed() any
	GetData() []byte
	GetVerification() Verification
	GetOrigin() Subject
	SetOrigin(Subject)
	SetVerification(Verification)
}

// Subject abstracts a piece of software covered by an attestation. The purpose
// of the subject interface is to be able to define more methods on top of the
// standard in-toto ResourceDescriptor.
type Subject interface {
	GetName() string
	GetUri() string
	GetDigest() map[string]string
}

// SubjectsMatch compares two subjects and returns a boolean indicate if they
// are the same. Ideally this function should compare the full resource descriptor
// fields but, for now, it only checks that the hashes from s2 which are
// present in s1 match.
func SubjectsMatch(s1, s2 Subject) bool {
	hashes1 := s1.GetDigest()
	hashes2 := s2.GetDigest()
	if len(hashes1) == 0 {
		return false
	}

	// To match, all common algos in s1 and s2 must match and there has
	// to be at least one common algorithm hash.
	matches := 0
	for algo, val1 := range hashes1 {
		if val2, ok := hashes2[algo]; ok {
			matches++
			if val1 != val2 {
				return false
			}
		}
	}
	return matches > 1
}
