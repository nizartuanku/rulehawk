package fwrule

// Test hooks for the external equivalence test (fwrule_test imports fwparse,
// which imports fwrule — an in-package test would be an import cycle).
var (
	ShadowAndDuplicateForTest          = shadowAndDuplicate
	ShadowAndDuplicateQuadraticForTest = shadowAndDuplicateQuadratic
)
