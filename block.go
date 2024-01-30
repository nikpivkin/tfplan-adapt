package main

import (
	"fmt"
	"strings"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	tfjson "github.com/hashicorp/terraform-json"
)

// Wrap for [tfjson.StateResource]
type block struct {
	inner      *tfjson.StateResource
	attributes map[string]*attribute
	plan       *PlanState
}

func (b *block) Address() string {
	return b.inner.Address
}

func (b *block) GetAttr(name string) *attribute {
	return b.attributes[name]
}

func (b *block) GetNestedAttr(path string) *attribute {
	if path == "" {
		return nil
	}

	parts := strings.SplitN(path, ".", 2)
	attr := b.GetAttr(parts[0])
	if attr == nil {
		return nil
	}
	if len(parts) == 1 {
		return attr
	}
	return attr.GetNestedAttr(parts[1])
}

func (b *block) FieldPath(field string) string {
	return fmt.Sprintf("%s.%s", b.inner.Address, field)
}

func (b *block) GetBoolAttr(name string) defsecTypes.BoolValue {
	def := defsecTypes.BoolDefault(false, defsecTypes.Metadata{})
	attr, exists := b.attributes[name]
	if !exists {
		return def
	}
	val := attr.AsBool()
	if val == nil {
		return def
	}

	return defsecTypes.Bool(*val, defsecTypes.Metadata{})
}

func (b *block) GetStringAttr(name string) defsecTypes.StringValue {
	def := defsecTypes.StringDefault("", defsecTypes.Metadata{})
	attr, exists := b.attributes[name]
	if !exists {
		return def
	}
	val := attr.AsString()
	if val == nil {
		return def
	}

	return defsecTypes.String(*val, defsecTypes.Metadata{})
}
