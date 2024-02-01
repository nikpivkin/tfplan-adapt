package main

import (
	"strings"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type Attribute struct {
	val any
}

func (a *Attribute) ToList() []*Attribute {
	val, ok := a.val.([]any)
	if !ok {
		return nil
	}

	res := make([]*Attribute, 0, len(val))
	for _, el := range val {
		m, ok := el.(map[string]any)
		if !ok {
			continue
		}

		res = append(res, &Attribute{m})
	}

	return res
}

func (a *Attribute) GetNestedAttr(path string) *Attribute {

	if path == "" {
		return nil
	}

	parts := strings.SplitN(path, ".", 2)
	var m map[string]any

	if val, ok := a.val.([]any); ok {
		if len(val) == 0 {
			return nil
		}
		m, ok = val[0].(map[string]any)
		if !ok {
			return nil
		}
	} else if val, ok := a.val.(map[string]any); ok {
		m = val
	}

	attr := &Attribute{m[parts[0]]}

	if len(parts) == 1 {
		return attr
	}

	return attr.GetNestedAttr(parts[1])
}

func (a *Attribute) GetStringAttr(path string) defsecTypes.StringValue {
	def := defsecTypes.StringDefault("", defsecTypes.Metadata{})
	if a.IsNil() {
		return def
	}

	nested := a.GetNestedAttr(path)
	val := nested.AsString()
	if val == nil {
		return def
	}
	return defsecTypes.String(*val, defsecTypes.Metadata{})
}

func (a *Attribute) GetBoolAttr(path string) defsecTypes.BoolValue {
	def := defsecTypes.BoolDefault(false, defsecTypes.Metadata{})
	if a.IsNil() {
		return def
	}

	nested := a.GetNestedAttr(path)
	val := nested.AsBool()
	if val == nil {
		return def
	}

	return defsecTypes.Bool(*val, defsecTypes.Metadata{})
}

// TODO
func (a *Attribute) AsBool() *bool {
	if a.IsNil() {
		return nil
	}

	val, ok := a.val.(bool)
	if !ok {
		return nil
	}
	return &val
}

func (a *Attribute) AsString() *string {
	if a.IsNil() {
		return nil
	}

	val, ok := a.val.(string)
	if !ok {
		return nil
	}
	return &val
}

func (a *Attribute) IsNil() bool {
	return a == nil || a.val == nil
}
