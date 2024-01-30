package main

import (
	"strings"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

type attribute struct {
	val any
}

func (a *attribute) ToList() []*attribute {
	val, ok := a.val.([]any)
	if !ok {
		return nil
	}

	res := make([]*attribute, 0, len(val))
	for _, el := range val {
		m, ok := el.(map[string]any)
		if !ok {
			continue
		}

		res = append(res, &attribute{m})
	}

	return res
}

func (a *attribute) GetNestedAttr(path string) *attribute {

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

	attr := &attribute{m[parts[0]]}

	if len(parts) == 1 {
		return attr
	}

	return attr.GetNestedAttr(parts[1])
}

func (a *attribute) GetStringAttr(path string) defsecTypes.StringValue {
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

func (a *attribute) GetBoolAttr(path string) defsecTypes.BoolValue {
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
func (a *attribute) AsBool() *bool {
	if a.IsNil() {
		return nil
	}

	val, ok := a.val.(bool)
	if !ok {
		return nil
	}
	return &val
}

func (a *attribute) AsString() *string {
	if a.IsNil() {
		return nil
	}

	val, ok := a.val.(string)
	if !ok {
		return nil
	}
	return &val
}

func (a *attribute) IsNil() bool {
	return a == nil || a.val == nil
}
