package main

import (
	"strings"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
)

// Node represents a resource node in the graph
type Node struct {
	resourceType string
	resourceName string
	moduleName   string
	Address      string
	neighbors    []*Edge
	backLinks    []*Edge
	attributes   map[string]*Attribute
}

// FindRelated searches for a related resource given the resource type
func (node *Node) FindRelated(toResource, fromAttr string, toAttrs ...string) *Node {
	for _, neighbor := range node.neighbors {
		if neighbor.to.resourceType == toResource {
			for _, attr := range toAttrs {
				if neighbor.linkAttributes[fromAttr] == attr {
					return neighbor.to
				}
			}

		}
	}
	return nil
}

// FindBackRelated searches for a backward-linked resource given the resource type
func (node *Node) FindBackRelated(toResource, fromAttr string, toAttrs ...string) *Node {
	for _, backLink := range node.backLinks {
		if backLink.from.resourceType == toResource {
			for _, attr := range toAttrs {
				if backLink.linkAttributes[fromAttr] == attr {
					return backLink.from
				}
			}
		}
	}
	return nil
}

func (n *Node) ID() string {
	return n.Address
}

func (b *Node) GetAttr(name string) *Attribute {
	return b.attributes[name]
}

func (b *Node) GetNestedAttr(path string) *Attribute {
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

func (b *Node) GetBoolAttr(name string, defValue ...bool) defsecTypes.BoolValue {
	def := defsecTypes.BoolDefault(firstOrDefault(defValue), defsecTypes.Metadata{})
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

func (b *Node) GetStringAttr(name string, defValue ...string) defsecTypes.StringValue {
	def := defsecTypes.StringDefault(firstOrDefault(defValue), defsecTypes.Metadata{})
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

func firstOrDefault[T any](a []T) T {
	if len(a) == 0 {
		return *new(T)
	}
	return a[0]
}
