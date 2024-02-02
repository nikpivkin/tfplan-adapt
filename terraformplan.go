package tfplanadapt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	tfjson "github.com/hashicorp/terraform-json"
)

func NewTerraformPlanGraph(plan *tfjson.Plan) (*Graph, error) {
	if plan == nil {
		return nil, errors.New("plan is nil")
	}

	if plan.PlannedValues == nil {
		return nil, errors.New("planned values is nil")
	}

	graph := NewGraph()

	fillNodes(graph, plan.PlannedValues.RootModule)
	fillEdges(graph, configModule{
		ConfigModule: plan.Config.RootModule,
	})

	return graph, nil
}

func fillNodes(g *Graph, module *tfjson.StateModule) {
	if module == nil {
		return
	}
	for _, resource := range module.Resources {
		moduleName := ""
		if module.Address != "" {
			parts := strings.Split(module.Address, ".")
			moduleName = parts[len(parts)-1]
		}
		node := Node{
			resourceType: resource.Type,
			resourceName: resource.Name,
			moduleName:   moduleName,
			Address:      resource.Address,
			attributes:   make(map[string]*Attribute, len(resource.AttributeValues)),
		}

		for key, attr := range resource.AttributeValues {
			node.attributes[key] = &Attribute{val: attr}
		}
		g.AddNode(node)
	}

	for _, module := range module.ChildModules {
		fillNodes(g, module)
	}
}

type configModule struct {
	*tfjson.ConfigModule
	name  string
	exprs expressions
}

func fillEdges(g *Graph, module configModule) {
	if module.ConfigModule == nil {
		return
	}
	for _, resource := range module.Resources {
		for attrPath, refs := range findReferences(resource.Expressions, module) {
			for _, ref := range refs {
				// parts := strings.Split(ref, ".")
				if ref.len() < 3 {
					continue
				}
				fromAddress := resource.Address
				if module.name != "" {
					fromAddress = "module." + module.name + "." + fromAddress
				}

				toAddress := ref.address()
				toAttr := ref.attribute()

				linkAttrs := map[string]string{
					attrPath: toAttr,
				}

				// If the resource has an index, we don't know the exact address of the resource
				// TODO support for-each
				if resource.CountExpression != nil {
					g.AddEdgeFromResources(module.name, resource.Type, resource.Name, toAddress, linkAttrs)
				} else {
					g.AddEdge(fromAddress, toAddress, linkAttrs)
				}
			}
		}
	}

	for moduleName, moduleCall := range module.ModuleCalls {
		fillEdges(g, configModule{
			name:         moduleName,
			exprs:        moduleCall.Expressions,
			ConfigModule: moduleCall.Module,
		})
	}
}

type expressions map[string]*tfjson.Expression

type referenceType int

const (
	moduleReference referenceType = iota
	varReference
	localReference
)

type reference struct {
	typ        referenceType
	moduleName string
	val        string
}

func (r reference) address() string {
	parts := r.split()
	switch r.typ {
	case localReference, varReference:
		if parts[0] == "module" {
			return strings.Join(parts[:4], ".")
		}
		return strings.Join(parts[:2], ".")
	case moduleReference:
		return "module." + r.moduleName + "." + strings.Join(parts[:2], ".")
	default:
		panic("unsupported ref type")
	}
}

func (r reference) attribute() string {
	parts := r.split()
	return parts[2]
}

func (r reference) split() []string {
	return strings.Split(r.val, ".")
}

func (r reference) len() int {
	return len(r.split())
}

func findReferences(exprs expressions, module configModule) map[string][]reference {
	refsMap := make(map[string][]reference)
	var walk func(exprs expressions, accPath string)
	walk = func(exprs expressions, accPath string) {
		for key, expr := range exprs {
			if expr == nil {
				continue
			}

			attributePath := key
			if accPath != "" {
				attributePath = fmt.Sprintf("%s.%s", accPath, key)
			}

			if len(expr.References) > 0 {
				refs := make([]reference, 0, len(expr.References))
				for _, ref := range expr.References {
					parts := strings.Split(ref, ".")
					// if the reference points to the module output, it has the following format:
					// "module.module_name.output_name" otherwise "resource_type.resource_name.attribute_path"

					// if the attribute refers to the module output, we must find the source reference
					if parts[0] == "module" && len(parts) == 3 {
						moduleCall, exists := module.ModuleCalls[parts[1]]
						if !exists {
							continue
						}
						childModule := moduleCall.Module
						output, exists := childModule.Outputs[parts[2]]
						if !exists {
							continue
						}
						outputExprs := expressions{parts[2]: output.Expression}
						childRefs := findReferences(outputExprs, configModule{
							name:         parts[1],
							exprs:        moduleCall.Expressions,
							ConfigModule: childModule,
						})
						for _, resolvedRefs := range childRefs {
							for _, resolvedRef := range resolvedRefs {
								refs = append(refs, reference{
									typ:        moduleReference,
									moduleName: parts[1],
									val:        resolvedRef.val,
								})
							}
						}
					} else if parts[0] == "var" && module.exprs != nil {
						moduleRefs := findReferences(module.exprs, module)
						for _, resolvedRefs := range moduleRefs {
							for _, reresolvedRef := range resolvedRefs {
								refs = append(refs, reference{
									typ: varReference,
									val: reresolvedRef.val,
								})
							}
						}
					} else if len(parts) == 3 {
						typ := localReference
						if module.name != "" {
							typ = moduleReference
						}
						refs = append(refs, reference{
							moduleName: module.name,
							typ:        typ,
							val:        ref,
						})
					}
				}

				refsMap[attributePath] = refs
			}

			for _, nested := range expr.NestedBlocks {
				walk(nested, attributePath)
			}
		}
	}
	walk(exprs, "")
	return refsMap
}

func ReadPlan(r io.Reader) (*tfjson.Plan, error) {
	var plan tfjson.Plan
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %w", err)
	}
	return &plan, nil
}
