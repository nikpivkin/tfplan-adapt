package main

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
	fillEdges(graph, "", plan.Config.RootModule)

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
			// TODO
			if len(parts) != 2 {
				panic(module.Address)
			}
			moduleName = parts[1]
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

func fillEdges(g *Graph, moduleName string, module *tfjson.ConfigModule) {
	if module == nil {
		return
	}
	for _, resource := range module.Resources {
		for attrPath, refs := range findReferences(resource.Expressions, module) {
			for _, ref := range refs {
				parts := strings.Split(ref, ".")
				if len(parts) < 3 {
					continue
				}
				fromAddress := resource.Address
				if moduleName != "" {
					fromAddress = "module." + moduleName + "." + fromAddress
				}

				toAddress := buildAddress(parts, moduleName)
				toAttr := parts[2]
				if parts[0] == "module" {
					toAttr = parts[4]
				}

				linkAttrs := map[string]string{
					attrPath: toAttr,
				}

				if resource.CountExpression != nil {
					g.AddEdgeFromResources(moduleName, resource.Type, resource.Name, toAddress, linkAttrs)
				} else {
					g.AddEdge(fromAddress, toAddress, linkAttrs)
				}
			}
		}
	}

	for moduleName, moduleCall := range module.ModuleCalls {
		fillEdges(g, moduleName, moduleCall.Module)
	}
}

func buildAddress(parts []string, moduleName string) string {
	var address string

	if parts[0] == "module" {
		address = strings.Join(parts[:4], ".")
	} else if moduleName != "" {
		address = "module." + moduleName + "." + strings.Join(parts[:2], ".")
	} else {
		address = strings.Join(parts[:2], ".")
	}

	return address
}

type expressions map[string]*tfjson.Expression

func findReferences(exprs expressions, module *tfjson.ConfigModule) map[string][]string {
	refsMap := make(map[string][]string)
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
				refs := make([]string, 0, len(expr.References))
				for _, ref := range expr.References {
					parts := strings.Split(ref, ".")
					// if the reference points to the module output, it has the following format:
					// "module.module_name.output_name" otherwise "resource_type.resource_name.attribute_path"
					if len(parts) != 3 {
						continue
					}
					// if the attribute refers to the module output, we must find the source reference
					if parts[0] == "module" {
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
						childRefs := findReferences(outputExprs, childModule)
						for _, resolvedRefs := range childRefs {
							for _, resolvedRef := range resolvedRefs {
								address := strings.Join([]string{"module", parts[1], resolvedRef}, ".")
								refs = append(refs, address)
							}
						}
					} else {
						refs = append(refs, ref)
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
