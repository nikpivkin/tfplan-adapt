package main

import (
	"errors"
	"fmt"

	tfjson "github.com/hashicorp/terraform-json"
)

type PlanState struct {
	resources map[string][]block
	config    *tfjson.Config
}

func NewPlanState(plan *tfjson.Plan) (*PlanState, error) {
	if plan == nil {
		return nil, errors.New("plan is nil")
	}

	if plan.PlannedValues == nil {
		return nil, errors.New("planned values is nil")
	}

	planState := &PlanState{
		resources: make(map[string][]block),
		config:    plan.Config,
	}

	for _, resource := range plan.PlannedValues.RootModule.Resources {
		block := block{
			inner:      resource,
			attributes: make(map[string]*attribute, len(resource.AttributeValues)),
			plan:       planState,
		}
		for key, attr := range resource.AttributeValues {
			block.attributes[key] = &attribute{val: attr}
		}
		planState.resources[resource.Type] = append(planState.resources[resource.Type], block)
	}
	return planState, nil
}

func findReferences(exprs map[string]*tfjson.Expression, path, accPath string) []string {
	for key, expr := range exprs {
		if expr == nil {
			continue
		}

		currentPath := key
		if accPath != "" {
			currentPath = fmt.Sprintf("%s.%s", accPath, key)
		}

		if path == currentPath {
			return expr.References
		}

		for _, nested := range expr.NestedBlocks {
			if refs := findReferences(nested, path, currentPath); len(refs) > 0 {
				return refs
			}
		}
	}
	return nil
}

func (s *PlanState) GetResourcesByType(typ string) []block {
	return s.resources[typ]
}

type RelatedResourceParams struct {
	ResourceType  string
	ByField       string
	To            block
	CompareFields []string
}

func (s *PlanState) FindBlockByResourceRef(params RelatedResourceParams) *block {
	for _, res := range s.GetResourcesByType(params.ResourceType) {
		configResource := s.findConfigResource(res.Address())
		if configResource == nil {
			continue
		}
		for _, ref := range findReferences(configResource.Expressions, params.ByField, "") {
			for _, field := range params.CompareFields {
				if ref == params.To.FieldPath(field) {
					return &res
				}
			}
		}
	}
	return nil
}

func (s *PlanState) FindBlockByConfigRef(params RelatedResourceParams) *block {
	configResource := s.findConfigResource(params.To.Address())
	if configResource == nil {
		return nil
	}

	for _, ref := range findReferences(configResource.Expressions, params.ByField, "") {
		for _, res := range s.GetResourcesByType(params.ResourceType) {
			for _, field := range params.CompareFields {
				if ref == res.FieldPath(field) {
					return &res
				}
			}
		}
	}
	return nil
}

func (s *PlanState) findConfigResource(address string) *tfjson.ConfigResource {
	for _, res := range s.config.RootModule.Resources {
		if res.Address == address {
			return res
		}
	}
	return nil
}
