package tfplanadapt

// Edge represents the link between resources
type Edge struct {
	from           *Node
	to             *Node
	linkAttributes map[string]string
}

// Graph represents an oriented graph of resources
type Graph struct {
	nodes map[string]*Node
}

// AddNode adds a node to the graph
func (g *Graph) AddNode(node Node) {
	g.nodes[node.ID()] = &node
}

// AddEdge adds an edge between two resources
func (g *Graph) AddEdge(from, to string, linkAttributes map[string]string) {
	fromNode := g.nodes[from]
	toNode := g.nodes[to]

	if fromNode != nil && toNode != nil {
		edge := &Edge{
			from:           fromNode,
			to:             toNode,
			linkAttributes: linkAttributes,
		}
		fromNode.neighbors = append(fromNode.neighbors, edge)
		toNode.backLinks = append(toNode.backLinks, edge) // Добавление обратной связи
	}
}

// AddEdgeFromResources adds an edge between resources based on module, type, and name
func (g *Graph) AddEdgeFromResources(moduleName, fromType, fromName, toAddress string, linkAttributes map[string]string) {

	toNode := g.nodes[toAddress]
	if toNode == nil {
		return
	}

	for _, fromNode := range g.FindResources(moduleName, fromType, fromName) {
		if fromNode == nil {
			continue
		}

		edge := &Edge{
			from:           fromNode,
			to:             toNode,
			linkAttributes: linkAttributes,
		}
		fromNode.neighbors = append(fromNode.neighbors, edge)
		toNode.backLinks = append(toNode.backLinks, edge)
	}
}

// FindResourcesByType searches for resources by type
func (g *Graph) FindResourcesByType(resourceType string) []*Node {
	var result []*Node
	for _, node := range g.nodes {
		if node.resourceType == resourceType {
			result = append(result, node)
		}
	}
	return result
}

func (g *Graph) FindResources(moduleName, resourceType, resourceName string) []*Node {
	var result []*Node
	for _, node := range g.nodes {
		if node.moduleName == moduleName &&
			node.resourceType == resourceType &&
			node.resourceName == resourceName {
			result = append(result, node)
		}
	}
	return result
}

func (g *Graph) GetResource(address string) *Node {
	return g.nodes[address]
}

func NewGraph() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
	}
}
