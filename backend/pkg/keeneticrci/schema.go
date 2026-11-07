package keeneticrci

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
)

const (
	maxSchemaDepth = 8
	maxSchemaNodes = 256
)

// SchemaNode describes a bounded JSON value shape without retaining scalar values or arbitrary object keys.
type SchemaNode struct {
	Type         string       `json:"type"`
	ArrayLength  *int         `json:"array_length,omitempty"`
	Fields       []SchemaNode `json:"fields,omitempty"`
	OtherSchemas []SchemaNode `json:"other_schemas,omitempty"`
	Name         string       `json:"name,omitempty"`
	OtherFields  int          `json:"other_fields,omitempty"`
}

// DescribeSchema converts bounded JSON into a privacy-preserving shape description using only named safe fields.
func DescribeSchema(data json.RawMessage, safeFields []string) (SchemaNode, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return SchemaNode{}, &Error{Kind: ErrorInvalidJSON}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return SchemaNode{}, &Error{Kind: ErrorInvalidJSON}
	}
	allow := make(map[string]struct{}, len(safeFields))
	for _, field := range safeFields {
		allow[strings.ToLower(field)] = struct{}{}
	}
	remaining := maxSchemaNodes
	node, err := describeJSONValue(value, 0, &remaining, allow)
	if err != nil {
		return SchemaNode{}, &Error{Kind: ErrorSchema}
	}
	return node, nil
}

// describeJSONValue returns one bounded value shape and anonymizes every object key outside the allowlist.
func describeJSONValue(value any, depth int, remaining *int, allow map[string]struct{}) (SchemaNode, error) {
	if remaining == nil {
		return SchemaNode{}, &Error{Kind: ErrorSchema}
	}
	*remaining--
	if *remaining < 0 || depth > maxSchemaDepth {
		return SchemaNode{}, &Error{Kind: ErrorSchema}
	}
	switch typed := value.(type) {
	case nil:
		return SchemaNode{Type: "null"}, nil
	case bool:
		return SchemaNode{Type: "boolean"}, nil
	case json.Number:
		return SchemaNode{Type: "number"}, nil
	case string:
		return SchemaNode{Type: "string"}, nil
	case []any:
		if len(typed) > *remaining {
			return SchemaNode{}, &Error{Kind: ErrorSchema}
		}
		length := len(typed)
		node := SchemaNode{Type: "array", ArrayLength: &length}
		for index, childValue := range typed {
			child, err := describeJSONValue(childValue, depth+1, remaining, allow)
			if err != nil {
				return SchemaNode{}, err
			}
			child.Name = "item"
			if index == 0 {
				node.Fields = append(node.Fields, child)
				continue
			}
			if !containsSchema(node.Fields, child) {
				node.OtherSchemas = append(node.OtherSchemas, child)
			}
		}
		return node, nil
	case map[string]any:
		if status, ok := typed["status"].(string); ok && status == "error" {
			return SchemaNode{}, &Error{Kind: ErrorSchema}
		}
		if len(typed) > *remaining {
			return SchemaNode{}, &Error{Kind: ErrorSchema}
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		node := SchemaNode{Type: "object"}
		for _, key := range keys {
			child, err := describeJSONValue(typed[key], depth+1, remaining, allow)
			if err != nil {
				return SchemaNode{}, err
			}
			if _, ok := allow[strings.ToLower(key)]; ok {
				child.Name = key
				node.Fields = append(node.Fields, child)
				continue
			}
			node.OtherFields++
			child.Name = "other"
			if !containsSchema(node.OtherSchemas, child) {
				node.OtherSchemas = append(node.OtherSchemas, child)
			}
		}
		return node, nil
	default:
		return SchemaNode{}, &Error{Kind: ErrorSchema}
	}
}

// containsSchema reports whether an anonymized schema shape already appears in a bounded sibling list.
func containsSchema(schemas []SchemaNode, candidate SchemaNode) bool {
	want, _ := json.Marshal(candidate)
	for _, schema := range schemas {
		current, _ := json.Marshal(schema)
		if bytes.Equal(current, want) {
			return true
		}
	}
	return false
}
