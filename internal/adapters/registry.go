package adapters

import "sort"

var globalRegistry = map[string]Adapter{}
var staticRegistry = map[string]StaticAdapter{}

func Register(a Adapter) {
	globalRegistry[a.ID()] = a
}

func Get(id string) (Adapter, bool) {
	a, ok := globalRegistry[id]
	return a, ok
}

func All() []Adapter {
	result := make([]Adapter, 0, len(globalRegistry))
	for _, a := range globalRegistry {
		result = append(result, a)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID() < result[j].ID()
	})
	return result
}

func RegisterStatic(a StaticAdapter) {
	staticRegistry[a.ID()] = a
}

func GetStatic(id string) (StaticAdapter, bool) {
	a, ok := staticRegistry[id]
	return a, ok
}

func AllStatic() []StaticAdapter {
	result := make([]StaticAdapter, 0, len(staticRegistry))
	for _, a := range staticRegistry {
		result = append(result, a)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID() < result[j].ID()
	})
	return result
}
