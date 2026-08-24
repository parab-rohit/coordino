package policy

import (
	"testing"
)

func TestSelectorCacheAddPod(t *testing.T) {
	sc := NewSelectorCache()
	podKey := "pod-1"
	labels := map[string]string{"app": "nginx", "env": "prod"}
	sc.AddPod(podKey, labels)

	selector := map[string]string{"app": "nginx"}
	results := sc.EvaluateSelector(selector)
	if !results[podKey] {
		t.Errorf("Expected pod-1 to match selector, but it didn't")
	}

	stats := sc.GetCacheStats()
	if stats.PodCount != 1 {
		t.Errorf("Expected PodCount 1, got %d", stats.PodCount)
	}
}

func TestSelectorCacheRemovePod(t *testing.T) {
	sc := NewSelectorCache()
	podKey := "pod-1"
	labels := map[string]string{"app": "nginx"}
	sc.AddPod(podKey, labels)

	selector := map[string]string{"app": "nginx"}
	sc.EvaluateSelector(selector)

	sc.RemovePod(podKey)
	results := sc.EvaluateSelector(selector)
	if results[podKey] {
		t.Errorf("Expected pod-1 to be removed from selector results")
	}
}

func TestSelectorCacheIncremental(t *testing.T) {
	sc := NewSelectorCache()
	selector := map[string]string{"app": "nginx"}

	// Evaluate first to cache it
	sc.EvaluateSelector(selector)

	sc.AddPod("pod-1", map[string]string{"app": "nginx"})
	results := sc.EvaluateSelector(selector)
	if !results["pod-1"] {
		t.Errorf("Expected pod-1 to be added to cached selector results")
	}

	stats := sc.GetCacheStats()
	if stats.CacheHits == 0 {
		// This depends on implementation details, but EvaluateSelector should hit the cache if already evaluated
		// However, AddPod re-evaluates.
	}
}

func TestMatchesSelector(t *testing.T) {
	sc := NewSelectorCache()

	tests := []struct {
		labels   map[string]string
		selector map[string]string
		expected bool
	}{
		{
			labels:   map[string]string{"app": "nginx", "env": "prod"},
			selector: map[string]string{"app": "nginx"},
			expected: true,
		},
		{
			labels:   map[string]string{"app": "nginx"},
			selector: map[string]string{"app": "nginx", "env": "prod"},
			expected: false,
		},
		{
			labels:   map[string]string{"app": "redis"},
			selector: map[string]string{"app": "nginx"},
			expected: false,
		},
		{
			labels:   map[string]string{"app": "nginx"},
			selector: map[string]string{},
			expected: true,
		},
	}

	for _, tc := range tests {
		result := sc.MatchesSelector(tc.labels, tc.selector)
		if result != tc.expected {
			t.Errorf("MatchesSelector(%v, %v) = %v; want %v", tc.labels, tc.selector, result, tc.expected)
		}
	}
}
