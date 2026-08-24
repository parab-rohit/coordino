package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// SelectorCache caches the results of label selector evaluations.
// It supports incremental updates when pods change, avoiding full recomputation.
type SelectorCache struct {
	// podsByLabels maps a label hash to set of pod keys
	podsByLabels map[string]map[string]bool
	// podLabels maps pod key to its label set
	podLabels map[string]map[string]string
	// selectorResults maps selector hash to matched pod keys
	selectorResults map[string]map[string]bool
	// selectorSpecs maps selector hash to the actual selector
	selectorSpecs map[string]map[string]string

	hits   int64
	misses int64
	mu     sync.RWMutex
}

type CacheStats struct {
	PodCount      int
	SelectorCount int
	CacheHits     int64
	CacheMisses   int64
}

// NewSelectorCache creates a new SelectorCache.
func NewSelectorCache() *SelectorCache {
	return &SelectorCache{
		podsByLabels:    make(map[string]map[string]bool),
		podLabels:       make(map[string]map[string]string),
		selectorResults: make(map[string]map[string]bool),
		selectorSpecs:   make(map[string]map[string]string),
	}
}

// AddPod adds/updates a pod and re-evaluates affected selectors.
func (sc *SelectorCache) AddPod(key string, labels map[string]string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Remove old references if pod existed
	sc.removePodInternal(key)

	// Add new pod
	sc.podLabels[key] = labels
	labelHash := sc.hashLabels(labels)
	if sc.podsByLabels[labelHash] == nil {
		sc.podsByLabels[labelHash] = make(map[string]bool)
	}
	sc.podsByLabels[labelHash][key] = true

	// Re-evaluate all selectors for this new pod
	for selectorHash, selector := range sc.selectorSpecs {
		if sc.MatchesSelector(labels, selector) {
			if sc.selectorResults[selectorHash] == nil {
				sc.selectorResults[selectorHash] = make(map[string]bool)
			}
			sc.selectorResults[selectorHash][key] = true
		}
	}
}

// RemovePod removes a pod and updates affected selector results.
func (sc *SelectorCache) RemovePod(key string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.removePodInternal(key)
}

func (sc *SelectorCache) removePodInternal(key string) {
	labels, exists := sc.podLabels[key]
	if !exists {
		return
	}

	labelHash := sc.hashLabels(labels)
	if pods, ok := sc.podsByLabels[labelHash]; ok {
		delete(pods, key)
		if len(pods) == 0 {
			delete(sc.podsByLabels, labelHash)
		}
	}
	delete(sc.podLabels, key)

	// Remove from all cached selector results
	for hash := range sc.selectorResults {
		delete(sc.selectorResults[hash], key)
	}
}

// EvaluateSelector returns pods matching selector (cached).
func (sc *SelectorCache) EvaluateSelector(selector map[string]string) map[string]bool {
	hash := sc.hashLabels(selector) // reuse hashing logic

	sc.mu.RLock()
	if result, ok := sc.selectorResults[hash]; ok {
		sc.mu.RUnlock()
		atomic.AddInt64(&sc.hits, 1)
		return sc.copyMap(result)
	}
	sc.mu.RUnlock()

	atomic.AddInt64(&sc.misses, 1)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Double check
	if result, ok := sc.selectorResults[hash]; ok {
		return sc.copyMap(result)
	}

	sc.selectorSpecs[hash] = selector
	result := make(map[string]bool)
	for key, labels := range sc.podLabels {
		if sc.MatchesSelector(labels, selector) {
			result[key] = true
		}
	}
	sc.selectorResults[hash] = result
	return sc.copyMap(result)
}

// InvalidateSelector force re-evaluation of a selector.
func (sc *SelectorCache) InvalidateSelector(selector map[string]string) {
	hash := sc.hashLabels(selector)
	sc.mu.Lock()
	defer sc.mu.Unlock()
	delete(sc.selectorResults, hash)
	delete(sc.selectorSpecs, hash)
}

// MatchesSelector checks if labels match selector.
func (sc *SelectorCache) MatchesSelector(podLabels, selector map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	for k, v := range selector {
		val, ok := podLabels[k]
		if !ok || val != v {
			return false
		}
	}
	return true
}

// GetCacheStats returns cache hit/miss statistics.
func (sc *SelectorCache) GetCacheStats() CacheStats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return CacheStats{
		PodCount:      len(sc.podLabels),
		SelectorCount: len(sc.selectorSpecs),
		CacheHits:     atomic.LoadInt64(&sc.hits),
		CacheMisses:   atomic.LoadInt64(&sc.misses),
	}
}

func (sc *SelectorCache) hashLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(labels[k])
		sb.WriteString(";")
	}
	h := sha256.New()
	h.Write([]byte(sb.String()))
	return hex.EncodeToString(h.Sum(nil))
}

func (sc *SelectorCache) copyMap(m map[string]bool) map[string]bool {
	res := make(map[string]bool, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}
