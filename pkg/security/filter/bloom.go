package filter

import (
	"hash/fnv"
	"sync"
)

// BloomFilter provides memory-efficient probabilistic membership testing.
type BloomFilter struct {
	mu       sync.RWMutex
	bitset   []uint64
	sizeBits uint64
	numHash  uint32
}

// NewBloomFilter creates a new BloomFilter with the specified bit size and hash count.
func NewBloomFilter(sizeBits uint64, numHash uint32) *BloomFilter {
	if sizeBits == 0 {
		sizeBits = 65536 // 64K bits
	}
	if numHash == 0 {
		numHash = 4
	}

	numWords := (sizeBits + 63) / 64
	return &BloomFilter{
		bitset:   make([]uint64, numWords),
		sizeBits: sizeBits,
		numHash:  numHash,
	}
}

// Add inserts a string key into the BloomFilter.
func (bf *BloomFilter) Add(key string) {
	bf.mu.Lock()
	defer bf.mu.Unlock()

	h1, h2 := bf.hashPair(key)
	for i := uint32(0); i < bf.numHash; i++ {
		combined := (h1 + uint64(i)*h2) % bf.sizeBits
		wordIdx := combined / 64
		bitIdx := combined % 64
		bf.bitset[wordIdx] |= (1 << bitIdx)
	}
}

// MayContain checks if the string might be in the set (false positives possible, false negatives impossible).
func (bf *BloomFilter) MayContain(key string) bool {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	h1, h2 := bf.hashPair(key)
	for i := uint32(0); i < bf.numHash; i++ {
		combined := (h1 + uint64(i)*h2) % bf.sizeBits
		wordIdx := combined / 64
		bitIdx := combined % 64
		if (bf.bitset[wordIdx] & (1 << bitIdx)) == 0 {
			return false
		}
	}
	return true
}

func (bf *BloomFilter) hashPair(key string) (uint64, uint64) {
	f := fnv.New64a()
	f.Write([]byte(key))
	h1 := f.Sum64()

	// Secondary hash with prime salt
	f.Reset()
	f.Write([]byte(key))
	f.Write([]byte{0x5A, 0xC3, 0x19, 0x8D})
	h2 := f.Sum64()
	if h2 == 0 {
		h2 = 1
	}
	return h1, h2
}
