package tests

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blackalex1/sentinel-core/pkg/security/ingest"
)

// BenchmarkHighThroughput_ConntrackIngestion benchmarks throughput of processing 50,000 conntrack events.
func BenchmarkHighThroughput_ConntrackIngestion(b *testing.B) {
	pipeline := ingest.NewSecurityPipeline(ingest.DefaultPipelineConfig())
	dispatcher := ingest.GetDefaultEventDispatcher()
	dispatcher.Clear()

	// Generate batch of realistic conntrack lines
	benignLines := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		benignLines[i] = fmt.Sprintf("[NEW] tcp 6 120 SYN_SENT src=192.168.1.%d dst=198.51.100.%d sport=%d dport=443 [UNREPLIED]", (i%200)+1, (i%250)+1, 30000+(i%30000))
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		line := benignLines[i%1000]
		_ = pipeline.ProcessRouterConntrackLine(line)
	}
}

// TestHighThroughput_ConntrackParallelStream tests multi-threaded ingestion of 50,000 events across 8 concurrent goroutines.
func TestHighThroughput_ConntrackParallelStream(t *testing.T) {
	pipeline := ingest.NewSecurityPipeline(ingest.DefaultPipelineConfig())
	dispatcher := ingest.GetDefaultEventDispatcher()
	dispatcher.Clear()

	sub := dispatcher.Subscribe()
	defer dispatcher.Unsubscribe(sub)

	numWorkers := 8
	eventsPerWorker := 6250 // Total 50,000 events
	var wg sync.WaitGroup

	startTime := time.Now()

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < eventsPerWorker; i++ {
				var line string
				if i == 500 && workerID == 0 {
					// 1 actual exploit probe amidst 50,000 normal packets
					line = fmt.Sprintf("[NEW] tcp 6 120 SYN_SENT src=192.168.1.%d dst=203.0.113.10 sport=%d dport=23 [UNREPLIED]", workerID+10, 40000+i)
				} else {
					line = fmt.Sprintf("[NEW] tcp 6 120 SYN_SENT src=192.168.1.%d dst=198.51.100.%d sport=%d dport=443 [UNREPLIED]", (workerID*10)+(i%10), (i%200)+1, 30000+i)
				}
				_ = pipeline.ProcessRouterConntrackLine(line)
			}
		}(w)
	}

	wg.Wait()
	duration := time.Since(startTime)

	totalEvents := numWorkers * eventsPerWorker
	eps := float64(totalEvents) / duration.Seconds()

	t.Logf("🚀 Ingested %d conntrack events across %d parallel goroutines in %v (%.2f events/sec)",
		totalEvents, numWorkers, duration, eps)

	if eps < 10000 {
		t.Errorf("expected throughput > 10,000 events/sec, got %.2f eps", eps)
	}

	// Verify the 1 exploit event was detected and emitted
	select {
	case ev := <-sub:
		if ev.DstPort != 23 {
			t.Errorf("expected exploit port 23 threat event, got: %+v", ev)
		}
		t.Logf("✅ Successfully captured real-time threat event: %+v", ev)
	case <-time.After(1 * time.Second):
		t.Fatalf("expected threat event to be emitted into subscriber channel")
	}
}
