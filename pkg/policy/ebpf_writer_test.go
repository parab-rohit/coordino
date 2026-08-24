package policy

import (
	"testing"
)

func TestCompileRulesToMapEntries(t *testing.T) {
	w := NewEBPFWriter("/sys/fs/bpf/policy")
	rules := []PolicyRule{
		{
			SrcIdentity: 1,
			DstIdentity: 2,
			Proto:       "tcp",
			Port:        80,
			Verdict:     VerdictAllow,
		},
		{
			SrcIdentity: 3,
			DstIdentity: 4,
			Proto:       "udp",
			Port:        53,
			Verdict:     VerdictDeny,
		},
		{
			SrcIdentity: 5,
			DstIdentity: 6,
			Proto:       "icmp",
			Port:        0,
			Verdict:     VerdictAllow,
		},
		{
			SrcIdentity: 7,
			DstIdentity: 8,
			Proto:       "other",
			Port:        1234,
			Verdict:     VerdictAllow,
		},
	}

	entries := w.CompileRulesToMapEntries(rules)

	if len(entries) != 4 {
		t.Errorf("Expected 4 entries, got %d", len(entries))
	}

	// Check TCP Allow
	key1 := PolicyMapKey{SrcIdentity: 1, DstIdentity: 2, Proto: 6, DstPort: 80}
	val1, ok := entries[key1]
	if !ok || val1.Verdict != MapVerdictAllow {
		t.Errorf("TCP Allow rule not compiled correctly: %+v, ok=%v", val1, ok)
	}

	// Check UDP Deny
	key2 := PolicyMapKey{SrcIdentity: 3, DstIdentity: 4, Proto: 17, DstPort: 53}
	val2, ok := entries[key2]
	if !ok || val2.Verdict != MapVerdictDeny {
		t.Errorf("UDP Deny rule not compiled correctly: %+v, ok=%v", val2, ok)
	}

	// Check ICMP Allow
	key3 := PolicyMapKey{SrcIdentity: 5, DstIdentity: 6, Proto: 1, DstPort: 0}
	val3, ok := entries[key3]
	if !ok || val3.Verdict != MapVerdictAllow {
		t.Errorf("ICMP Allow rule not compiled correctly: %+v, ok=%v", val3, ok)
	}

	// Check Other/Any
	key4 := PolicyMapKey{SrcIdentity: 7, DstIdentity: 8, Proto: 0, DstPort: 1234}
	val4, ok := entries[key4]
	if !ok || val4.Verdict != MapVerdictAllow {
		t.Errorf("Other rule not compiled correctly: %+v, ok=%v", val4, ok)
	}
}

func TestCompileRulesToMapEntriesEmpty(t *testing.T) {
	w := NewEBPFWriter("/sys/fs/bpf/policy")
	entries := w.CompileRulesToMapEntries([]PolicyRule{})
	if len(entries) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(entries))
	}
}
