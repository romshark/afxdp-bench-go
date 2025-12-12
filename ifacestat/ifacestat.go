package ifacestat

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"

	"github.com/dustin/go-humanize"
)

type Counter int

const (
	TxPackets Counter = iota
	TxBytes
	RxPackets
	RxBytes
)

func (c Counter) String() string {
	switch c {
	case TxPackets:
		return "tx_packets_phy"
	case TxBytes:
		return "tx_bytes_phy"
	case RxPackets:
		return "rx_packets_phy"
	case RxBytes:
		return "rx_bytes_phy"
	}
	return ""
}

// Per-interface values.
type IfaceStats map[Counter]uint64

// Multi-interface stats.
type Stats map[string]IfaceStats

// Snapshot runs ethtool -S on all interfaces and returns a Snapshot.
func Snapshot(ifaces []string, counters ...Counter) (Stats, error) {
	s := make(Stats)
	for _, iface := range ifaces {
		vals, err := readIface(iface, counters)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", iface, err)
		}
		s[iface] = vals
	}
	return s, nil
}

// Since computes s(now) - old.
func (s Stats) Since(old Stats) Stats {
	out := make(Stats)
	for ifc, now := range s {
		prev := old[ifc]
		diff := make(IfaceStats, len(now))
		for ctr, v := range now {
			diff[ctr] = v - prev[ctr]
		}
		out[ifc] = diff
	}
	return out
}

func readIface(name string, counters []Counter) (IfaceStats, error) {
	out, err := exec.Command("ethtool", "-S", name).Output()
	if err != nil {
		return nil, err
	}

	// convert counters -> lookup table
	want := make(map[string]Counter, len(counters))
	for _, c := range counters {
		want[c.String()] = c
	}

	found := make(IfaceStats, len(counters))

	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSuffix(parts[0], ":")
		ctr, ok := want[key]
		if !ok {
			continue
		}

		var v uint64
		if _, err := fmt.Sscan(parts[1], &v); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		found[ctr] = v
	}

	// ensure all counters exist
	for _, ctr := range counters {
		if _, ok := found[ctr]; !ok {
			found[ctr] = 0
		}
	}

	return found, nil
}

func Print(w io.Writer, s Stats, aliases map[string]string) error {
	ifaces := make([]string, 0, len(s))
	for iface := range s {
		ifaces = append(ifaces, iface)
	}
	slices.Sort(ifaces)

	for _, iface := range ifaces {
		stats := s[iface]

		txPkts := stats[TxPackets]
		txBytes := stats[TxBytes]
		rxPkts := stats[RxPackets]
		rxBytes := stats[RxBytes]

		if alias, ok := aliases[iface]; ok {
			fmt.Fprintf(w, "%s (%s):\n", iface, alias)
		} else {
			fmt.Fprintf(w, "%s :\n", iface)
		}

		fmt.Fprintf(w, "  TX   %-12d  ≈ %-8s (%s)\n",
			txPkts, humanize.Bytes(txBytes), humanize.Comma(int64(txBytes)),
		)
		fmt.Fprintf(w, "  RX   %-12d  ≈ %-8s (%s)\n",
			rxPkts, humanize.Bytes(rxBytes), humanize.Comma(int64(rxBytes)),
		)
	}

	return nil
}
