package main

import (
    "fmt"
    "log"
    "net"
    "os"
    "sort"
    "strings"
    "unsafe"
    "time"

    "github.com/aquasecurity/libbpfgo"
    "github.com/cloudflare/ebpf_exporter/v2/util"
)

const (
    bpfObj = "examples/tcptop.bpf.o"
    taskCommLen = 16
)

type entry struct {
    pid  uint32
    comm string
    laddr string
    raddr string
    lport uint16
    rport uint16
    tx   uint64
    rx   uint64
}

func decodeKey(k []byte) entry {
    // Layout from tcptop.bpf.c:
    // u32 laddr; u32 raddr; u16 lport; u16 rport; u32 pid; char comm[16];
    bo := util.GetHostByteOrder()

    e := entry{}

    if len(k) < 32 {
        return e
    }

    laddr := bo.Uint32(k[0:4])
    raddr := bo.Uint32(k[4:8])
    lport := bo.Uint16(k[8:10])
    rport := bo.Uint16(k[10:12])
    pid := bo.Uint32(k[12:16])
    commBytes := k[16:32]

    e.pid = pid
    e.comm = strings.TrimRight(string(commBytes), "\x00")
    e.laddr = net.IPv4(byte(laddr), byte(laddr>>8), byte(laddr>>16), byte(laddr>>24)).String()
    e.raddr = net.IPv4(byte(raddr), byte(raddr>>8), byte(raddr>>16), byte(raddr>>24)).String()
    e.lport = lport
    e.rport = rport

    return e
}

func main() {
    if _, err := os.Stat(bpfObj); err != nil {
        log.Fatalf("bpf object %q not found: %v", bpfObj, err)
    }

    mod, err := libbpfgo.NewModuleFromFile(bpfObj)
    if err != nil {
        log.Fatalf("failed to create module: %v", err)
    }

    if err := mod.BPFLoadObject(); err != nil {
        log.Fatalf("failed to load bpf object: %v", err)
    }

    // Attach all programs (fentry/kprobe/etc) so maps start receiving data
    iter := mod.Iterator()
    for {
        prog := iter.NextProgram()
        if prog == nil {
            break
        }

        if _, err := prog.AttachGeneric(); err != nil {
            log.Printf("warning: failed to attach program %q: %v", prog.Name(), err)
        }
    }

    txMap, err := mod.GetMap("tcptop_tx_bytes_total")
    if err != nil {
        log.Fatalf("failed to get tx map: %v", err)
    }

    rxMap, err := mod.GetMap("tcptop_rx_bytes_total")
    if err != nil {
        log.Fatalf("failed to get rx map: %v", err)
    }

    fmt.Printf("Loaded %s and attached programs; reading maps every 2s. Ctrl-C to exit.\n", bpfObj)

    for {
        entries := map[string]*entry{}

        iterTx := txMap.Iterator()
        for iterTx.Next() {
            key := iterTx.Key()
            valBuf, err := txMap.GetValue(unsafe.Pointer(&key[0]))
            if err != nil || len(valBuf) < 8 {
                continue
            }
            tx := util.GetHostByteOrder().Uint64(valBuf)

            k := string(key)
            e := decodeKey(key)
            existing := entries[k]
            if existing == nil {
                e.tx = tx
                entries[k] = &e
            } else {
                existing.tx = tx
            }
        }

        iterRx := rxMap.Iterator()
        for iterRx.Next() {
            key := iterRx.Key()
            valBuf, err := rxMap.GetValue(unsafe.Pointer(&key[0]))
            if err != nil || len(valBuf) < 8 {
                continue
            }
            rx := util.GetHostByteOrder().Uint64(valBuf)

            k := string(key)
            e := decodeKey(key)
            existing := entries[k]
            if existing == nil {
                e.rx = rx
                entries[k] = &e
            } else {
                existing.rx = rx
            }
        }

        // Sort by total bytes desc
        list := []*entry{}
        for _, v := range entries {
            list = append(list, v)
        }

        sort.Slice(list, func(i, j int) bool {
            return (list[i].tx + list[i].rx) > (list[j].tx + list[j].rx)
        })

        // Print header
        fmt.Printf("%-6s %-12s %-15s %-6s %-15s %-6s %-7s %-7s %-4s\n", "PID", "COMM", "LADDR", "LPORT", "RADDR", "RPORT", "TX_KB", "RX_KB", "MS")

        for _, e := range list {
            txkb := e.tx / 1024
            rxkb := e.rx / 1024
            fmt.Printf("%-6d %-12s %-15s %-6d %-15s %-6d %-7d %-7d %-4s\n",
                e.pid, e.comm, e.laddr, e.lport, e.raddr, e.rport, txkb, rxkb, "0")
        }

        time.Sleep(2 * time.Second)
        fmt.Println()
    }
}
