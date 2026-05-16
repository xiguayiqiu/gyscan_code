package ano

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
)

const (
	etherOffset  = 0
	ipOffset     = 14
	ipProtoOff   = 23
	ipSrcOff     = 26
	ipDstOff     = 30
	tcpUdpSPort  = 0
	tcpUdpDPort  = 2
)

func CompileBPF(expr string) ([]bpf.RawInstruction, error) {
	prog, err := compileExpr(expr)
	if err != nil {
		return nil, err
	}
	return bpf.Assemble(prog)
}

func SetSocketBPF(fd int, expr string) error {
	raw, err := CompileBPF(expr)
	if err != nil {
		return fmt.Errorf("ano: compile bpf %q: %w", expr, err)
	}
	return attachBPF(fd, raw)
}

func attachBPF(fd int, insns []bpf.RawInstruction) error {
	type sockFprog struct {
		Len    uint16
		pad    [6]byte
		Filter *bpf.RawInstruction
	}
	prog := sockFprog{
		Len:    uint16(len(insns)),
		Filter: &insns[0],
	}
	_, _, e := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(0x1A), // SO_ATTACH_FILTER = 26 on Linux
		uintptr(unsafe.Pointer(&prog)),
		unsafe.Sizeof(prog),
		0,
	)
	if e != 0 {
		return fmt.Errorf("ano: SO_ATTACH_FILTER: %w", e)
	}
	return nil
}

func compileExpr(expr string) ([]bpf.Instruction, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty bpf expression")
	}

	tokens := tokenize(expr)
	p := &parser{tokens: tokens, pos: 0}
	prog, err := p.parse()
	if err != nil {
		return nil, err
	}

	insns := prog.compile()
	insns = append(insns, bpf.RetConstant{Val: 65535})
	insns = append(insns, bpf.RetConstant{Val: 0})
	return insns, nil
}

type token struct {
	kind  string
	value string
}

func tokenize(s string) []token {
	var tokens []token
	s = strings.ToLower(s)
	parts := strings.Fields(s)

	for i := 0; i < len(parts); i++ {
		p := parts[i]
		switch p {
		case "tcp", "udp", "icmp", "arp", "ip", "ip6", "rarp":
			tokens = append(tokens, token{kind: "proto", value: p})
		case "port":
			if i+1 < len(parts) {
				tokens = append(tokens, token{kind: "port", value: parts[i+1]})
				i++
			}
		case "host":
			if i+1 < len(parts) {
				tokens = append(tokens, token{kind: "host", value: parts[i+1]})
				i++
			}
		case "net":
			if i+1 < len(parts) {
				tokens = append(tokens, token{kind: "net", value: parts[i+1]})
				i++
			}
		case "src":
			if i+1 < len(parts) {
				next := parts[i+1]
				switch next {
				case "host":
					if i+2 < len(parts) {
						tokens = append(tokens, token{kind: "src_host", value: parts[i+2]})
						i += 2
					}
				case "port":
					if i+2 < len(parts) {
						tokens = append(tokens, token{kind: "src_port", value: parts[i+2]})
						i += 2
					}
				default:
					tokens = append(tokens, token{kind: "src", value: next})
					i++
				}
			}
		case "dst":
			if i+1 < len(parts) {
				next := parts[i+1]
				switch next {
				case "host":
					if i+2 < len(parts) {
						tokens = append(tokens, token{kind: "dst_host", value: parts[i+2]})
						i += 2
					}
				case "port":
					if i+2 < len(parts) {
						tokens = append(tokens, token{kind: "dst_port", value: parts[i+2]})
						i += 2
					}
				default:
					tokens = append(tokens, token{kind: "dst", value: next})
					i++
				}
			}
		case "and", "or":
			tokens = append(tokens, token{kind: "op", value: p})
		case "not":
			tokens = append(tokens, token{kind: "not", value: p})
		default:
			if isNumber(p) {
				tokens = append(tokens, token{kind: "port", value: p})
			} else {
				tokens = append(tokens, token{kind: "unknown", value: p})
			}
		}
	}
	return tokens
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	return &p.tokens[p.pos]
}

func (p *parser) next() *token {
	t := p.peek()
	if t != nil {
		p.pos++
	}
	return t
}

func (p *parser) parse() (*bpfProg, error) {
	return p.parseOr()
}

func (p *parser) parseOr() (*bpfProg, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t != nil && t.kind == "op" && t.value == "or" {
			p.next()
			right, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			left = &bpfProg{op: opOr, left: left, right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *parser) parseAnd() (*bpfProg, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t != nil && t.kind == "op" && t.value == "and" {
			p.next()
			right, err := p.parseNot()
			if err != nil {
				return nil, err
			}
			left = &bpfProg{op: opAnd, left: left, right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *parser) parseNot() (*bpfProg, error) {
	t := p.peek()
	if t != nil && t.kind == "not" {
		p.next()
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &bpfProg{op: opNot, left: inner}, nil
	}
	return p.parseAtom()
}

func (p *parser) parseAtom() (*bpfProg, error) {
	t := p.next()
	if t == nil {
		return nil, fmt.Errorf("unexpected end of expression")
	}

	switch t.kind {
	case "proto":
		return parseProto(t.value)
	case "port":
		n, err := strconv.Atoi(t.value)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", t.value)
		}
		return portProg(uint32(n)), nil
	case "host":
		ip, err := parseIP(t.value)
		if err != nil {
			return nil, err
		}
		return hostProg(ip), nil
	case "net":
		return parseNetwork(t.value)
	case "src_host":
		ip, err := parseIP(t.value)
		if err != nil {
			return nil, err
		}
		return srcHostProg(ip), nil
	case "dst_host":
		ip, err := parseIP(t.value)
		if err != nil {
			return nil, err
		}
		return dstHostProg(ip), nil
	case "src_port":
		n, err := strconv.Atoi(t.value)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", t.value)
		}
		return srcPortProg(uint32(n)), nil
	case "dst_port":
		n, err := strconv.Atoi(t.value)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %s", t.value)
		}
		return dstPortProg(uint32(n)), nil
	default:
		return nil, fmt.Errorf("unexpected token: %s", t.value)
	}
}

type opType int

const (
	opAnd opType = iota
	opOr
	opNot
)

type bpfProg struct {
	op         opType
	left       *bpfProg
	right      *bpfProg
	insns      []bpf.Instruction
	isLeaf     bool
	leafInsns  []bpf.Instruction
}

func (bp *bpfProg) compile() []bpf.Instruction {
	if !bp.isLeaf {
		switch bp.op {
		case opAnd:
			left := bp.left.compile()
			right := bp.right.compile()
			return append(left, right...)
		case opOr:
			left := bp.left.compile()
			right := bp.right.compile()
			if len(left) == 1 && len(right) == 1 {
				li := left[0]
				ri := right[0]
				if lj, ok := li.(bpf.JumpIf); ok {
					if rj, ok := ri.(bpf.JumpIf); ok {
						lj.SkipFalse = uint8(len(right) + 1)
						return []bpf.Instruction{lj, rj}
					}
				}
			}
			left = append(left, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipTrue: uint8(len(right) + 2), SkipFalse: 0})
			left = append(left, right...)
			return left
		case opNot:
			inner := bp.left.compile()
			if len(inner) == 1 {
				if j, ok := inner[0].(bpf.JumpIf); ok {
					if j.Cond == bpf.JumpEqual {
						j.Cond = bpf.JumpNotEqual
					} else {
						j.SkipTrue, j.SkipFalse = j.SkipFalse, j.SkipTrue
					}
					return []bpf.Instruction{j}
				}
			}
			return inner
		}
	}
	return bp.leafInsns
}

func protoProg(name string, proto uint8) *bpfProg {
	return &bpfProg{
		isLeaf: true,
		leafInsns: []bpf.Instruction{
			bpf.LoadAbsolute{Off: ipProtoOff, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(proto), SkipTrue: 1, SkipFalse: 0},
		},
	}
}

func etherProg(etype uint16) *bpfProg {
	return &bpfProg{
		isLeaf: true,
		leafInsns: []bpf.Instruction{
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(etype), SkipTrue: 1, SkipFalse: 0},
		},
	}
}

func parseProto(name string) (*bpfProg, error) {
	switch name {
	case "tcp":
		return protoProg("tcp", 6), nil
	case "udp":
		return protoProg("udp", 17), nil
	case "icmp":
		return protoProg("icmp", 1), nil
	case "arp":
		return etherProg(0x0806), nil
	case "ip":
		return etherProg(0x0800), nil
	case "ip6":
		return etherProg(0x86DD), nil
	default:
		return nil, fmt.Errorf("unknown protocol: %s", name)
	}
}

func parseIP(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("invalid ip: %s", s)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("only IPv4 supported: %s", s)
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3]), nil
}

func hostProg(ip uint32) *bpfProg {
	return &bpfProg{
		isLeaf: true,
		leafInsns: []bpf.Instruction{
			bpf.LoadAbsolute{Off: ipSrcOff, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip, SkipTrue: 2, SkipFalse: 1},
			bpf.LoadAbsolute{Off: ipDstOff, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip, SkipTrue: 1, SkipFalse: 0},
		},
	}
}

func srcHostProg(ip uint32) *bpfProg {
	return &bpfProg{
		isLeaf: true,
		leafInsns: []bpf.Instruction{
			bpf.LoadAbsolute{Off: ipSrcOff, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip, SkipTrue: 1, SkipFalse: 0},
		},
	}
}

func dstHostProg(ip uint32) *bpfProg {
	return &bpfProg{
		isLeaf: true,
		leafInsns: []bpf.Instruction{
			bpf.LoadAbsolute{Off: ipDstOff, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ip, SkipTrue: 1, SkipFalse: 0},
		},
	}
}

func portProg(port uint32) *bpfProg {
	return &bpfProg{
		isLeaf: true,
		leafInsns: []bpf.Instruction{
			bpf.LoadAbsolute{Off: ipProtoOff, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 4, SkipFalse: 0},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 5},
			bpf.LoadAbsolute{Off: ipOffset, Size: 1},
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0F},
			bpf.LoadMemShift{Off: 0},
			bpf.LoadIndirect{Off: ipOffset, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: port, SkipTrue: 1, SkipFalse: 0},
			bpf.LoadIndirect{Off: ipOffset + 2, Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: port, SkipTrue: 1, SkipFalse: 0},
		},
	}
}

func srcPortProg(port uint32) *bpfProg {
	return portOffsetProg(0, port)
}

func dstPortProg(port uint32) *bpfProg {
	return portOffsetProg(2, port)
}

func portOffsetProg(off int, port uint32) *bpfProg {
	return &bpfProg{
		isLeaf: true,
		leafInsns: []bpf.Instruction{
			bpf.LoadAbsolute{Off: ipProtoOff, Size: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 4, SkipFalse: 0},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 4},
			bpf.LoadAbsolute{Off: ipOffset, Size: 1},
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0F},
			bpf.LoadMemShift{Off: 0},
			bpf.LoadIndirect{Off: uint32(ipOffset + off), Size: 2},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: port, SkipTrue: 1, SkipFalse: 0},
		},
	}
}

func parseNetwork(s string) (*bpfProg, error) {
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid network: %s", s)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 networks supported: %s", s)
	}
	mask := net.IP(ipnet.Mask).To4()
	netVal := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	maskVal := uint32(mask[0])<<24 | uint32(mask[1])<<16 | uint32(mask[2])<<8 | uint32(mask[3])

	return &bpfProg{
		isLeaf: true,
		leafInsns: []bpf.Instruction{
			bpf.LoadAbsolute{Off: ipSrcOff, Size: 4},
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: maskVal},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: netVal, SkipTrue: 3, SkipFalse: 0},
			bpf.LoadAbsolute{Off: ipDstOff, Size: 4},
			bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: maskVal},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: netVal, SkipTrue: 1, SkipFalse: 0},
		},
	}, nil
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}