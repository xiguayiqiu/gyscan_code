package ano

type Layer interface {
	Tag() string
	Serialize() []byte
	Deserialize(data []byte) ([]byte, error)
	Len() int
	Next(data []byte) Layer
	Copy() Layer
}

type Packet struct {
	Layers  []Layer
	Payload []byte
}

func Build(ls ...Layer) *Packet {
	return &Packet{Layers: ls}
}

func (p *Packet) Add(l Layer) *Packet {
	p.Layers = append(p.Layers, l)
	return p
}

func (p *Packet) Set(l Layer) *Packet {
	tag := l.Tag()
	for i, v := range p.Layers {
		if v.Tag() == tag {
			p.Layers[i] = l
			return p
		}
	}
	return p.Add(l)
}

func (p *Packet) Get(name string) Layer {
	for _, l := range p.Layers {
		tag := l.Tag()
		if tag == name || "*ano."+tag == name || "ano."+tag == name {
			return l
		}
	}
	return nil
}

func (p *Packet) Has(name string) bool {
	return p.Get(name) != nil
}

func (p *Packet) Remove(name string) *Packet {
	for i, l := range p.Layers {
		tag := l.Tag()
		if tag == name || "*ano."+tag == name || "ano."+tag == name {
			p.Layers = append(p.Layers[:i], p.Layers[i+1:]...)
			return p
		}
	}
	return p
}

func (p *Packet) Bytes() []byte {
	var b []byte
	for _, l := range p.Layers {
		b = append(b, l.Serialize()...)
	}
	if p.Payload != nil {
		b = append(b, p.Payload...)
	}
	return b
}

func (p *Packet) ParseLayers(ls ...Layer) error {
	p.Layers = ls
	return p.Parse(p.Bytes())
}

func (p *Packet) Parse(data []byte) error {
	var err error
	current := data
	for i := 0; i < len(p.Layers); i++ {
		l := p.Layers[i]
		current, err = l.Deserialize(current)
		if err != nil {
			return err
		}
		next := l.Next(current)
		if next != nil {
			p.Layers = append(p.Layers, next)
		}
	}
	if len(current) > 0 {
		p.Payload = make([]byte, len(current))
		copy(p.Payload, current)
	}
	return nil
}

func (p *Packet) Show() string {
	var s string
	for _, l := range p.Layers {
		s += l.Tag() + " > "
	}
	return s
}

func (p *Packet) Summary() string {
	if len(p.Layers) < 2 {
		return p.Show()
	}
	var src, dst string
	if ip := p.Get("IPv4"); ip != nil {
		ipv4 := ip.(*IPv4)
		src = IPBytes(ipv4.Src)
		dst = IPBytes(ipv4.Dst)
	}
	if tcp := p.Get("TCP"); tcp != nil {
		t := tcp.(*TCP)
		return src + ":" + itoa(int(t.SrcPort)) + " > " + dst + ":" + itoa(int(t.DstPort))
	}
	if udp := p.Get("UDP"); udp != nil {
		u := udp.(*UDP)
		return src + ":" + itoa(int(u.SrcPort)) + " > " + dst + ":" + itoa(int(u.DstPort))
	}
	return src + " > " + dst
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
