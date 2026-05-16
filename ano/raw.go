package ano

type Raw struct {
	Load []byte
}

func NewRaw(data []byte) *Raw {
	return &Raw{Load: data}
}

func (r *Raw) Tag() string { return "Raw" }
func (r *Raw) Len() int { return len(r.Load) }

func (r *Raw) Copy() Layer {
	n := &Raw{}
	if len(r.Load) > 0 {
		n.Load = make([]byte, len(r.Load))
		copy(n.Load, r.Load)
	}
	return n
}

func (r *Raw) Serialize() []byte {
	if r.Load == nil {
		return []byte{}
	}
	b := make([]byte, len(r.Load))
	copy(b, r.Load)
	return b
}

func (r *Raw) Deserialize(data []byte) ([]byte, error) {
	r.Load = make([]byte, len(data))
	copy(r.Load, data)
	return nil, nil
}

func (r *Raw) Next(data []byte) Layer { return nil }
