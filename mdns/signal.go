package mdns

type signal struct {
	c chan struct{}
}

func newSignal() *signal {
	return &signal{
		c: make(chan struct{}),
	}
}

func (s *signal) wait() <-chan struct{} {
	return s.c
}

func (s *signal) raise() {
	c := s.c
	s.c = make(chan struct{})
	close(c)
}
