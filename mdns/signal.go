package mdns

// signal is a simple way to release a number of goroutines when something happens
type signal struct {
	c chan struct{}
}

func newSignal() *signal {
	return &signal{
		c: make(chan struct{}),
	}
}

func (s *signal) waitCh() <-chan struct{} {
	return s.c
}

func (s *signal) raise() {
	c := s.c
	s.c = make(chan struct{})
	close(c)
}
