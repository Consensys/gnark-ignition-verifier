package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

// Chunk that matches a "Chunk" in the Aleo ceremony
type Chunk struct {
	Hash  [64]byte
	TauG1 []bls12377.G1Affine

	// is set only for chunk == 0
	TauG2   []bls12377.G2Affine
	AlphaG1 []bls12377.G1Affine

	isFirst bool
}

func newChunk() Chunk {
	return Chunk{
		TauG1:   make([]bls12377.G1Affine, 0, nbTauG1),
		TauG2:   make([]bls12377.G2Affine, 0, nbTauG2),
		AlphaG1: make([]bls12377.G1Affine, 0, nbAlphaG1),
		isFirst: false,
	}
}

// IsValid checks if the contribution is valid
func (c *Chunk) IsValid() bool {
	l1, l2 := linearCombinationG1(c.TauG1)
	return sameRatio(l1, l2, c.TauG2[1], snarkVMG2Gen)
}

func (c *Chunk) ReadFrom(path string, isFirst bool) error {
	c.TauG1 = c.TauG1[:0]
	// c.TauG2 = c.TauG2[:0]
	// c.AlphaG1 = c.AlphaG1[:0]
	c.isFirst = isFirst

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// skip first 64bytes
	_, err = io.ReadFull(f, c.Hash[:])
	if err != nil {
		return err
	}

	var tryReadErr error
	var buf [fp.Bytes]byte
	tryReadElement := func() (e fp.Element) {
		if tryReadErr != nil {
			return
		}
		_, tryReadErr = f.Read(buf[:])
		if tryReadErr == nil {
			e, tryReadErr = fp.LittleEndian.Element(&buf)
		}
		return
	}

	// we should have nbTauG1 valid G1 points
	for i := 0; i < nbTauG1; i++ {
		c.TauG1 = append(c.TauG1, bls12377.G1Affine{
			X: tryReadElement(),
			Y: tryReadElement(),
		})
	}

	if tryReadErr != nil {
		return tryReadErr
	}

	if isFirst {
		// now we should have nbTauG2 valid G2 points
		for i := 0; i < nbTauG2; i++ {
			c.TauG2 = append(c.TauG2, bls12377.G2Affine{})

			c.TauG2[i].X.A0 = tryReadElement()
			c.TauG2[i].X.A1 = tryReadElement()
			c.TauG2[i].Y.A0 = tryReadElement()
			c.TauG2[i].Y.A1 = tryReadElement()
		}

		if tryReadErr != nil {
			return tryReadErr
		}

		// now we should have nbAlphaG1 valid G1 points
		for i := 0; i < nbAlphaG1; i++ {
			c.AlphaG1 = append(c.AlphaG1, bls12377.G1Affine{})
			c.AlphaG1[i].X = tryReadElement()
			c.AlphaG1[i].Y = tryReadElement()
		}
	}

	return tryReadErr
}

func (c *Chunk) VerifyPoints() error {

	var errors []error
	var lock sync.Mutex

	execute(nbTauG1, func(start, end int) {
		for i := start; i < end; i++ {
			if !c.TauG1[i].IsInSubGroup() {
				lock.Lock()
				errors = append(errors, fmt.Errorf("TauG1[%d] is not in subgroup", i))
				lock.Unlock()
				return
			}
		}
	})

	if len(errors) > 0 {
		return fmt.Errorf("TauG1: %v", errors)
	}

	if c.isFirst {
		// verify that TauG1[0] is the prime subgroup generator

		if !c.TauG2[0].Equal(&snarkVMG2Gen) {
			return fmt.Errorf("TauG2[0] is not the prime subgroup generator")
		}

		if !c.TauG1[0].Equal(&snarkVMG1Gen) {
			return fmt.Errorf("TauG1[0] is not the prime subgroup generator")
		}

		execute(len(c.TauG2), func(start, end int) {
			for i := start; i < end; i++ {
				if !c.TauG2[i].IsInSubGroup() {
					lock.Lock()
					errors = append(errors, fmt.Errorf("TauG2[%d] is not in subgroup", i))
					lock.Unlock()
					return
				}
			}
		})

		if len(errors) > 0 {
			return fmt.Errorf("TauG2: %v", errors)
		}

		execute(len(c.AlphaG1), func(start, end int) {
			for i := start; i < end; i++ {
				if !c.AlphaG1[i].IsInSubGroup() {
					lock.Lock()
					errors = append(errors, fmt.Errorf("AlphaG1[%d] is not in subgroup", i))
					lock.Unlock()
					return
				}
			}
		})

		if len(errors) > 0 {
			return fmt.Errorf("AlphaG1: %v", errors)
		}
	}

	return nil
}

// sameRatio checks that e(a₁, a₂) = e(b₁, b₂)
func sameRatio(a1, b1 bls12377.G1Affine, a2, b2 bls12377.G2Affine) bool {
	// we already know that a1, b1, a2, b2 are in the correct subgroup
	// if !a1.IsInSubGroup() || !b1.IsInSubGroup() || !a2.IsInSubGroup() || !b2.IsInSubGroup() {
	// 	panic("invalid point not in subgroup")
	// }
	var na2 bls12377.G2Affine
	na2.Neg(&a2)
	res, err := bls12377.PairingCheck(
		[]bls12377.G1Affine{a1, b1},
		[]bls12377.G2Affine{na2, b2})
	if err != nil {
		panic(err)
	}
	return res
}

var initROnce sync.Once
var rVector []fr.Element

// L1 = ∑ rᵢAᵢ, L2 = ∑ rᵢAᵢ₊₁ in G1
func linearCombinationG1(A []bls12377.G1Affine) (L1, L2 bls12377.G1Affine) {
	nc := runtime.NumCPU()
	n := len(A)
	initROnce.Do(func() {
		rVector = make([]fr.Element, n-1)
		for i := 0; i < n-1; i++ {
			rVector[i].SetRandom()
		}
	})
	chDone := make(chan struct{})
	go func() {
		L1.MultiExp(A[:n-1], rVector, ecc.MultiExpConfig{NbTasks: nc / 2})
		close(chDone)
	}()
	L2.MultiExp(A[1:], rVector, ecc.MultiExpConfig{NbTasks: nc / 2})
	<-chDone
	return
}

func execute(nbIterations int, work func(int, int), maxCpus ...int) {

	nbTasks := runtime.NumCPU()
	if len(maxCpus) == 1 {
		nbTasks = maxCpus[0]
	}
	nbIterationsPerCpus := nbIterations / nbTasks

	// more CPUs than tasks: a CPU will work on exactly one iteration
	if nbIterationsPerCpus < 1 {
		nbIterationsPerCpus = 1
		nbTasks = nbIterations
	}

	var wg sync.WaitGroup

	extraTasks := nbIterations - (nbTasks * nbIterationsPerCpus)
	extraTasksOffset := 0

	for i := 0; i < nbTasks; i++ {
		wg.Add(1)
		_start := i*nbIterationsPerCpus + extraTasksOffset
		_end := _start + nbIterationsPerCpus
		if extraTasks > 0 {
			_end++
			extraTasks--
			extraTasksOffset++
		}
		go func() {
			work(_start, _end)
			wg.Done()
		}()
	}

	wg.Wait()
}
