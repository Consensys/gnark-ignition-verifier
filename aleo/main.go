package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
)

const (
	nbTauG1   = 65536
	nbTauG2   = 30
	nbAlphaG1 = 87
	nbChunks  = 4096
)

const roundsRootDir = "./rounds/"

var (
	snarkVMG1Gen bls12377.G1Affine
	snarkVMG2Gen bls12377.G2Affine
)

func init() {
	// see https://github.com/AleoHQ/snarkVM/blob/6579ca49ddf7693a7482b26d99adbf79bf112a41/curves/src/bls12_377/g1.rs
	snarkVMG1Gen.X.SetString("89363714989903307245735717098563574705733591463163614225748337416674727625843187853442697973404985688481508350822")
	snarkVMG1Gen.Y.SetString("3702177272937190650578065972808860481433820514072818216637796320125658674906330993856598323293086021583822603349")

	snarkVMG2Gen.X.A0.SetString("170590608266080109581922461902299092015242589883741236963254737235977648828052995125541529645051927918098146183295")
	snarkVMG2Gen.X.A1.SetString("83407003718128594709087171351153471074446327721872642659202721143408712182996929763094113874399921859453255070254")
	snarkVMG2Gen.Y.A0.SetString("1843833842842620867708835993770650838640642469700861403869757682057607397502738488921663703124647238454792872005")
	snarkVMG2Gen.Y.A1.SetString("33145532013610981697337930729788870077912093258611421158732879580766461459275194744385880708057348608045241477209")
}

var (
	outputSRS        = flag.String("srs", "", "output gnark SRS") // optional flag to set the output gnark SRS generated by this program
	noSubgroupChecks = flag.Bool("no-subgroup-checks", false, "disable subgroup checks")
)

// This tool is dirty with many constants and hardcoded values.
// It aims to parse 2 rounds of the Aleo ceremony and verify that the points are on the curve and in the subgroup.
// Then it creates a KZG srs from the last round of the ceremony, in the gnark format.
func main() {
	flag.Parse()

	var wout io.Writer
	var srs *kzg.SRS

	// if flag is set, we write the full KZG srs to provided file, in gnark format.
	if *outputSRS != "" {
		f, err := os.Create(*outputSRS)
		if err != nil {
			log.Fatalf("failed to create gnark SRS file: %v", err)
		}
		defer f.Close()
		wout = f
		srs = &kzg.SRS{}
		srs.Pk.G1 = make([]bls12377.G1Affine, 0, nbTauG1*nbChunks) // TODO @gbotrel being able to stream write the SRS would be nice
		srs.Vk.G1 = snarkVMG1Gen
		srs.Vk.G2[0] = snarkVMG2Gen
		srs.Vk.Lines[0] = bls12377.PrecomputeLines(srs.Vk.G2[0])
	}

	// TODO verify hash chain (chunk(n) of round(t) follows chunk(n) of round(t-1))
	// TODO verify against public signatures map

	// initial version; verifies the last 2 rounds of the ceremony.
	// chunk by chunk we:
	// if chunk == 0--> verify the key ratio and that TauG1[0] is the prime subgroup generator
	// verify that the points are on on the subgroup and that they are, powers of tau.
	lastRoundRootDir := filepath.Join(roundsRootDir, "round_139")
	prevRoundRootDir := filepath.Join(roundsRootDir, "round_138")

	currChunk := newChunk()
	prevChunk := newChunk()

	for i := 0; i < nbChunks; i++ {
		log.Printf("verifying chunk %d", i)

		// 1- read the chunks from disk (last round and current round)
		lastChunkPath := filepath.Join(lastRoundRootDir, fmt.Sprintf("chunk_%d", i), "contribution_0.verified")
		prevChunkPath := filepath.Join(prevRoundRootDir, fmt.Sprintf("chunk_%d", i), "contribution_0.verified")

		if err := currChunk.ReadFrom(lastChunkPath, i == 0); err != nil {
			log.Fatalf("failed to read chunk %d of last round: %s", i, err.Error())
		}

		if err := prevChunk.ReadFrom(prevChunkPath, i == 0); err != nil {
			log.Fatalf("failed to read chunk %d of prev round: %s", i, err.Error())
		}

		if !*noSubgroupChecks {
			// ensure points are on the curve and in the subgroup
			if err := currChunk.VerifyPoints(); err != nil {
				log.Fatalf("failed to verify chunk %d of last round: %s", i, err.Error())
			}

			if err := prevChunk.VerifyPoints(); err != nil {
				log.Fatalf("failed to verify chunk %d of prev round: %s", i, err.Error())
			}
		}

		if i == 0 {
			if !sameRatio(currChunk.TauG1[1], prevChunk.TauG1[1], prevChunk.TauG2[1], currChunk.TauG2[1]) {
				log.Fatalf("TauG1[1] for chunk %d not computed well.", i)
			}
		}
		// the Aztec way
		if !currChunk.IsValid() {
			log.Fatalf("chunk %d of last round is not valid (the aztec way)", i)
		}

		if srs != nil {
			srs.Pk.G1 = append(srs.Pk.G1, currChunk.TauG1...)
			if i == 0 {
				srs.Vk.G2[1] = currChunk.TauG2[1]
				srs.Vk.Lines[1] = bls12377.PrecomputeLines(srs.Vk.G2[1])
			}
		}

	}

	if wout != nil {
		log.Printf("running sanity check on gnark SRS")
		srsSanityCheck(srs)
		// write gnark SRS to file
		log.Printf("writing gnark SRS to file %s", *outputSRS)
		if _, err := srs.WriteRawTo(wout); err != nil {
			log.Fatalf("failed to write gnark SRS to file: %v", err)
		}
	}

	log.Println("done")
}

func srsSanityCheck(srs *kzg.SRS) {
	// we can now use the SRS to verify a proof
	// create a polynomial
	f := randomPolynomial(60)

	// commit the polynomial
	digest, err := kzg.Commit(f, srs.Pk)
	if err != nil {
		log.Fatalf("failed to commit polynomial: %v", err)
	}

	// compute opening proof at a random point
	var point fr.Element
	point.SetString("4321")
	proof, err := kzg.Open(f, point, srs.Pk)
	if err != nil {
		log.Fatalf("failed to open polynomial: %v", err)
	}

	// verify the claimed valued
	expected := eval(f, point)
	if !proof.ClaimedValue.Equal(&expected) {
		log.Fatal("inconsistent claimed value")
	}

	// verify correct proof
	err = kzg.Verify(&digest, &proof, point, srs.Vk)
	if err != nil {
		log.Fatalf("failed to verify proof: %v", err)
	}
}

func randomPolynomial(size int) []fr.Element {
	f := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		f[i].SetRandom()
	}
	return f
}

// eval returns p(point) where p is interpreted as a polynomial
// ∑_{i<len(p)}p[i]Xⁱ
func eval(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	n := len(p)
	res.Set(&p[n-1])
	for i := n - 2; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}
