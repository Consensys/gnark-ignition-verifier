package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/kzg"
	"github.com/consensys/gnark-ignition-verifier/ignition"
)

const startIdx = 30

func main() {

	// Example usage of the ignition package
	config := ignition.Config{
		BaseURL:  "https://aztec-ignition.s3.amazonaws.com/",
		Ceremony: "TINY_TEST_5", // "MAIN IGNITION"
		CacheDir: "./data",
	}
	if config.CacheDir != "" {
		os.MkdirAll(config.CacheDir, os.ModePerm)
	}

	// 1. fetch manifest
	log.Println("fetch manifest")
	manifest, err := ignition.NewManifest(config)
	if err != nil {
		log.Fatal("when fetching manifest: ", err)
	}

	// sanity check
	if len(manifest.Participants) <= startIdx+1 {
		log.Fatal("not enough participants")
	}
	// p := profile.Start(profile.MemProfile, profile.ProfilePath("."), profile.NoShutdownHook)
	// 2. we read two contributions at a time, and check that the second one follows the first one
	current, next := ignition.NewContribution(manifest.NumG1Points), ignition.NewContribution(manifest.NumG1Points)

	config.CacheDir = "" // temporary hack to avoid downloading all files.

	log.Printf("processing contributions %d and %d", startIdx, startIdx+1)
	if err := current.Get(manifest.Participants[startIdx], config); err != nil {
		log.Fatal("when fetching contribution: ", err)
	}
	if err := next.Get(manifest.Participants[startIdx+1], config); err != nil {
		log.Fatal("when fetching contribution: ", err)
	}
	if !next.Follows(&current) {
		log.Fatalf("contribution %d does not follow contribution %d", startIdx+1, startIdx)
	}
	for i := startIdx + 2; i < len(manifest.Participants); i++ {
		log.Println("processing contribution ", i+1)
		current, next = next, current
		if err := next.Get(manifest.Participants[i], config); err != nil {
			log.Fatal("when fetching contribution ", i+1, ": ", err)
		}
		if !next.Follows(&current) {
			log.Fatal("contribution ", i+1, " does not follow contribution ", i, ": ", err)
		}
	}
	// p.Stop()

	log.Println("success ✅: all contributions are valid")

	// we use the last contribution to build a kzg SRS for bn254
	srs := kzg.SRS{
		Pk: kzg.ProvingKey{
			G1: next.G1,
		},
		Vk: kzg.VerifyingKey{
			G1: next.G1[0],
			G2: [2]bn254.G2Affine{
				g2gen,
				next.G2[0],
			},
		},
	}

	// sanity check
	sanityCheck(&srs)
	log.Println("success ✅: kzg sanity check with SRS")

	if config.CacheDir == "" {
		config.CacheDir = "./data"
		os.MkdirAll(config.CacheDir, os.ModePerm)
	}

	// we can now serialize the SRS and use it, for example in gnark / PlonK circuits
	n := len(srs.Pk.G1)
	srsPath := fmt.Sprintf("kzg_srs_%d_bn254_%s", n, config.Ceremony)
	srsPath = filepath.Join(config.CacheDir, srsPath)
	f, err := os.Create(srsPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	log.Println("writing SRS to ", srsPath)
	if _, err := srs.WriteTo(f); err != nil {
		log.Fatal(err)
	}
	log.Println("success ✅: SRS written to ", srsPath)

}

func sanityCheck(srs *kzg.SRS) {
	// we can now use the SRS to verify a proof
	// create a polynomial
	f := randomPolynomial(60)

	// commit the polynomial
	digest, err := kzg.Commit(f, srs.Pk)
	if err != nil {
		log.Fatal(err)
	}

	// compute opening proof at a random point
	var point fr.Element
	point.SetString("4321")
	proof, err := kzg.Open(f, point, srs.Pk)
	if err != nil {
		log.Fatal(err)
	}

	// verify the claimed valued
	expected := eval(f, point)
	if !proof.ClaimedValue.Equal(&expected) {
		log.Fatal("inconsistent claimed value")
	}

	// verify correct proof
	err = kzg.Verify(&digest, &proof, point, srs.Vk)
	if err != nil {
		log.Fatal(err)
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

var g2gen bn254.G2Affine

func init() {
	_, _, _, g2gen = bn254.Generators()
}
