package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strconv"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
)

var (
	fInput = flag.String("input", "", "path to the input file")
)

// This tool job is to parse a valid canonical kzg.SRS gnark object
// and produce, for each powers of 2 in the range, a {canonical,lagrange} SRS
// pair.
// Modify the imports & constants to match other curves.
// TODO @gbotrel make a gnark-cli package that helps with this kind of tasks
func main() {
	flag.Parse()

	// 1 - read the full SRS (input)
	var fullSRS kzg.SRS
	f, err := os.Open(*fInput)
	if err != nil {
		log.Fatalf("failed to open input file: %v", err)
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 1<<20)
	if _, err := fullSRS.UnsafeReadFrom(r); err != nil {
		log.Fatalf("failed to read SRS from file: %v", err)
	}

	maxSize := min(1<<27, len(fullSRS.Pk.G1))
	const minSize = 1 << 8

	// file format is kzg_srs_canonical|lagrange_size_bls12377_aleo

	for size := minSize; size <= maxSize; size <<= 1 {
		// for each size, we need to create a new SRS
		truncatedSRS := fullSRS
		truncatedSRS.Pk.G1 = truncatedSRS.Pk.G1[:size]

		// write the canonical SRS
		if err := writeToFile(&truncatedSRS, "kzg_srs_canonical_"+strconv.Itoa(size)+"_bls12377_aleo"); err != nil {
			log.Fatalf("failed to write canonical SRS to file: %v", err)
		}

		// convert to lagrange and be patient.
		truncatedSRS.Pk.G1, err = kzg.ToLagrangeG1(truncatedSRS.Pk.G1)
		if err != nil {
			log.Fatalf("failed to convert to lagrange: %v", err)
		}

		// write the lagrange SRS
		if err := writeToFile(&truncatedSRS, "kzg_srs_lagrange_"+strconv.Itoa(size)+"_bls12377_aleo"); err != nil {
			log.Fatalf("failed to write lagrange SRS to file: %v", err)
		}

	}
}

func writeToFile(srs *kzg.SRS, fPath string) error {
	f, err := os.Create(fPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 1<<20)
	if _, err := srs.WriteRawTo(w); err != nil {
		return err
	}

	return w.Flush()
}
