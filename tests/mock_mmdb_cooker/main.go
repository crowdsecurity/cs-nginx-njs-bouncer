package main

import (
	"log"
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	// as db
	writer, _ := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType:            "My-ASN-DB",
			RecordSize:              28,
			IncludeReservedNetworks: true,
		},
	)

	asnMap := mmdbtype.Map{}
	asnMap["autonomous_system_number"] = mmdbtype.Uint32(12300)
	asnMap["autonomous_system_organization"] = mmdbtype.String("acme")
	writer.Insert(&net.IPNet{
		IP:   net.IPv4(127, 0, 0, 1),
		Mask: net.CIDRMask(32, 32),
	},
		asnMap,
	)

	fh, err := os.Create("as.mmdb")
	if err != nil {
		log.Fatal(err)
	}

	_, err = writer.WriteTo(fh)
	if err != nil {
		log.Fatal(err)
	}

	// country db
	writer, _ = mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType:            "My-Country-DB",
			RecordSize:              24,
			IncludeReservedNetworks: true,
		},
	)

	countryRootMap := mmdbtype.Map{}
	countryMap := mmdbtype.Map{}
	countryMap["iso_code"] = mmdbtype.String("US")
	countryRootMap["country"] = countryMap

	writer.Insert(&net.IPNet{
		IP:   net.IPv4(127, 0, 0, 1),
		Mask: net.CIDRMask(32, 32),
	},
		countryRootMap)

	fh, err = os.Create("cn.mmdb")
	if err != nil {
		log.Fatal(err)
	}

	_, err = writer.WriteTo(fh)
	if err != nil {
		log.Fatal(err)
	}
}
