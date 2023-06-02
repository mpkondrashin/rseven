package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
)

type NativeColumn int

const (
	VENDOR NativeColumn = iota
	PRODUCT
	VERSION
	ASSET_GROUP
	IP_ADDRESS
	MAC_ADDRESS
	HOST_NAME
	PORT
	SERVICE
	CVE_IDS
	VULNERABILITY_ID
	VULNERABILITY_TITLE
	DEVICE_SCAN_START_DATE
	DEVICE_SCAN_END_DATE
	SEVERITY
)

var header = "VENDOR,PRODUCT,VERSION,ASSET_GROUP,IP_ADDRESS,MAC_ADDRESS,HOST_NAME,PORT,SERVICE,CVE_IDS,VULNERABILITY_ID,VULNERABILITY_TITLE,DEVICE_SCAN_START_DATE,DEVICE_SCAN_END_DATE,SEVERITY"

type RapidSevenColumn int

const (
	AssetIPAddress RapidSevenColumn = iota
	ServicePort
	VulnerabilityTestResultCode
	VulnerabilityID
	VulnerabilityCVEIDs
	VulnerabilitySeverityLevel
	VulnerabilityTitle
)

func Rapid7toNative(in []string) (out []string, err error) {
	out = make([]string, SEVERITY+1)
	out[PRODUCT] = "Rapid7"
	out[IP_ADDRESS] = in[AssetIPAddress]
	if out[IP_ADDRESS] == "" {
		return nil, fmt.Errorf("IP address (column %d) is missing", AssetIPAddress+1)
	}
	out[PORT] = in[ServicePort]
	_ = in[VulnerabilityTestResultCode]
	out[VULNERABILITY_ID] = in[VulnerabilityID]
	out[CVE_IDS] = in[VulnerabilityCVEIDs]
	if out[CVE_IDS] == "" {
		return nil, fmt.Errorf("CVE IDs (column %d) are missing", VulnerabilityCVEIDs+1)
	}
	out[SEVERITY] = in[VulnerabilitySeverityLevel]
	out[VULNERABILITY_TITLE] = in[VulnerabilityTitle]
	for i := range out {
		out[i] = "\"" + out[i] + "\""
	}
	return
}

func ProcessFile(inFileName, outFileName string) {
	inFile, err := os.Open(inFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer inFile.Close()

	csvReader := csv.NewReader(inFile)
	inData, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	outFile, err := os.Create(outFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	fmt.Fprintf(outFile, "%s\n", header)
	for lineNumber, inLine := range inData[1:] {
		outData, err := Rapid7toNative(inLine)
		if err != nil {
			log.Printf("%s[%d]: %v", inFileName, lineNumber+2, err)
			continue
		}
		line := strings.Join(outData, ",")
		fmt.Fprintf(outFile, "%s\n", line)
	}

}

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("RSeven: convert from Rapid7 CSV report to Tipping Point SMS native CSV format\nUsage: %s input_filename output_filename\n", os.Args[0])
		os.Exit(1)
	}
	inFileName := os.Args[1]
	outFileName := os.Args[2]
	ProcessFile(inFileName, outFileName)
}
