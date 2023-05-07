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
var r7 = "Asset IP Address,Service Port,Vulnerability Test Result Code,Vulnerability ID,Vulnerability CVE IDs,Vulnerability Severity Level,Vulnerability Title"

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

func Rapid7toNative(in []string) (out []string) {
	out = make([]string, 15)
	out[PRODUCT] = "Rapid7"
	out[IP_ADDRESS] = in[AssetIPAddress]
	out[PORT] = in[ServicePort]
	_ = in[VulnerabilityTestResultCode]
	out[VULNERABILITY_ID] = in[VulnerabilityID]
	out[CVE_IDS] = in[VulnerabilityCVEIDs]
	out[SEVERITY] = in[VulnerabilitySeverityLevel]
	out[VULNERABILITY_TITLE] = in[VulnerabilityTitle]
	return
}
func main() {
	if len(os.Args) != 3 {
		fmt.Printf("RSeven: convert from Rapid7 CSV report to Tipping Point SMS native CSV format\nUsage: %s input_filename output_filename\n", os.Args[0])
		os.Exit(1)
	}
	inFile, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer inFile.Close()

	csvReader := csv.NewReader(inFile)
	inData, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	outFile, err := os.Create(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()
	//csvWriter := csv.NewWriter(outFile)
	//defer csvWriter.Flush()
	//csvWriter.Write(strings.Split(header, ","))
	fmt.Fprintf(outFile, "%s\n", header)
	for _, inLine := range inData[1:] {
		outData := Rapid7toNative(inLine)
		for i := range outData {
			outData[i] = "\"" + outData[i] + "\""
		}
		line := strings.Join(outData, ",")
		//fmt.Println(outData)
		//csvWriter.Write(outData)
		fmt.Fprintf(outFile, "%s\n", line)
	}
}
