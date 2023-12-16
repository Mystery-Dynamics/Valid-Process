package main

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/StackExchange/wmi"
)

type Win32_Process struct {
	Name           string
	ProcessId      uint32
	ExecutablePath *string
}

func main() {
	var unsignedProcesses []string
	var scannedProcesses map[string]bool = make(map[string]bool)
	var processes []Win32_Process
	query := "SELECT Name, ProcessId, ExecutablePath FROM Win32_Process"

	err := wmi.Query(query, &processes)
	if err != nil {
		fmt.Println("Failed to retrieve processes:", err)
		return
	}

	fmt.Println("List of Processes:")
	for _, process := range processes {
		fmt.Printf("Name: %s, PID: %d\n", process.Name, process.ProcessId)
		if process.ExecutablePath != nil {
			signerInfo, err := getSignerInformation(*process.ExecutablePath)
			if err != nil {
				fmt.Printf("Error getting signer information for %s: %s\n", *process.ExecutablePath, err)
				unsignedProcesses = append(unsignedProcesses, *process.ExecutablePath)
			} else {
				fmt.Printf("Signer Information for %s: %s\n", *process.ExecutablePath, signerInfo)
			}
		}
	}

	// Deduplicate unsigned processes
	unsignedProcesses = removeDuplicates(unsignedProcesses)

	// Scan only the unique unsigned processes with Windows Defender
	fmt.Println("\nScanning unsigned processes:")
	fmt.Println(unsignedProcesses)
	for _, process := range unsignedProcesses {
		if _, ok := scannedProcesses[process]; !ok {
			err := scanWithDefender(process)
			if err != nil {
				fmt.Printf("Error scanning %s with Windows Defender: %s\n", process, err)
			} else {
				fmt.Printf("Scanned %s with Windows Defender\n", process)
				scannedProcesses[process] = true
			}
		}
	}
}

func getSignerInformation(filePath string) (string, error) {
	output, err := exec.Command("powershell", "-Command", "(Get-AuthenticodeSignature '"+filePath+"').SignerCertificate.Subject").Output()
	if err != nil {
		return "", err
	}

	signerInfo := strings.TrimSpace(string(output))
	return signerInfo, nil
}

func scanWithDefender(filePath string) error {
	_, err := exec.Command("powershell", "-Command", "Start-MpScan -ScanPath '"+filePath+"' -ScanType QuickScan").Output()
	if err != nil {
		return err
	}
	return nil
}

func removeDuplicates(elements []string) []string {
	encountered := map[string]bool{}
	result := []string{}

	for v := range elements {
		if encountered[elements[v]] == true {
			// Do not add duplicate.
		} else {
			// Record this element as an encountered element.
			encountered[elements[v]] = true
			// Append to result slice.
			result = append(result, elements[v])
		}
	}
	return result
}
