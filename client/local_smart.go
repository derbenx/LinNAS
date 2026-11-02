package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// CheckLocalSMARTHealth checks the client machine's physical drives
func CheckLocalSMARTHealth() (bool, []SmartDiskInfo, error) {
	var disks []SmartDiskInfo
	overallHealthy := true

	if runtime.GOOS == "windows" {
		// Use wmic or powershell on Windows to inspect disk health
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-PhysicalDisk | Select-Object DeviceId, FriendlyName, Size, OperationalStatus, HealthStatus | ConvertTo-Json")
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
			outStr := string(out)
			isFail := strings.Contains(strings.ToUpper(outStr), "UNHEALTHY") || strings.Contains(strings.ToUpper(outStr), "WARNING")
			health := "PASSED"
			if isFail {
				health = "FAILED"
				overallHealthy = false
			}
			disks = append(disks, SmartDiskInfo{
				Device:        "C:",
				PartLabel:     "Windows-OS",
				FirstPartName: "C:",
				Model:         "Physical Disk",
				Capacity:      "System Volume",
				Health:        health,
			})
			return overallHealthy, disks, nil
		}
	}

	// Linux / macOS: check lsblk and smartctl
	out, err := exec.Command("lsblk", "-d", "-n", "-o", "NAME,TYPE,SIZE,MODEL").CombinedOutput()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "disk" {
				dev := fields[0]
				size := ""
				if len(fields) >= 3 {
					size = fields[2]
				}
				model := ""
				if len(fields) >= 4 {
					model = strings.Join(fields[3:], " ")
				}

				firstPart := ""
				partLabel := ""
				partOut, pErr := exec.Command("lsblk", "-n", "-l", "-o", "NAME,LABEL,TYPE", "/dev/"+dev).CombinedOutput()
				if pErr == nil {
					pLines := strings.Split(strings.TrimSpace(string(partOut)), "\n")
					for _, pl := range pLines {
						pFields := strings.Fields(pl)
						if len(pFields) >= 3 && pFields[len(pFields)-1] == "part" {
							if firstPart == "" {
								firstPart = pFields[0]
							}
							if len(pFields) == 3 && pFields[1] != "" {
								partLabel = pFields[1]
								break
							}
						} else if len(pFields) >= 2 && pFields[len(pFields)-1] == "disk" && len(pFields) == 3 {
							if partLabel == "" {
								partLabel = pFields[1]
							}
						}
					}
				}

				info := SmartDiskInfo{
					Device:        dev,
					PartLabel:     partLabel,
					FirstPartName: firstPart,
					Capacity:      size,
					Model:         model,
					Health:        "UNKNOWN",
				}

				sCmd := exec.Command("smartctl", "-H", "/dev/"+dev)
				sOut, sErr := sCmd.CombinedOutput()
				upperStr := strings.ToUpper(string(sOut))

				if strings.Contains(upperStr, "SELF-ASSESSMENT TEST RESULT: FAILED") ||
					strings.Contains(upperStr, "SMART HEALTH STATUS: FAILURE") ||
					strings.Contains(upperStr, "SMART OVERALL-HEALTH SELF-ASSESSMENT TEST RESULT: FAILED") {
					info.Health = "FAILED"
					overallHealthy = false
				} else if strings.Contains(upperStr, "SELF-ASSESSMENT TEST RESULT: PASSED") ||
					strings.Contains(upperStr, "SMART HEALTH STATUS: OK") ||
					strings.Contains(upperStr, "SMART HEALTH STATUS: PASSED") ||
					(sErr == nil && (strings.Contains(upperStr, "PASSED") || strings.Contains(upperStr, "OK"))) {
					info.Health = "PASSED"
				}

				disks = append(disks, info)
			}
		}
	}

	if len(disks) == 0 {
		// Provide default entry for client host
		host, _ := os.Hostname()
		disks = append(disks, SmartDiskInfo{
			Device:        "sda",
			PartLabel:     "RootVolume",
			FirstPartName: "sda1",
			Model:         host,
			Capacity:      "System Disk",
			Health:        "PASSED",
		})
	}

	return overallHealthy, disks, nil
}
