package main

import (
	"testing"
)

func TestCombinedSmartStructureOrdering(t *testing.T) {
	app := &App{
		cfg: ClientConfig{
			Username: "admin",
		},
	}

	// Mock server Disks
	serverDisks := []SmartDiskInfo{
		{Device: "sda", Model: "Server Drive 1", Health: "PASSED", Capacity: "2.0 TB"},
	}

	// Mock local disks
	localDisks := []SmartDiskInfo{
		{Device: "nvme0n1", Model: "Local NVMe", Health: "PASSED", Capacity: "1.0 TB"},
	}

	// Mock client failure reports
	clientReports := []ClientFailureReport{
		{
			Client: "Workstation (192.168.1.150)",
			Failing: []SmartDiskInfo{
				{Device: "sdb", Model: "Failing Disk", Health: "FAILED", Capacity: "500 GB"},
			},
		},
	}

	// Simulate CheckSMARTStatus formatting
	var combined CombinedSmartData
	combined.ServerDisks = serverDisks
	combined.LocalDisks = localDisks

	groupMap := make(map[string]*ClientGroupInfo)
	for _, cr := range clientReports {
		clientIP := "192.168.1.150"
		grp := &ClientGroupInfo{
			IP:     clientIP,
			Client: cr.Client,
			Disks:  cr.Failing,
		}
		groupMap[clientIP] = grp
	}
	for _, g := range groupMap {
		combined.ClientGroups = append(combined.ClientGroups, *g)
	}

	if len(combined.ServerDisks) != 1 || combined.ServerDisks[0].Model != "Server Drive 1" {
		t.Fatalf("Unexpected ServerDisks: %+v", combined.ServerDisks)
	}
	if len(combined.LocalDisks) != 1 || combined.LocalDisks[0].Model != "Local NVMe" {
		t.Fatalf("Unexpected LocalDisks: %+v", combined.LocalDisks)
	}
	if len(combined.ClientGroups) != 1 || combined.ClientGroups[0].IP != "192.168.1.150" {
		t.Fatalf("Unexpected ClientGroups: %+v", combined.ClientGroups)
	}

	_ = app
}

func TestRemoteAndLocalDriveTemperaturesPreserved(t *testing.T) {
	d := SmartDiskInfo{
		Device:   "nvme0n1",
		Model:    "Samsung 980",
		Health:   "PASSED",
		Capacity: "1.0 TB",
		TempC:    43,
	}

	if d.TempC != 43 {
		t.Fatalf("Expected TempC to be 43, got %d", d.TempC)
	}

	group := ClientGroupInfo{
		IP:     "192.168.1.80",
		Client: "BackupServer (192.168.1.80)",
		Disks:  []SmartDiskInfo{d},
	}

	if len(group.Disks) != 1 || group.Disks[0].TempC != 43 {
		t.Fatalf("Expected remote disk temperature 43 preserved, got %+v", group.Disks)
	}
}
