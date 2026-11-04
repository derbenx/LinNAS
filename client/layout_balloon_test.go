package main

import (
	"fmt"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func TestClientLayoutDoesNotBalloon(t *testing.T) {
	a := test.NewApp()
	w := a.NewWindow("LinNAS Local Cloud")
	initW := float32(760)
	initH := float32(560)
	w.Resize(fyne.NewSize(initW, initH))

	treeBox := container.NewVBox()
	treeScroll := container.NewScroll(treeBox)
	treeScroll.SetMinSize(fyne.NewSize(660, 220))

	serverSmartBannerBox := container.NewVBox()
	smartTilesContainer := container.NewGridWrap(fyne.NewSize(135, 88))
	serverSmartScroll := container.NewScroll(container.NewVBox(
		serverSmartBannerBox,
		smartTilesContainer,
	))

	localSmartBannerBox := container.NewVBox()
	localSmartTilesContainer := container.NewGridWrap(fyne.NewSize(135, 88))
	localSmartScroll := container.NewScroll(container.NewVBox(
		localSmartBannerBox,
		localSmartTilesContainer,
	))

	tabs := container.NewAppTabs(
		container.NewTabItem("Folders", treeScroll),
		container.NewTabItem("Server SMART", serverSmartScroll),
		container.NewTabItem("Local SMART", localSmartScroll),
	)
	w.SetContent(tabs)

	if w.Canvas().Size().Width > 800 {
		t.Fatalf("Initial window width too wide: %v", w.Canvas().Size())
	}

	// 1. Force extreme long folder tree updates
	for i := 0; i < 30; i++ {
		treeBox.Add(widget.NewCheck(fmt.Sprintf("📁 /very/extremely/long/path/nested/subfolder/deep/level/%d/subitem/filename/data/storage/folder/item", i), func(b bool) {}))
	}
	treeBox.Refresh()
	treeScroll.Refresh()
	w.Canvas().Refresh(w.Content())

	if w.Canvas().Size().Width > 800 {
		t.Fatalf("Window ballooned after tree update! Width: %v", w.Canvas().Size().Width)
	}

	// 2. Force SMART drive updates with long client hostnames & model names
	for i := 0; i < 20; i++ {
		smartTilesContainer.Add(createCompactSmartTile(SmartDiskInfo{
			Device:    fmt.Sprintf("/dev/nvme%dn1p1", i),
			PartLabel: fmt.Sprintf("StorageDrive-%d-Label-UltraLong", i),
			Model:     fmt.Sprintf("Client VeryLongHostname-%d (Samsung SSD 980 PRO 2TB NVMe)", i),
			Capacity:  "2.0 TB",
			Health:    "PASSED",
			TempC:     42,
		}))
		localSmartTilesContainer.Add(createCompactSmartTile(SmartDiskInfo{
			Device:    fmt.Sprintf("/dev/sd%c", 'a'+i),
			PartLabel: "LocalDataPart",
			Model:     "WDC WD40EFRX-68N32N0 NASWare",
			Capacity:  "4.0 TB",
			Health:    "PASSED",
			TempC:     35,
		}))
	}
	smartTilesContainer.Refresh()
	serverSmartScroll.Refresh()
	localSmartTilesContainer.Refresh()
	localSmartScroll.Refresh()
	w.Canvas().Refresh(w.Content())

	finalWidth := w.Canvas().Size().Width
	fmt.Println("Window Width after extreme data updates:", finalWidth)
	if finalWidth > 800 {
		t.Fatalf("Window ballooned after SMART updates! Width: %v (expected <= 800)", finalWidth)
	}

	// 3. Verify user can still resize
	w.Resize(fyne.NewSize(950, 700))
	if w.Canvas().Size().Width != 950 {
		t.Fatalf("User manual resize failed: got %v", w.Canvas().Size().Width)
	}
}
