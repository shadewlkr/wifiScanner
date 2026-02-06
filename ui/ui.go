package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"wifiscanner/scanner"
)

// Cyberpunk neon color palette
const (
	colorCyan    = "#00ffff"
	colorMagenta = "#ff00ff"
	colorGreen   = "#00ff41"
	colorOrange  = "#ff8c00"
	colorRed     = "#ff0040"
	colorDim     = "#444444"
	colorMuted   = "#888888"
	colorYellow  = "#ffff00"
	colorHotPink = "#ff1493"
	colorBg      = "#0a0a1a"

	colorDarkMagenta = "#330033"

	refreshInterval = 10 * time.Second
	newBadgeTTL     = 30 * time.Second
)

// App is the terminal UI application.
type App struct {
	app      *tview.Application
	scanner  *scanner.Scanner
	header   *tview.TextView
	table    *tview.Table
	footer   *tview.TextView
	networks []scanner.Network
	sortBy   string
	scanning bool

	// Session state tracking
	session *scanner.Session

	// Detail panel
	detail      *tview.TextView
	pages       *tview.Pages
	detailShown bool

	// New network alerts
	newBSSIDs map[string]time.Time
}

// New creates a new App wired to the given scanner.
func New(s *scanner.Scanner) *App {
	return &App{
		scanner:   s,
		sortBy:    "signal",
		session:   scanner.NewSession(),
		newBSSIDs: make(map[string]time.Time),
	}
}

// Run starts the TUI event loop (blocks until exit).
func (a *App) Run() error {
	a.app = tview.NewApplication()

	a.buildHeader()
	a.buildTable()
	a.buildFooter()
	a.buildDetail()

	// Main layout
	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(a.header, 5, 0, false).
		AddItem(a.table, 0, 1, true).
		AddItem(a.footer, 1, 0, false)

	// Pages overlay for detail modal
	a.pages = tview.NewPages().
		AddPage("main", layout, true, true).
		AddPage("detail", a.buildDetailModal(), true, false)

	// Global keybindings
	a.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			if a.detailShown {
				a.hideDetail()
				return nil
			}
			a.app.Stop()
			return nil
		case tcell.KeyEnter:
			if a.detailShown {
				a.hideDetail()
				return nil
			}
			a.showDetail()
			return nil
		case tcell.KeyRune:
			if a.detailShown {
				return nil // Ignore rune keys while detail is open
			}
			switch event.Rune() {
			case 'q', 'Q':
				a.app.Stop()
				return nil
			case 'r', 'R':
				go a.doScan()
				return nil
			case 's', 'S':
				a.cycleSortOrder()
				return nil
			}
		}
		return event
	})

	// Fire initial scan
	go a.doScan()

	// Periodic auto-refresh
	go a.autoRefresh()

	a.app.SetRoot(a.pages, true)
	return a.app.Run()
}

// ── Header ──────────────────────────────────────────────────────────────────

func (a *App) buildHeader() {
	a.header = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter).
		SetWordWrap(false)

	a.header.
		SetBorder(true).
		SetBorderColor(tcell.GetColor(colorMagenta)).
		SetTitle(fmt.Sprintf(" [%s]◈[-] [%s]SPECTR[-][%s]//[-][%s]SCAN[-] [%s]◈[-] ",
			colorHotPink, colorCyan, colorMagenta, colorCyan, colorHotPink)).
		SetTitleAlign(tview.AlignCenter).
		SetBorderPadding(0, 0, 1, 1)

	a.updateHeader()
}

func (a *App) updateHeader() {
	mode := fmt.Sprintf("[%s]◉ LIVE[-]", colorGreen)
	if a.scanner.Demo {
		mode = fmt.Sprintf("[%s]◉ DEMO[-]", colorOrange)
	}

	iface := a.scanner.Interface
	if iface == "" {
		iface = "..."
	}

	scanTime := "—"
	netCount := "0"
	if len(a.networks) > 0 {
		scanTime = a.networks[0].LastSeen.Format("15:04:05")
		netCount = fmt.Sprintf("%d", len(a.networks))
	}

	status := "READY"
	statusColor := colorGreen
	if a.scanning {
		status = "SCANNING"
		statusColor = colorCyan
	}

	line1 := fmt.Sprintf(
		"[%s]WiFi Spectrum Analyzer[-]    %s    [%s]Status:[-] [%s]%s[-]",
		colorMuted, mode, colorDim, statusColor, status,
	)
	line2 := fmt.Sprintf(
		"[%s]Interface:[-] [%s]%s[-]  [%s]│[-]  [%s]Networks:[-] [%s]%s[-]  [%s]│[-]  [%s]Last Scan:[-] [%s]%s[-]  [%s]│[-]  [%s]Sort:[-] [%s]%s[-]",
		colorDim, colorCyan, iface, colorDim,
		colorDim, colorCyan, netCount, colorDim,
		colorDim, colorCyan, scanTime, colorDim,
		colorDim, colorGreen, strings.ToUpper(a.sortBy),
	)

	a.header.SetText(line1 + "\n" + line2)
}

// ── Table ───────────────────────────────────────────────────────────────────

func (a *App) buildTable() {
	a.table = tview.NewTable().
		SetBorders(false).
		SetSelectable(true, false).
		SetFixed(1, 0).
		SetSeparator(tview.Borders.Vertical)

	a.table.
		SetBorder(true).
		SetBorderColor(tcell.GetColor(colorMagenta)).
		SetTitle(fmt.Sprintf(" [%s]NETWORK TARGETS[-] ", colorHotPink)).
		SetTitleAlign(tview.AlignLeft).
		SetBorderPadding(0, 0, 1, 1)

	a.setTableHeaders()
}

func (a *App) setTableHeaders() {
	headers := []struct {
		text  string
		width int
		exp   int
		align int
	}{
		{"▌SIGNAL▐", 12, 0, tview.AlignLeft},
		{"dBm", 5, 0, tview.AlignRight},
		{"SPARK", 12, 0, tview.AlignLeft},
		{"SSID", 24, 1, tview.AlignLeft},
		{"BSSID", 17, 0, tview.AlignLeft},
		{"VENDOR", 16, 0, tview.AlignLeft},
		{"CH", 4, 0, tview.AlignRight},
		{"FREQ", 6, 0, tview.AlignRight},
		{"BAND", 5, 0, tview.AlignCenter},
		{"SECURITY", 10, 0, tview.AlignLeft},
	}

	for i, h := range headers {
		cell := tview.NewTableCell(" " + h.text + " ").
			SetTextColor(tcell.GetColor(colorMagenta)).
			SetBackgroundColor(tcell.GetColor("#1a0033")).
			SetSelectable(false).
			SetExpansion(h.exp).
			SetAlign(h.align).
			SetAttributes(tcell.AttrBold)
		a.table.SetCell(0, i, cell)
	}
}

func (a *App) updateTable() {
	// Clear data rows
	for r := a.table.GetRowCount() - 1; r >= 1; r-- {
		a.table.RemoveRow(r)
	}

	now := time.Now()

	for i, net := range a.networks {
		row := i + 1

		// Check if this network is "new"
		isNew := false
		if t, ok := a.newBSSIDs[net.BSSID]; ok {
			if now.Sub(t) < newBadgeTTL {
				isNew = true
			}
		}

		var rowBg tcell.Color
		if isNew {
			rowBg = tcell.GetColor(colorDarkMagenta)
		} else {
			rowBg = tcell.ColorDefault
		}

		// Col 0: Signal bars
		bars, barColor := signalBars(net.Signal)
		filled := strings.Repeat("█", bars)
		empty := strings.Repeat("░", 10-bars)
		a.table.SetCell(row, 0, tview.NewTableCell(filled+empty).
			SetTextColor(tcell.GetColor(barColor)).
			SetBackgroundColor(rowBg))

		// Col 1: dBm
		a.table.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%d", net.Signal)).
			SetTextColor(tcell.GetColor(barColor)).
			SetAlign(tview.AlignRight).
			SetBackgroundColor(rowBg))

		// Col 2: Sparkline
		spark := ""
		if state := a.session.Get(net.BSSID); state != nil {
			spark = state.Sparkline()
		}
		a.table.SetCell(row, 2, tview.NewTableCell(spark).
			SetTextColor(tcell.GetColor(colorCyan)).
			SetBackgroundColor(rowBg))

		// Col 3: SSID (with NEW badge if applicable)
		ssidText := net.SSID
		ssidColor := colorCyan
		if net.SSID == "<hidden>" {
			ssidColor = colorDim
		}
		if isNew {
			ssidText = fmt.Sprintf("[%s]NEW[-] %s", colorHotPink, net.SSID)
			a.table.SetCell(row, 3, tview.NewTableCell(ssidText).
				SetTextColor(tcell.GetColor(ssidColor)).
				SetExpansion(1).
				SetBackgroundColor(rowBg))
		} else {
			a.table.SetCell(row, 3, tview.NewTableCell(ssidText).
				SetTextColor(tcell.GetColor(ssidColor)).
				SetExpansion(1).
				SetBackgroundColor(rowBg))
		}

		// Col 4: BSSID
		a.table.SetCell(row, 4, tview.NewTableCell(net.BSSID).
			SetTextColor(tcell.GetColor(colorMuted)).
			SetBackgroundColor(rowBg))

		// Col 5: Vendor
		vendor := scanner.LookupVendor(net.BSSID)
		vendorColor := colorMuted
		if vendor != "Unknown" && vendor != "Local" {
			vendorColor = colorGreen
		}
		a.table.SetCell(row, 5, tview.NewTableCell(vendor).
			SetTextColor(tcell.GetColor(vendorColor)).
			SetBackgroundColor(rowBg))

		// Col 6: Channel
		a.table.SetCell(row, 6, tview.NewTableCell(fmt.Sprintf("%d", net.Channel)).
			SetTextColor(tcell.GetColor(colorYellow)).
			SetAlign(tview.AlignRight).
			SetBackgroundColor(rowBg))

		// Col 7: Frequency
		a.table.SetCell(row, 7, tview.NewTableCell(fmt.Sprintf("%d", net.Frequency)).
			SetTextColor(tcell.GetColor(colorMuted)).
			SetAlign(tview.AlignRight).
			SetBackgroundColor(rowBg))

		// Col 8: Band
		band, bandColor := bandInfo(net.Frequency)
		a.table.SetCell(row, 8, tview.NewTableCell(band).
			SetTextColor(tcell.GetColor(bandColor)).
			SetAlign(tview.AlignCenter).
			SetBackgroundColor(rowBg))

		// Col 9: Security
		a.table.SetCell(row, 9, tview.NewTableCell(net.Security).
			SetTextColor(tcell.GetColor(securityColor(net.Security))).
			SetBackgroundColor(rowBg))
	}
}

// ── Detail Panel ────────────────────────────────────────────────────────────

func (a *App) buildDetail() {
	a.detail = tview.NewTextView().
		SetDynamicColors(true).
		SetWordWrap(true)

	a.detail.
		SetBorder(true).
		SetBorderColor(tcell.GetColor(colorCyan)).
		SetTitle(fmt.Sprintf(" [%s]◈[-] [%s]NETWORK DETAIL[-] [%s]◈[-] ",
			colorHotPink, colorCyan, colorHotPink)).
		SetTitleAlign(tview.AlignCenter).
		SetBorderPadding(1, 1, 2, 2)
}

func (a *App) buildDetailModal() *tview.Flex {
	// Center the detail panel with surrounding padding
	modal := tview.NewFlex().
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(nil, 0, 1, false).
			AddItem(a.detail, 20, 0, true).
			AddItem(nil, 0, 1, false), 70, 0, true).
		AddItem(nil, 0, 1, false)
	return modal
}

func (a *App) showDetail() {
	row, _ := a.table.GetSelection()
	if row < 1 || row > len(a.networks) {
		return
	}
	net := a.networks[row-1]

	vendor := scanner.LookupVendor(net.BSSID)
	band, _ := bandInfo(net.Frequency)

	// Build detail content
	var b strings.Builder
	writeLine := func(label, value, color string) {
		b.WriteString(fmt.Sprintf("  [%s]%-14s[-]  [%s]%s[-]\n", colorDim, label, color, value))
	}

	b.WriteString("\n")
	writeLine("SSID", net.SSID, colorCyan)
	writeLine("BSSID", net.BSSID, colorMuted)
	writeLine("VENDOR", vendor, colorGreen)

	// Signal with min/max from session
	sigStr := fmt.Sprintf("%d dBm", net.Signal)
	if state := a.session.Get(net.BSSID); state != nil {
		sigStr = fmt.Sprintf("%d dBm  (min %d / max %d)", net.Signal, state.MinSignal, state.MaxSignal)
	}
	_, barColor := signalBars(net.Signal)
	writeLine("SIGNAL", sigStr, barColor)

	// Sparkline
	if state := a.session.Get(net.BSSID); state != nil {
		spark := state.Sparkline()
		if spark != "" {
			writeLine("HISTORY", spark, colorCyan)
		}
	}

	writeLine("CHANNEL", fmt.Sprintf("%d", net.Channel), colorYellow)
	writeLine("FREQUENCY", fmt.Sprintf("%d MHz", net.Frequency), colorMuted)
	writeLine("BAND", band, colorCyan)
	writeLine("SECURITY", net.Security, securityColor(net.Security))

	// First/Last seen from session
	if state := a.session.Get(net.BSSID); state != nil {
		writeLine("FIRST SEEN", state.FirstSeen.Format("15:04:05"), colorMuted)
		writeLine("LAST SEEN", state.LastSeen.Format("15:04:05"), colorMuted)
	}

	b.WriteString(fmt.Sprintf("\n  [%s]Press Esc or Enter to close[-]", colorDim))

	a.detail.SetText(b.String())
	a.detailShown = true
	a.pages.ShowPage("detail")
	a.app.SetFocus(a.detail)
}

func (a *App) hideDetail() {
	a.detailShown = false
	a.pages.HidePage("detail")
	a.app.SetFocus(a.table)
}

// ── Footer ──────────────────────────────────────────────────────────────────

func (a *App) buildFooter() {
	a.footer = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignCenter)

	a.setDefaultFooter()
}

func (a *App) setDefaultFooter() {
	a.footer.SetText(fmt.Sprintf(
		" [%s][Q][-][%s]uit  [%s][R][-][%s]escan  [%s][S][-][%s]ort  [%s][Enter][-][%s] Detail  [%s][↑↓][-][%s] Navigate[-]  [%s]│[-]  [%s]Auto-refresh: 10s[-]",
		colorCyan, colorMuted,
		colorCyan, colorMuted,
		colorCyan, colorMuted,
		colorCyan, colorMuted,
		colorCyan, colorMuted,
		colorDim, colorDim,
	))
}

func (a *App) showNewNetworkAlert(count int) {
	label := "network"
	if count > 1 {
		label = "networks"
	}
	a.footer.SetText(fmt.Sprintf(
		" [%s]⚡ %d new %s discovered![-]",
		colorHotPink, count, label,
	))

	// Restore default footer after 5 seconds
	go func() {
		time.Sleep(5 * time.Second)
		a.app.QueueUpdateDraw(func() {
			a.setDefaultFooter()
		})
	}()
}

// ── Scanning ────────────────────────────────────────────────────────────────

func (a *App) doScan() {
	a.app.QueueUpdateDraw(func() {
		a.scanning = true
		a.updateHeader()
	})

	networks, err := a.scanner.Scan()

	a.app.QueueUpdateDraw(func() {
		a.scanning = false
		if err != nil {
			a.footer.SetText(fmt.Sprintf(" [%s]✗ Scan error: %v[-]", colorRed, err))
			a.updateHeader()
			return
		}
		a.networks = networks

		// Update session state and detect new networks
		newBSSIDs := a.session.Update(networks)
		now := time.Now()

		// Add newly discovered BSSIDs
		for _, bssid := range newBSSIDs {
			a.newBSSIDs[bssid] = now
		}

		// Clean expired entries
		for bssid, t := range a.newBSSIDs {
			if now.Sub(t) >= newBadgeTTL {
				delete(a.newBSSIDs, bssid)
			}
		}

		a.updateHeader()
		a.updateTable()

		// Show alert if new networks found (skip first scan)
		if len(newBSSIDs) > 0 && a.session.Count() > len(newBSSIDs) {
			a.showNewNetworkAlert(len(newBSSIDs))
		}
	})
}

func (a *App) autoRefresh() {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()

	for range ticker.C {
		a.doScan()
	}
}

// ── Sorting ─────────────────────────────────────────────────────────────────

func (a *App) cycleSortOrder() {
	switch a.sortBy {
	case "signal":
		a.sortBy = "ssid"
		sort.Slice(a.networks, func(i, j int) bool {
			return strings.ToLower(a.networks[i].SSID) < strings.ToLower(a.networks[j].SSID)
		})
	case "ssid":
		a.sortBy = "channel"
		sort.Slice(a.networks, func(i, j int) bool {
			return a.networks[i].Channel < a.networks[j].Channel
		})
	case "channel":
		a.sortBy = "security"
		sort.Slice(a.networks, func(i, j int) bool {
			return a.networks[i].Security < a.networks[j].Security
		})
	default:
		a.sortBy = "signal"
		sort.Slice(a.networks, func(i, j int) bool {
			return a.networks[i].Signal > a.networks[j].Signal
		})
	}

	a.updateHeader()
	a.updateTable()
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// signalBars maps dBm to a bar count (0–10) and a color.
func signalBars(signal int) (int, string) {
	switch {
	case signal >= -30:
		return 10, colorGreen
	case signal >= -40:
		return 9, colorGreen
	case signal >= -50:
		return 8, colorGreen
	case signal >= -55:
		return 7, colorCyan
	case signal >= -60:
		return 6, colorCyan
	case signal >= -67:
		return 5, colorYellow
	case signal >= -70:
		return 4, colorYellow
	case signal >= -75:
		return 3, colorOrange
	case signal >= -80:
		return 2, colorOrange
	case signal >= -90:
		return 1, colorRed
	default:
		return 0, colorRed
	}
}

func bandInfo(freq int) (string, string) {
	switch {
	case freq >= 5955:
		return "6G", colorMagenta
	case freq >= 5000:
		return "5G", colorCyan
	default:
		return "2.4G", colorGreen
	}
}

func securityColor(sec string) string {
	switch sec {
	case "OPEN":
		return colorRed
	case "WEP":
		return colorOrange
	case "WPA":
		return colorOrange
	case "WPA3":
		return colorCyan
	default:
		return colorGreen
	}
}
