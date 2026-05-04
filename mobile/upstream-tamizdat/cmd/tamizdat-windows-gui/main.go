// Native Win32 GUI for tamizdat client. Uses raw user32/gdi32 syscalls via
// golang.org/x/sys/windows — no walk, no CGO, no Common-Controls dependency.
//
//go:build windows

package main

import (
	"net"
	"runtime"
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var defaultBypassHosts = []string{
	// Public DNS resolvers — must bypass TUN or all UDP DNS dies.
	// (Samizdat v1 doesn't transit UDP; system DNS uses UDP/53.)
	"1.1.1.1",
	"1.0.0.1",
	"8.8.8.8",
	"8.8.4.4",
	"9.9.9.9",
	"77.88.8.8",
	"77.88.8.1",
	// Local resolvers commonly seen on home routers (static IPs by IP literal).
	"192.168.1.1",
	"192.168.2.1",
	"192.168.0.1",
	"192.168.123.1",
	// AI provider APIs — must remain reachable when tunnel is busy / blocked.
	"api.anthropic.com",
	"console.anthropic.com",
	"claude.ai",
	"api.openai.com",
	"chat.openai.com",
	"chatgpt.com",
	"cdn.openai.com",
	"oaistatic.com",
}

// --- syscall bindings ---

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW = user32.NewProc("RegisterClassExW")
	procCreateWindowExW  = user32.NewProc("CreateWindowExW")
	procDefWindowProcW   = user32.NewProc("DefWindowProcW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procUpdateWindow     = user32.NewProc("UpdateWindow")
	procGetMessageW      = user32.NewProc("GetMessageW")
	procTranslateMessage = user32.NewProc("TranslateMessage")
	procDispatchMessageW = user32.NewProc("DispatchMessageW")
	procPostQuitMessage  = user32.NewProc("PostQuitMessage")
	procSendMessageW     = user32.NewProc("SendMessageW")
	procSetWindowTextW   = user32.NewProc("SetWindowTextW")
	procGetWindowTextW   = user32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW = user32.NewProc("GetWindowTextLengthW")
	procLoadCursorW      = user32.NewProc("LoadCursorW")
	procEnableWindow     = user32.NewProc("EnableWindow")
	procPostMessageW     = user32.NewProc("PostMessageW")
	procMoveWindow       = user32.NewProc("MoveWindow")
	procGetClientRect    = user32.NewProc("GetClientRect")
	procMessageBoxW      = user32.NewProc("MessageBoxW")
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")

	procCreateFontIndirectW = gdi32.NewProc("CreateFontIndirectW")
	procDeleteObject        = gdi32.NewProc("DeleteObject")
)

// Constants
const (
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_VISIBLE          = 0x10000000
	WS_CHILD            = 0x40000000
	WS_BORDER           = 0x00800000
	WS_VSCROLL          = 0x00200000
	WS_HSCROLL          = 0x00100000
	WS_TABSTOP          = 0x00010000

	ES_LEFT       = 0x0000
	ES_MULTILINE  = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_AUTOHSCROLL = 0x0080
	ES_READONLY   = 0x0800
	ES_WANTRETURN = 0x1000

	BS_PUSHBUTTON     = 0x00000000
	BS_DEFPUSHBUTTON  = 0x00000001
	BS_AUTORADIOBUTTON = 0x00000009
	BM_GETCHECK = 0x00F0
	BM_SETCHECK = 0x00F1
	BST_CHECKED = 1
	BST_UNCHECKED = 0

	SS_LEFT  = 0x00000000
	SS_RIGHT = 0x00000002

	WM_DESTROY = 0x0002
	WM_COMMAND = 0x0111
	WM_SETFONT = 0x0030
	WM_SIZE    = 0x0005
	WM_APP     = 0x8000
	WM_USER    = 0x0400

	BN_CLICKED = 0
	EN_CHANGE  = 0x0300

	SW_SHOW = 5

	IDC_ARROW = 32512

	COLOR_BTNFACE = 15

	SPI_GETNONCLIENTMETRICS = 41

	EM_SETSEL          = 0x00B1
	EM_REPLACESEL      = 0x00C2
	EM_SCROLLCARET     = 0x00B7
	EM_LINESCROLL      = 0x00B6
	EM_GETLINECOUNT    = 0x00BA

	WMU_LOG    = WM_APP + 1 // custom: append a log preview; lParam = *[]uint16
	WMU_STATUS = WM_APP + 2 // custom: update status; wParam = state code (0 disconnected, 1 connecting, 2 connected, 3 error)
	WMU_DONE   = WM_APP + 3 // custom: child finished; reset UI to disconnected
	WMU_STATS  = WM_APP + 4 // custom: update stats label; lParam = *[]uint16
)

// Control IDs
const (
	IDC_URI    uintptr = 100
	IDC_BYPASS uintptr = 101
	IDC_BTN    uintptr = 102
	IDC_STATUS uintptr = 103
	IDC_LOG    uintptr = 104
	IDC_OPENLOG uintptr = 105
	IDC_STATS  uintptr = 106
	IDC_CLEANUP uintptr = 107
	IDC_VAR_V1  uintptr = 110
	IDC_VAR_V2  uintptr = 111
	IDC_VAR_V3  uintptr = 112
	IDC_ADDROUTES uintptr = 113
	IDC_LBL_VAR uintptr = 204
	IDC_LBL_URI    uintptr = 200
	IDC_LBL_BYPASS uintptr = 201
	IDC_LBL_LOG    uintptr = 202
	IDC_LBL_STATS  uintptr = 203
)

type wndclassex struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type msgStruct struct {
	Hwnd     windows.Handle
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       struct{ X, Y int32 }
	LPrivate uint32
}

type rect struct{ Left, Top, Right, Bottom int32 }

type logfontw struct {
	Height         int32
	Width          int32
	Escapement     int32
	Orientation    int32
	Weight         int32
	Italic         byte
	Underline      byte
	StrikeOut      byte
	CharSet        byte
	OutPrecision   byte
	ClipPrecision  byte
	Quality        byte
	PitchAndFamily byte
	FaceName       [32]uint16
}

type nonclientmetrics struct {
	Size           uint32
	BorderWidth    int32
	ScrollWidth    int32
	ScrollHeight   int32
	CaptionWidth   int32
	CaptionHeight  int32
	CaptionFont    logfontw
	SmCaptionWidth int32
	SmCaptionHeight int32
	SmCaptionFont  logfontw
	MenuWidth      int32
	MenuHeight     int32
	MenuFont       logfontw
	StatusFont     logfontw
	MessageFont    logfontw
	PaddedBorderWidth int32
}

// --- runtime state ---

type appCtx struct {
	// Stats — atomic counters updated by pumpOutput.
	tcpFlows  uint64
	udpDrops  uint64
	logLines  uint64

	hwnd         windows.Handle
	hwndURI      windows.Handle
	hwndBypass   windows.Handle
	hwndBtn      windows.Handle
	hwndStatus   windows.Handle
	hwndLog      windows.Handle
	hwndOpenLog  windows.Handle
	hwndCleanup  windows.Handle
	hwndVarV1    windows.Handle
	hwndVarV2    windows.Handle
	hwndVarV3    windows.Handle
	hwndAddRoutes windows.Handle
	hwndLblVar   windows.Handle
	hwndStats    windows.Handle
	hwndLblURI   windows.Handle
	hwndLblByp   windows.Handle
	hwndLblLog   windows.Handle
	hwndLblStats windows.Handle
	monoFont     windows.Handle

	tunExe   string
	logPath  string

	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool

	pendingLogs sync.Mutex
	pendingPin  []*[]uint16 // keep UTF-16 strings alive until processed
}

var app *appCtx

func main() {
	// CRITICAL: Win32 message queue is per-thread. CreateWindowEx + GetMessage
	// + DispatchMessage must all run on the same OS thread. Without LockOSThread,
	// the Go scheduler may move this goroutine between OS threads — making
	// GetMessageW pull from a queue that no one is posting to, which manifests
	// as random "Не отвечает" hangs (sometimes immediately on launch).
	runtime.LockOSThread()

	logPath := filepath.Join(os.TempDir(), "tamizdat-gui.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		// Wrap *os.File so each Write is followed by Sync — important since
		// the GUI process can be hard-killed via taskkill, losing buffered
		// log entries that haven't reached disk.
		log.SetOutput(syncWriter{f: f})
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		log.Printf("=== boot pid=%d ===", os.Getpid())
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC: %v", r)
			msgBox(fmt.Sprintf("Tamizdat panic:\n%v\n\nЛог: %s", r, logPath))
			os.Exit(1)
		}
	}()

	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("locate self: %v", err)
	}
	exeDir := filepath.Dir(exe)
	// Search candidates in order — a_ prefix preferred so the process sorts
	// to top of Task Manager next to a_Tamizdat.exe.
	candidates := []string{
		"a_tamizdat-tun-windows.exe",
		"tamizdat-tun-windows.exe",
		"tamizdat-tun-windows-bypass.exe",
	}
	var tunExe string
	for _, name := range candidates {
		full := filepath.Join(exeDir, name)
		if _, err := os.Stat(full); err == nil {
			tunExe = full
			break
		}
	}
	if tunExe == "" {
		msgBox(fmt.Sprintf("Не найден ни один из tun-windows бинарей рядом с .exe:\n%s\n\nДолжен быть один из:\n  a_tamizdat-tun-windows.exe\n  tamizdat-tun-windows.exe", exeDir))
		os.Exit(1)
	}
	log.Printf("tunExe=%s", tunExe)

	app = &appCtx{tunExe: tunExe, logPath: logPath}

	if err := runWindow(); err != nil {
		log.Printf("runWindow: %v", err)
		msgBox(fmt.Sprintf("Не удалось создать окно: %v\n\nЛог: %s", err, logPath))
		os.Exit(1)
	}
	stopChild()
	log.Printf("=== exit ===")
}

func runWindow() error {
	procGetModuleHandleW := kernel32.NewProc("GetModuleHandleW")
	hInstanceRaw, _, _ := procGetModuleHandleW.Call(0)
	hInstance := windows.Handle(hInstanceRaw)

	className, _ := syscall.UTF16PtrFromString("TamizdatMainWnd")
	title, _ := syscall.UTF16PtrFromString("Tamizdat — Windows")

	hCursor, _, _ := procLoadCursorW.Call(0, uintptr(IDC_ARROW))

	wc := wndclassex{
		Size:       uint32(unsafe.Sizeof(wndclassex{})),
		Style:      0x0003, // CS_HREDRAW | CS_VREDRAW
		WndProc:    syscall.NewCallback(wndProc),
		Instance:   hInstance,
		Cursor:     windows.Handle(hCursor),
		Background: windows.Handle(COLOR_BTNFACE + 1),
		ClassName:  className,
	}
	r1, _, e := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if r1 == 0 {
		return fmt.Errorf("RegisterClassEx: %v", e)
	}
	log.Printf("class registered")

	hwndRaw, _, e := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(title)),
		WS_OVERLAPPEDWINDOW|WS_VISIBLE,
		100, 100, 820, 640,
		0, 0, uintptr(hInstance), 0,
	)
	if hwndRaw == 0 {
		return fmt.Errorf("CreateWindowEx main: %v", e)
	}
	app.hwnd = windows.Handle(hwndRaw)
	log.Printf("main window hwnd=%v", app.hwnd)

	app.monoFont = createMonoFont(9)

	// Build child controls.
	if err := createChildren(hInstance); err != nil {
		return err
	}
	// Apply layout.
	layout()

	// Initial state: load saved URI, set bypass list.
	if savedURI := loadSavedURI(); savedURI != "" {
		setText(app.hwndURI, savedURI)
	}
	setText(app.hwndBypass, strings.Join(defaultBypassHosts, "\r\n"))
	setText(app.hwndStatus, "Отключено")
	appendLog(fmt.Sprintf("[gui] tun engine: %s", app.tunExe))
	appendLog(fmt.Sprintf("[gui] лог в файле: %s", app.logPath))

	procShowWindow.Call(uintptr(app.hwnd), SW_SHOW)
	procUpdateWindow.Call(uintptr(app.hwnd))
	log.Printf("window shown, entering message loop")

	var m msgStruct
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	log.Printf("message loop ended")
	return nil
}

func createChildren(hInstance windows.Handle) error {
	editClass, _ := syscall.UTF16PtrFromString("EDIT")
	btnClass, _ := syscall.UTF16PtrFromString("BUTTON")
	staticClass, _ := syscall.UTF16PtrFromString("STATIC")

	mk := func(class *uint16, text string, style uint32, exStyle uint32, id uintptr) (windows.Handle, error) {
		t, _ := syscall.UTF16PtrFromString(text)
		h, _, e := procCreateWindowExW.Call(
			uintptr(exStyle),
			uintptr(unsafe.Pointer(class)),
			uintptr(unsafe.Pointer(t)),
			uintptr(style),
			0, 0, 100, 25, // placeholder size; layout() resizes
			uintptr(app.hwnd),
			id,
			uintptr(hInstance),
			0,
		)
		if h == 0 {
			return 0, fmt.Errorf("CreateWindowEx %s: %v", text, e)
		}
		return windows.Handle(h), nil
	}

	var err error
	if app.hwndLblURI, err = mk(staticClass, "URI подключения:", WS_VISIBLE|WS_CHILD|SS_LEFT, 0, IDC_LBL_URI); err != nil {
		return err
	}
	if app.hwndURI, err = mk(editClass, "", WS_VISIBLE|WS_CHILD|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL, 0x00000200, IDC_URI); err != nil {
		return err
	}
	if app.hwndLblByp, err = mk(staticClass, "Bypass hosts (по одному на строке):", WS_VISIBLE|WS_CHILD|SS_LEFT, 0, IDC_LBL_BYPASS); err != nil {
		return err
	}
	if app.hwndBypass, err = mk(editClass, "", WS_VISIBLE|WS_CHILD|WS_BORDER|WS_TABSTOP|WS_VSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_WANTRETURN, 0x00000200, IDC_BYPASS); err != nil {
		return err
	}
	if app.hwndLblVar, err = mk(staticClass, "Pool variant:", WS_VISIBLE|WS_CHILD|SS_LEFT, 0, IDC_LBL_VAR); err != nil {
		return err
	}
	// First radio button gets WS_GROUP, others share that group.
	if app.hwndVarV1, err = mk(btnClass, "V1 STRICT (1 TCP forever)", WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_AUTORADIOBUTTON|0x00020000 /*WS_GROUP*/, 0, IDC_VAR_V1); err != nil {
		return err
	}
	if app.hwndVarV2, err = mk(btnClass, "V2 Two-transport on-demand (1+2)", WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_AUTORADIOBUTTON, 0, IDC_VAR_V2); err != nil {
		return err
	}
	if app.hwndVarV3, err = mk(btnClass, "V3 Opus pool sizing (2-4)", WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_AUTORADIOBUTTON, 0, IDC_VAR_V3); err != nil {
		return err
	}
	// Default selection: V1
	procSendMessageW.Call(uintptr(app.hwndVarV1), BM_SETCHECK, BST_CHECKED, 0)

	if app.hwndAddRoutes, err = mk(btnClass, "Добавить маршруты (default → TUN)", WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_PUSHBUTTON, 0, IDC_ADDROUTES); err != nil {
		return err
	}

	if app.hwndBtn, err = mk(btnClass, "Подключить", WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_DEFPUSHBUTTON, 0, IDC_BTN); err != nil {
		return err
	}
	if app.hwndStatus, err = mk(staticClass, "Отключено", WS_VISIBLE|WS_CHILD|SS_LEFT, 0, IDC_STATUS); err != nil {
		return err
	}
	if app.hwndLblStats, err = mk(staticClass, "Статистика:", WS_VISIBLE|WS_CHILD|SS_LEFT, 0, IDC_LBL_STATS); err != nil {
		return err
	}
	if app.hwndStats, err = mk(staticClass, "TCP flows: 0   UDP drops: 0   log lines: 0", WS_VISIBLE|WS_CHILD|SS_LEFT, 0, IDC_STATS); err != nil {
		return err
	}
	if app.hwndOpenLog, err = mk(btnClass, "Открыть полный лог в Блокноте", WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_PUSHBUTTON, 0, IDC_OPENLOG); err != nil {
		return err
	}
	if app.hwndCleanup, err = mk(btnClass, "Снести все маршруты Tamizdat", WS_VISIBLE|WS_CHILD|WS_TABSTOP|BS_PUSHBUTTON, 0, IDC_CLEANUP); err != nil {
		return err
	}
	if app.hwndLblLog, err = mk(staticClass, "Последние события (превью, обновляется раз в 2 сек):", WS_VISIBLE|WS_CHILD|SS_LEFT, 0, IDC_LBL_LOG); err != nil {
		return err
	}
	if app.hwndLog, err = mk(editClass, "", WS_VISIBLE|WS_CHILD|WS_BORDER|ES_MULTILINE|ES_READONLY, 0x00000200, IDC_LOG); err != nil {
		return err
	}

	// Apply mono font to URI / bypass / log.
	for _, h := range []windows.Handle{app.hwndURI, app.hwndBypass, app.hwndLog} {
		procSendMessageW.Call(uintptr(h), WM_SETFONT, uintptr(app.monoFont), 1)
	}
	return nil
}

func layout() {
	var rc rect
	procGetClientRect.Call(uintptr(app.hwnd), uintptr(unsafe.Pointer(&rc)))
	w := int(rc.Right - rc.Left)
	h := int(rc.Bottom - rc.Top)
	margin := 12
	rowH := 24
	editH := 24
	bypassH := 80
	logTop := margin*5 + rowH + editH + rowH + bypassH + rowH + 36
	_ = h - logTop - margin // logH unused after v5 layout

	move := func(hw windows.Handle, x, y, ww, hh int) {
		procMoveWindow.Call(uintptr(hw), uintptr(int32(x)), uintptr(int32(y)),
			uintptr(int32(ww)), uintptr(int32(hh)), 1)
	}

	y := margin
	move(app.hwndLblURI, margin, y, w-2*margin, rowH)
	y += rowH
	move(app.hwndURI, margin, y, w-2*margin, editH)
	y += editH + margin
	move(app.hwndLblByp, margin, y, w-2*margin, rowH)
	y += rowH
	move(app.hwndBypass, margin, y, w-2*margin, bypassH)
	y += bypassH + margin
	// Variant row: label + 3 radios
	move(app.hwndLblVar, margin, y+6, 100, rowH)
	move(app.hwndVarV1, margin+105, y+4, 220, 22)
	move(app.hwndVarV2, margin+105+225, y+4, 240, 22)
	move(app.hwndVarV3, margin+105+225+245, y+4, 200, 22)
	y += 26
	// Add-routes button row
	move(app.hwndAddRoutes, margin, y, 320, 28)
	move(app.hwndCleanup, margin+330, y, 280, 28)
	y += 28 + margin
	move(app.hwndBtn, margin, y, 160, 32)
	move(app.hwndStatus, margin+170, y+6, w-margin*2-170, rowH)
	y += 32 + margin
	move(app.hwndLblStats, margin, y, w-2*margin, rowH)
	y += rowH
	move(app.hwndStats, margin, y, w-2*margin-280, rowH)
	move(app.hwndOpenLog, w-margin-260, y-2, 260, 28)
	y += rowH + margin
	move(app.hwndLblLog, margin, y, w-2*margin, rowH)
	y += rowH
	previewH := 90
	if h-y-margin > previewH {
		previewH = h - y - margin
		if previewH > 200 {
			previewH = 200 // cap preview height — UI stays light
		}
	}
	move(app.hwndLog, margin, y, w-2*margin, previewH)
}

func wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) (result uintptr) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in wndProc msg=0x%x wp=%v lp=%v: %v", msg, wParam, lParam, r)
			// Fall through to DefWindowProc with default result.
			r2, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
			result = r2
		}
	}()
	switch msg {
	case WM_SIZE:
		layout()
		return 0
	case WM_COMMAND:
		notif := uint32(wParam>>16) & 0xFFFF
		ctrlID := uint32(wParam & 0xFFFF)
		if ctrlID == uint32(IDC_BTN) && notif == BN_CLICKED {
			onConnectClicked()
			return 0
		}
		if ctrlID == uint32(IDC_OPENLOG) && notif == BN_CLICKED {
			openLogInNotepad()
			return 0
		}
		if ctrlID == uint32(IDC_CLEANUP) && notif == BN_CLICKED {
			go runRouteCleanup()
			return 0
		}
		if ctrlID == uint32(IDC_ADDROUTES) && notif == BN_CLICKED {
			go runAddRoutes()
			return 0
		}
	case WMU_LOG:
		ptr := (*[]uint16)(unsafe.Pointer(lParam))
		if ptr != nil && len(*ptr) > 0 {
			text := windows.UTF16ToString(*ptr)
			appendLogToControl(text)
			releasePin(ptr)
		}
		return 0
	case WMU_STATS:
		ptr := (*[]uint16)(unsafe.Pointer(lParam))
		if ptr != nil && len(*ptr) > 0 {
			text := windows.UTF16ToString(*ptr)
			setText(app.hwndStats, text)
			releasePin(ptr)
		}
		return 0
	case WMU_STATUS:
		switch wParam {
		case 0:
			setText(app.hwndStatus, "Отключено")
			setText(app.hwndBtn, "Подключить")
		case 1:
			setText(app.hwndStatus, "Подключение...")
			setText(app.hwndBtn, "Отключить")
		case 2:
			setText(app.hwndStatus, "Подключено (TUN активен)")
			setText(app.hwndBtn, "Отключить")
		case 3:
			setText(app.hwndStatus, "Ошибка — см. лог")
			setText(app.hwndBtn, "Подключить")
		}
		return 0
	case WMU_DONE:
		app.mu.Lock()
		app.running = false
		app.cmd = nil
		app.mu.Unlock()
		setText(app.hwndStatus, "Отключено")
		setText(app.hwndBtn, "Подключить")
		return 0
	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

// --- helpers ---

func setText(hwnd windows.Handle, s string) {
	p, _ := syscall.UTF16PtrFromString(s)
	procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(p)))
}

func getText(hwnd windows.Handle) string {
	n, _, _ := procGetWindowTextLengthW.Call(uintptr(hwnd))
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), n+1)
	return windows.UTF16ToString(buf)
}

var (
	logBufMu     sync.Mutex
	logRing      []string
	logRingMax   = 5 // last 5 lines preview only — entire control is tiny
	logDirty     bool
	logTickerOn  bool
)

func appendLog(line string) {
	ts := time.Now().Format("15:04:05")
	full := ts + "  " + line

	// Update atomic stats counters based on log content.
	if app != nil {
		atomic.AddUint64(&app.logLines, 1)
		if strings.Contains(line, "[TCP]") && strings.Contains(line, "via samizdat") {
			atomic.AddUint64(&app.tcpFlows, 1)
		} else if strings.Contains(line, "[UDP drop]") {
			atomic.AddUint64(&app.udpDrops, 1)
		}
	}

	logBufMu.Lock()
	logRing = append(logRing, full)
	if len(logRing) > logRingMax {
		logRing = logRing[len(logRing)-logRingMax:]
	}
	logDirty = true
	if !logTickerOn {
		logTickerOn = true
		go logFlushLoop()
	}
	logBufMu.Unlock()
	log.Printf("LOG: %s", line)
}

// logFlushLoop updates two TINY controls every 2 seconds:
//   - hwndLog: 5-line preview (~700 chars max)
//   - hwndStats: one-line stats summary (~80 chars)
// Each SetWindowText handles <1KB. UI thread cost negligible.
func logFlushLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for range t.C {
		if app.hwnd == 0 {
			continue
		}
		logBufMu.Lock()
		preview := strings.Join(logRing, "\r\n")
		logBufMu.Unlock()
		stats := fmt.Sprintf("TCP flows: %d   UDP drops: %d   log lines: %d",
			atomic.LoadUint64(&app.tcpFlows),
			atomic.LoadUint64(&app.udpDrops),
			atomic.LoadUint64(&app.logLines))

		// Pin both UTF-16 buffers until the UI thread consumes WMU_LOG.
		utfPrev := utf16Of(preview)
		utfStat := utf16Of(stats)
		app.pendingLogs.Lock()
		app.pendingPin = append(app.pendingPin, &utfPrev, &utfStat)
		app.pendingLogs.Unlock()
		procPostMessageW.Call(uintptr(app.hwnd), WMU_LOG, 0, uintptr(unsafe.Pointer(&utfPrev)))
		procPostMessageW.Call(uintptr(app.hwnd), WMU_STATS, 0, uintptr(unsafe.Pointer(&utfStat)))
	}
}

func utf16Of(s string) []uint16 {
	r, _ := syscall.UTF16FromString(s)
	return r
}

func appendLogToControl(text string) {
	// Whole-content replace (one repaint, predictable cost).
	p, _ := syscall.UTF16PtrFromString(text)
	procSetWindowTextW.Call(uintptr(app.hwndLog), uintptr(unsafe.Pointer(p)))
	// Then move caret to end + scroll into view.
	procSendMessageW.Call(uintptr(app.hwndLog), EM_SETSEL, ^uintptr(0), ^uintptr(0))
	procSendMessageW.Call(uintptr(app.hwndLog), EM_SCROLLCARET, 0, 0)
}

func setStatusCode(code int) {
	procPostMessageW.Call(uintptr(app.hwnd), WMU_STATUS, uintptr(code), 0)
}

func onConnectClicked() {
	app.mu.Lock()
	running := app.running
	app.mu.Unlock()
	if running {
		go stopChild()
	} else {
		go startChild()
	}
}

func startChild() {
	atomic.StoreUint64(&app.tcpFlows, 0)
	atomic.StoreUint64(&app.udpDrops, 0)
	atomic.StoreUint64(&app.logLines, 0)
	uri := strings.TrimSpace(getText(app.hwndURI))
	bypassRaw := getText(app.hwndBypass)
	variant := readSelectedVariant()
	appendLog("[gui] pool-variant: " + variant)
	if uri == "" {
		appendLog("[gui] ошибка: введите URI")
		setStatusCode(3)
		return
	}
	var hosts []string
	for _, line := range strings.FieldsFunc(bypassRaw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	}) {
		line = strings.TrimSpace(line)
		if line != "" {
			hosts = append(hosts, line)
		}
	}
	if len(hosts) == 0 {
		hosts = defaultBypassHosts
	}
	bypassArg := strings.Join(hosts, ",")

	args := []string{
		"--config", uri,
		"--auto-route=false", // operator manages all routes manually
		"--pool-variant=" + variant,
		"--debug",
	}
	// V1 radio = strict-single-h2 mode (1 TCP/443 forever, even with realtime).
	if variant == "v1" {
		args = append(args, "--strict-single-h2")
	}
	_ = bypassArg // engine touches no routes — bypass list is informational only

	saveURI(uri)
	setStatusCode(1)
	appendLog("[gui] запуск " + app.tunExe)
	appendLog("[gui] bypass: " + bypassArg)

	cmd := exec.Command(app.tunExe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		appendLog("[gui] stdout pipe: " + err.Error())
		setStatusCode(3)
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		appendLog("[gui] stderr pipe: " + err.Error())
		setStatusCode(3)
		return
	}
	if err := cmd.Start(); err != nil {
		appendLog("[gui] запуск не удался: " + err.Error())
		setStatusCode(3)
		return
	}
	app.mu.Lock()
	app.cmd = cmd
	app.running = true
	app.mu.Unlock()
	appendLog(fmt.Sprintf("[gui] PID=%d", cmd.Process.Pid))
	setStatusCode(2)

	go pumpOutput("stdout", stdout)
	go pumpOutput("stderr", stderr)
	go func() {
		err := cmd.Wait()
		if err != nil {
			appendLog("[gui] процесс завершился с ошибкой: " + err.Error())
		} else {
			appendLog("[gui] процесс завершился штатно.")
		}
		procPostMessageW.Call(uintptr(app.hwnd), WMU_DONE, 0, 0)
	}()
}

func stopChild() {
	app.mu.Lock()
	cmd := app.cmd
	app.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	appendLog("[gui] остановка...")
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	app.mu.Lock()
	app.cmd = nil
	app.running = false
	app.mu.Unlock()
	appendLog("[gui] остановлено.")
	setStatusCode(0)
}

func pumpOutput(label string, r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		appendLog("[" + label + "] " + sc.Text())
	}
}

// Persist URI between launches.
func savedURIPath() string {
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		exe, _ := os.Executable()
		return filepath.Join(filepath.Dir(exe), "tamizdat-uri.txt")
	}
	d := filepath.Join(dir, "tamizdat")
	_ = os.MkdirAll(d, 0700)
	return filepath.Join(d, "uri.txt")
}

func loadSavedURI() string {
	b, err := os.ReadFile(savedURIPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveURI(s string) {
	_ = os.WriteFile(savedURIPath(), []byte(s), 0600)
}

func msgBox(text string) {
	t, _ := syscall.UTF16PtrFromString(text)
	caption, _ := syscall.UTF16PtrFromString("Tamizdat")
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(caption)), 0)
}

func createMonoFont(pointSize int) windows.Handle {
	face := "Consolas"
	lf := logfontw{
		Height: int32(-pointSize * 96 / 72), // approx; ignores actual DPI
		Weight: 400,
		CharSet: 1, // DEFAULT_CHARSET
	}
	for i, r := range face {
		if i >= 31 {
			break
		}
		lf.FaceName[i] = uint16(r)
	}
	r, _, _ := procCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	return windows.Handle(r)
}

// syncWriter wraps *os.File and calls Sync() after every Write so log entries
// survive a hard kill (taskkill /F).
type syncWriter struct{ f *os.File }

func (w syncWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	_ = w.f.Sync()
	return n, err
}

func releasePin(ptr *[]uint16) {
	app.pendingLogs.Lock()
	for i, p := range app.pendingPin {
		if p == ptr {
			app.pendingPin = append(app.pendingPin[:i], app.pendingPin[i+1:]...)
			break
		}
	}
	app.pendingLogs.Unlock()
}

func openLogInNotepad() {
	if app == nil || app.logPath == "" {
		return
	}
	cmd := exec.Command("notepad.exe", app.logPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false, CreationFlags: 0}
	_ = cmd.Start()
}

// runRouteCleanup hand-cleans every Tamizdat-touched route. Called by operator
// when something hung previously and the OS still has stale entries.
//
// Sweeps:
//   - default 0.0.0.0/0 via 10.255.0.1 (orphan TUN default)
//   - any /32 routes via 10.255.0.1 (orphan selective-routes)
//   - any /32 host-route to known server IPs (185.193.102.213, 38.135.53.241,
//     resolved odikee.dpdns.org, llm2.detectqq.dpdns.org) via the local LAN
//     gateway 192.168.1.1 (best effort — won't error if absent)
func runRouteCleanup() {
	appendLog("[gui] cleanup: scanning routing table...")
	// 1. Get full route table once.
	routePrint := exec.Command("route.exe", "PRINT", "-4")
	routePrint.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := routePrint.Output()
	if err != nil {
		appendLog("[gui] cleanup: route PRINT failed: " + err.Error())
		return
	}
	removed := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		dest, mask, gw := fields[0], fields[1], fields[2]
		// Match orphan TUN routes
		isTunDefault := dest == "0.0.0.0" && mask == "0.0.0.0" && gw == "10.255.0.1"
		isTunSlash32 := mask == "255.255.255.255" && gw == "10.255.0.1"
		// Match host-routes to known server IPs (operator's odikee + llm2)
		isServerPin := mask == "255.255.255.255" && (
			strings.HasPrefix(dest, "185.193.102.") ||
				strings.HasPrefix(dest, "38.135.53.") ||
				strings.HasPrefix(dest, "111.88.103."))
		if !isTunDefault && !isTunSlash32 && !isServerPin {
			continue
		}
		// Skip On-link entries (they belong to active interfaces, can't route DELETE them)
		if gw == "On-link" {
			continue
		}
		appendLog(fmt.Sprintf("[gui] cleanup: deleting %s mask %s via %s", dest, mask, gw))
		del := exec.Command("route.exe", "DELETE", dest, "MASK", mask, gw)
		del.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
		if delOut, delErr := del.CombinedOutput(); delErr != nil {
			appendLog(fmt.Sprintf("[gui] cleanup: DELETE %s failed: %v (%s)", dest, delErr, strings.TrimSpace(string(delOut))))
			continue
		}
		removed++
	}
	appendLog(fmt.Sprintf("[gui] cleanup: removed %d Tamizdat routes", removed))
}

func readSelectedVariant() string {
	check := func(h windows.Handle) bool {
		r, _, _ := procSendMessageW.Call(uintptr(h), BM_GETCHECK, 0, 0)
		return r == BST_CHECKED
	}
	if check(app.hwndVarV2) {
		return "v2"
	}
	if check(app.hwndVarV3) {
		return "v3"
	}
	return "v1" // default
}

// runAddRoutes installs the basic Tamizdat tunnel routing:
//   1. Assign 10.255.0.2/24 to Samizdat TUN
//   2. Pin host-route to server IP via the original physical/Hysteria gateway
//   3. Install default 0.0.0.0/0 via 10.255.0.1 (TUN gateway)
//
// Operator decision: server pin goes via current default-route gateway
// (192.168.1.1 = physical, or 192.168.123.1 if Hysteria is up). This way
// Hysteria continues to route Anthropic/OpenAI traffic that has its own
// /32 routes set by Hysteria itself.
func runAddRoutes() {
	appendLog("[gui] add-routes: starting...")

	// 1. Get TUN interface index.
	idxOut, idxErr := exec.Command("powershell.exe", "-NoProfile", "-Command",
		"(Get-NetIPInterface -InterfaceAlias 'Samizdat' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).ifIndex").CombinedOutput()
	if idxErr != nil {
		appendLog("[gui] add-routes: no Samizdat TUN found: " + idxErr.Error())
		return
	}
	tunIdx := strings.TrimSpace(string(idxOut))
	if tunIdx == "" {
		appendLog("[gui] add-routes: Samizdat TUN not up yet — start engine first")
		return
	}
	appendLog("[gui] add-routes: Samizdat ifIndex=" + tunIdx)

	// 2. Get current default gateway (physical or Hysteria — whichever owns 0.0.0.0/0 with lowest metric).
	gwOut, _ := exec.Command("powershell.exe", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1).NextHop").CombinedOutput()
	physGw := strings.TrimSpace(string(gwOut))
	if physGw == "" || physGw == "0.0.0.0" {
		appendLog("[gui] add-routes: no default gateway found, aborting")
		return
	}
	appendLog("[gui] add-routes: physical gateway=" + physGw)

	// 3. Resolve server IP from URI (re-parse the URI for host:port).
	uri := strings.TrimSpace(getText(app.hwndURI))
	serverIP := ""
	if i := strings.Index(uri, "@"); i > 0 {
		rest := uri[i+1:]
		if j := strings.Index(rest, ":"); j > 0 {
			host := rest[:j]
			ips, err := net.LookupHost(host)
			if err == nil && len(ips) > 0 {
				for _, ip := range ips {
					if v4 := net.ParseIP(ip); v4 != nil && v4.To4() != nil {
						serverIP = ip
						break
					}
				}
			}
		}
	}
	if serverIP == "" {
		appendLog("[gui] add-routes: couldn't resolve server IP from URI, skipping pin")
	} else {
		appendLog("[gui] add-routes: server IP=" + serverIP + " pin via " + physGw)
		out, err := runRouteCmd("ADD", serverIP, "255.255.255.255", physGw, "1", "")
		if err != nil {
			appendLog("[gui] add-routes: pin server failed: " + err.Error() + " (" + out + ")")
		} else {
			appendLog("[gui] add-routes: pinned " + serverIP + " -> " + physGw)
		}
	}

	// 4. Assign TUN IP via netsh (idempotent).
	out, err := exec.Command("netsh.exe", "interface", "ipv4", "set", "address",
		"name=Samizdat", "static", "10.255.0.2", "255.255.255.0").CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "already exists") {
		appendLog("[gui] add-routes: netsh set address failed: " + err.Error() + " (" + strings.TrimSpace(string(out)) + ")")
	} else {
		appendLog("[gui] add-routes: assigned 10.255.0.2/24 to Samizdat")
	}

	// 5. Install default via TUN.
	out2, err := runRouteCmd("ADD", "0.0.0.0", "0.0.0.0", "10.255.0.1", "1", tunIdx)
	if err != nil {
		appendLog("[gui] add-routes: default-via-TUN failed: " + err.Error() + " (" + out2 + ")")
		return
	}
	appendLog("[gui] add-routes: default 0.0.0.0/0 via 10.255.0.1 ifIndex=" + tunIdx + " METRIC 1")
	appendLog("[gui] add-routes: DONE — your traffic now goes through Tamizdat tunnel.")
}

func runRouteCmd(op, dest, mask, gw, metric, ifIdx string) (string, error) {
	args := []string{op, dest, "MASK", mask, gw, "METRIC", metric}
	if ifIdx != "" {
		args = append(args, "IF", ifIdx)
	}
	cmd := exec.Command("route.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

