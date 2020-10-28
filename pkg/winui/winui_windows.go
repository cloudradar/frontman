// +build windows

package winui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lxn/walk"
	decl "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/pkg/errors"
	"github.com/shirou/w32"
	log "github.com/sirupsen/logrus"

	"github.com/cloudradar-monitoring/frontman"
)

var (
	screenDPIX int
	screenDPIY int
)

func init() {
	// Retrieve screen DPI
	hDC := win.GetDC(0)
	defer win.ReleaseDC(0, hDC)
	screenDPIX = int(win.GetDeviceCaps(hDC, win.LOGPIXELSX))
	screenDPIY = int(win.GetDeviceCaps(hDC, win.LOGPIXELSY))
}

func pt(points int) int {
	return int(win.MulDiv(int32(points), int32(screenDPIX), 72))
}

type UI struct {
	MainWindow  *MultiPageMainWindow
	DataBinder  *walk.DataBinder
	SuccessIcon *walk.Icon
	ErrorIcon   *walk.Icon
	StatusBar   *walk.StatusBarItem
	SaveButton  *walk.ToolButton

	DefaultFont decl.Font

	frontman         *frontman.Frontman
	installationMode bool
}

type setupErrors struct {
	connectionError error
	configError     error
	serviceError    error
}

func (se *setupErrors) SetConnectionError(err error) {
	se.connectionError = err
}

func (se *setupErrors) SetConfigError(err error) {
	se.configError = err
}

func (se *setupErrors) SetServiceError(err error) {
	se.serviceError = err
}

func (se *setupErrors) Describe() string {
	buf := new(bytes.Buffer)
	if se.connectionError != nil {
		fmt.Fprintf(buf, "Hub connection failed: %v", se.connectionError)
		return buf.String()
	}

	if se.configError != nil {
		fmt.Fprintf(buf, "Failed to save settings: %v", se.configError)
		return buf.String()
	}
	fmt.Fprintln(buf, "Your settings are saved.")

	if se.serviceError != nil {
		fmt.Fprintf(buf, "Failed to start Frontman service: %v", se.serviceError)
		return buf.String()
	}
	fmt.Fprint(buf, "Services restarted and you are all set up!")

	return buf.String()
}

const urlScheme = "frontman"

func HandleFeedback(fm *frontman.Frontman, cfgPath string) {
	// handle URL schema arguments on windows
	if runtime.GOOS != "windows" {
		return
	}

	if len(os.Args) < 2 {
		return
	}

	switch os.Args[1] {
	case urlScheme + ":settings":
		// hide console window
		console := w32.GetConsoleWindow()
		if console != 0 {
			w32.ShowWindow(console, w32.SW_HIDE)
		}
		WindowsShowSettingsUI(fm, false)
	case urlScheme + ":install":
		// hide console window
		console := w32.GetConsoleWindow()
		if console != 0 {
			w32.ShowWindow(console, w32.SW_HIDE)
		}
		WindowsShowSettingsUI(fm, true)
	case urlScheme + ":test":
		fm.HandleFlagTest()
	case urlScheme + ":config":
		openConfigInNotepad(cfgPath)
	}
}

func openConfigInNotepad(cfgPath string) error {
	r := strings.NewReplacer("&", "^&")
	cfgPath = r.Replace(cfgPath)
	defer os.Exit(1)
	return exec.Command("cmd", "/C", "start", "", "notepad", cfgPath).Start()
}

// saveAndReloadProxySettings saves the proxy settings to the config and reloads the service
func (ui *UI) saveAndReloadProxySettings() {
	setupStatus := &setupErrors{}
	err := frontman.SaveConfigFile(&ui.frontman.Config.MinValuableConfig, ui.frontman.ConfigLocation)
	if err != nil {
		setupStatus.SetConfigError(errors.Wrap(err, "Failed to write config file"))
		runDialog(ui.MainWindow, ui.ErrorIcon, "Error", setupStatus.Describe(), nil)
	} else {
		runDialog(ui.MainWindow, ui.SuccessIcon, "Success", "Your Proxy Settings successfully saved. To test connection, go to Hub Settings", nil)
	}
}

// saveAndReloadLogSettings saves the log settings to the config and reloads the service
func (ui *UI) saveAndReloadLogSettings() {
	setupStatus := &setupErrors{}
	err := frontman.SaveConfigFile(&ui.frontman.Config.MinValuableConfig, ui.frontman.ConfigLocation)
	if err != nil {
		setupStatus.SetConfigError(errors.Wrap(err, "Failed to write config file"))
		runDialog(ui.MainWindow, ui.ErrorIcon, "Error", setupStatus.Describe(), nil)
	}
}

// testSaveAndReloadHubSettings trying to test the Hub address and credentials from the config.
// If testOnly is true do not show alert message about the status (used to test the existing config on start).
func (ui *UI) testSaveAndReloadHubSettings(testOnly bool) {
	saveButtonText := ui.SaveButton.Text()
	defer func() {
		ui.SaveButton.SetText(saveButtonText)
		ui.SaveButton.SetEnabled(true)
	}()

	ui.SaveButton.SetEnabled(false)
	ui.SaveButton.SetText("Testing...")

	ctx := context.Background()
	setupStatus := &setupErrors{}
	err := ui.frontman.CheckHubCredentials(ctx, "Hub URL", "Username", "Password")
	if err != nil {
		if testOnly {
			return
		}
		setupStatus.SetConnectionError(err)
		ui.StatusBar.SetText("Status: failed to connect to the Hub")
		ui.StatusBar.SetIcon(ui.ErrorIcon)
		runDialog(ui.MainWindow, ui.ErrorIcon, "Error", setupStatus.Describe(), nil)
		return
	}

	// otherwise - provide a feedback for user and set the status
	ui.StatusBar.SetText("Status: successfully connected to the Hub")
	ui.StatusBar.SetIcon(ui.SuccessIcon)

	if testOnly {
		// in case we running this inside msi installer, just exit
		if ui.installationMode {
			os.Exit(0)
		}
		return
	}

	ui.SaveButton.SetText("Saving...")

	ui.frontman.Config.MinValuableConfig.IOMode = frontman.IOModeHTTP
	err = frontman.SaveConfigFile(&ui.frontman.Config.MinValuableConfig, ui.frontman.ConfigLocation)
	if err != nil {
		setupStatus.SetConfigError(errors.Wrap(err, "Failed to write config file"))
		runDialog(ui.MainWindow, ui.ErrorIcon, "Error", setupStatus.Describe(), nil)
		return
	}

	err = ui.reloadService()
	if err != nil {
		setupStatus.SetServiceError(errors.Wrap(err, err.Error()))
		runDialog(ui.MainWindow, ui.ErrorIcon, "Error", setupStatus.Describe(), nil)
	} else {
		if ui.installationMode {
			runDialog(ui.MainWindow, ui.SuccessIcon, "Success", setupStatus.Describe(), func() {
				os.Exit(0)
			})
		} else {
			runDialog(ui.MainWindow, ui.SuccessIcon, "Success", setupStatus.Describe(), nil)
		}
	}
}

// WindowsShowSettingsUI draws a window and waits until it will be closed.
// When installationMode is true, close the window after successful test&save.
func WindowsShowSettingsUI(frontman *frontman.Frontman, installationMode bool) {
	ui := &UI{
		frontman:         frontman,
		installationMode: installationMode,
	}
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exPath := filepath.Dir(ex)
	walk.Resources.SetRootDirPath(filepath.Join(exPath, "resources"))

	ui.SuccessIcon, err = walk.Resources.Icon("success.ico")
	if err != nil {
		log.Fatal(err)
	}
	ui.ErrorIcon, err = walk.Resources.Icon("error.ico")
	if err != nil {
		log.Fatal(err)
	}
	ui.DefaultFont = decl.Font{
		Family:    "Segoe UI",
		PointSize: 12,
	}
	wcfg := &MultiPageMainWindowConfig{
		Title: "Frontman Settings",
		MinSize: decl.Size{
			Width:  pt(200),
			Height: pt(200),
		},
		MaxSize: decl.Size{
			Width:  pt(200),
			Height: pt(200),
		},
		PageCfgs: []PageConfig{
			{"Hub Settings", "login.png", ui.newHubLoginPage()},
			{"Proxy Setup", "proxy.png", ui.newProxyPage()},
			{"Log View", "logs.png", ui.newLogsPage()},
		},
		StatusBarItems: []decl.StatusBarItem{{
			AssignTo:  &ui.StatusBar,
			Width:     pt(40),
			OnClicked: func() {},
		}},
	}
	mpmw, err := NewMultiPageMainWindow(wcfg)
	if err != nil {
		panic(err)
	}
	ui.MainWindow = mpmw

	go func() {
		ui.testSaveAndReloadHubSettings(true)
	}()

	// disable window resize
	win.SetWindowLong(ui.MainWindow.Handle(), win.GWL_STYLE, win.WS_CAPTION|win.WS_SYSMENU)
	win.ShowWindow(ui.MainWindow.Handle(), win.SW_SHOW)
	ui.MainWindow.Run()
}

type HubLoginPage struct {
	*walk.Composite
}

func (ui *UI) newHubLoginPage() PageFactoryFunc {
	return func(parent walk.Container) (Page, error) {
		p := new(HubLoginPage)

		if err := (decl.Composite{
			AssignTo: &p.Composite,
			Name:     "Hub Settings",
			DataBinder: decl.DataBinder{
				AssignTo:       &ui.DataBinder,
				Name:           "config",
				DataSource:     ui.frontman.Config,
				ErrorPresenter: decl.ToolTipErrorPresenter{},
			},
			Layout: decl.VBox{},
			Children: []decl.Widget{
				decl.GroupBox{
					Title: "Frontman > Hub Settings > Hub Connection Credentials",
					Layout: decl.Grid{
						Columns: 2,
						Margins: decl.Margins{
							Left:   pt(10),
							Top:    pt(10),
							Right:  pt(10),
							Bottom: pt(10),
						},
					},
					Children: []decl.Widget{
						decl.Label{
							Text: "Hub URL:",
							Font: ui.DefaultFont,
						},
						decl.LineEdit{
							Text: decl.Bind("HubURL"),
							Font: ui.DefaultFont,
						},
						decl.Label{
							Text: "Username:",
							Font: ui.DefaultFont,
						},
						decl.LineEdit{
							Text: decl.Bind("HubUser"),
							Font: ui.DefaultFont,
						},
						decl.Label{
							Text: "Password:",
							Font: ui.DefaultFont,
						},
						decl.LineEdit{
							Text: decl.Bind("HubPassword"),
							Font: ui.DefaultFont,
						},
					},
				},
				decl.Composite{
					Layout: decl.HBox{},
					Children: []decl.Widget{
						decl.ToolButton{
							MinSize: decl.Size{
								Width:  pt(380),
								Height: pt(35),
							},
							AlwaysConsumeSpace: true,
							AssignTo:           &ui.SaveButton,
							Text:               "Test and Save",
							Font:               ui.DefaultFont,
							OnClicked: func() {
								ui.DataBinder.Submit()
								ui.testSaveAndReloadHubSettings(false)
							},
						},
					},
				},
			},
		}).Create(decl.NewBuilder(parent)); err != nil {
			err = errors.Wrap(err, "failed to create composite")
			return nil, err
		}

		if err := walk.InitWrapperWindow(p); err != nil {
			err = errors.Wrap(err, "failed to init wrapper window")
			return nil, err
		}

		return p, nil
	}
}

type ProxyPage struct {
	*walk.Composite
}

func (ui *UI) newProxyPage() PageFactoryFunc {
	return func(parent walk.Container) (Page, error) {
		p := new(ProxyPage)

		if err := (decl.Composite{
			AssignTo: &p.Composite,
			Name:     "Proxy Setup",
			DataBinder: decl.DataBinder{
				AssignTo:       &ui.DataBinder,
				Name:           "config",
				DataSource:     ui.frontman.Config,
				ErrorPresenter: decl.ToolTipErrorPresenter{},
			},
			Layout: decl.VBox{},
			Children: []decl.Widget{
				decl.GroupBox{
					Title: "Frontman > Hub Settings > Hub Proxy Setup",
					Layout: decl.Grid{
						Columns: 2,
						Margins: decl.Margins{
							Left:   pt(10),
							Top:    pt(10),
							Right:  pt(10),
							Bottom: pt(10),
						},
					},
					Children: []decl.Widget{
						decl.Label{
							Text: "Proxy Address:",
							Font: ui.DefaultFont,
						},
						decl.LineEdit{
							Text: decl.Bind("HubProxy"),
							Font: ui.DefaultFont,
						},
						decl.Label{
							Text: "Proxy User:",
							Font: ui.DefaultFont,
						},
						decl.LineEdit{
							Text: decl.Bind("HubProxyUser"),
							Font: ui.DefaultFont,
						},
						decl.Label{
							Text: "Proxy Password:",
							Font: ui.DefaultFont,
						},
						decl.LineEdit{
							Text: decl.Bind("HubProxyPassword"),
							Font: ui.DefaultFont,
						},
					},
				},
				decl.Composite{
					Layout: decl.HBox{},
					Children: []decl.Widget{
						decl.ToolButton{
							MinSize: decl.Size{
								Width:  pt(380),
								Height: pt(35),
							},
							AlwaysConsumeSpace: true,
							AssignTo:           &ui.SaveButton,
							Text:               "Save Settings",
							Font:               ui.DefaultFont,
							OnClicked: func() {
								ui.DataBinder.Submit()
								ui.saveAndReloadProxySettings()
							},
						},
					},
				},
			},
		}).Create(decl.NewBuilder(parent)); err != nil {
			err = errors.Wrap(err, "failed to create composite")
			return nil, err
		}

		if err := walk.InitWrapperWindow(p); err != nil {
			err = errors.Wrap(err, "failed to init wrapper window")
			return nil, err
		}

		return p, nil
	}
}

type LogsPage struct {
	*walk.Composite
}

func (ui *UI) newLogsPage() PageFactoryFunc {
	return func(parent walk.Container) (Page, error) {
		p := new(LogsPage)

		if err := (decl.Composite{
			AssignTo: &p.Composite,
			Name:     "Logs View",
			DataBinder: decl.DataBinder{
				AssignTo:       &ui.DataBinder,
				Name:           "config",
				DataSource:     ui.frontman.Config,
				ErrorPresenter: decl.ToolTipErrorPresenter{},
			},
			Layout: decl.VBox{},
			Children: []decl.Widget{
				decl.RadioButtonGroupBox{
					ColumnSpan: 1,
					Title:      "Frontman > Logs Settings",
					Layout: decl.HBox{
						Margins: decl.Margins{
							Left:   pt(10),
							Top:    pt(10),
							Right:  pt(10),
							Bottom: pt(10),
						},
					},
					DataMember: "LogLevel",
					Buttons: []decl.RadioButton{
						{Text: "Info", Value: frontman.LogLevelInfo},
						{Text: "Debug", Value: frontman.LogLevelDebug},
						{Text: "Errors only", Value: frontman.LogLevelError},
					},
				},
				decl.PushButton{
					MinSize: decl.Size{
						Width:  pt(30),
						Height: pt(15),
					},
					Text: "Save Settings",
					Font: decl.Font{
						Family:    "Segoe UI",
						PointSize: 10,
					},
					OnClicked: func() {
						ui.DataBinder.Submit()
						ui.saveAndReloadLogSettings()
					},
				},
			},
		}).Create(decl.NewBuilder(parent)); err != nil {
			err = errors.Wrap(err, "failed to create composite")
			return nil, err
		}

		if err := walk.InitWrapperWindow(p); err != nil {
			err = errors.Wrap(err, "failed to init wrapper window")
			return nil, err
		}

		lv, err := NewLogView(p)
		if err != nil {
			err = errors.Wrap(err, "failed to init new log vieww")
			return nil, err
		}
		lv.SetMinMaxSize(walk.Size{
			Width:  pt(500),
			Height: pt(250),
		}, walk.Size{
			Width:  pt(1600),
			Height: pt(800),
		})
		logFile, err := os.Open(ui.frontman.Config.LogFile)
		if err != nil {
			lv.PostAppendText("failed to open log file: " + ui.frontman.Config.LogFile)
		} else {
			go func() {
				defer logFile.Close()
				buf := make([]byte, 65536)
				for {
					if _, err := io.CopyBuffer(lv, logFile, buf); err != nil {
						lv.PostAppendText("log file read error: " + err.Error())
						return
					}
					time.Sleep(500 * time.Millisecond)
				}
			}()
		}

		return p, nil
	}
}

func runDialog(owner walk.Form, icon *walk.Icon, title, text string, callback func()) (int, error) {
	var dlg *walk.Dialog
	var acceptPB *walk.PushButton
	font := decl.Font{PointSize: 12, Family: "Segoe UI"}

	return decl.Dialog{
		FixedSize:     true,
		AssignTo:      &dlg,
		Title:         title,
		DefaultButton: &acceptPB,
		MaxSize: decl.Size{
			Width:  pt(320),
			Height: pt(180),
		},
		Font:   font,
		Layout: decl.VBox{},
		Children: []decl.Widget{
			decl.Composite{
				Layout: decl.HBox{},
				Children: []decl.Widget{
					decl.ImageView{
						Image: icon,
					},
					decl.VSpacer{},
					decl.TextLabel{
						MaxSize: decl.Size{
							Width:  pt(320),
							Height: pt(180),
						},
						Text: text,
						Font: font,
					},
				},
			},
			decl.HSpacer{},
			decl.Composite{
				Layout: decl.VBox{},
				Children: []decl.Widget{
					decl.PushButton{
						Font:     font,
						AssignTo: &acceptPB,
						Text:     "OK",
						OnClicked: func() {
							dlg.Accept()
							if callback != nil {
								callback()
							}
						},
					},
				},
			},
		},
	}.Run(owner)
}
