package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"govuln-scanner/cislinuxfive"
	"govuln-scanner/cislinuxfour"
	"govuln-scanner/cislinuxone"
	"govuln-scanner/cislinuxsix"
	"govuln-scanner/cislinuxthree"
	"govuln-scanner/cislinuxtwo"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
)

// Use vals to create dummy vars
func Use(vals ...interface{}) {
	for _, val := range vals {
		_ = val
	}
}



// percentOf calculation
func percentOf(part int, total int) float64 {
	if total == 0 {
		return 0
	}
	return (float64(part) * float64(100)) / float64(total)
}

				// floatToString function
				func floatToString(inputnum float64) string {
					// to convert a float number to a string
					return strconv.FormatFloat(inputnum, 'f', 0, 64)
				}

				// Context declaration
				type Context struct {
					Title   string
					Node    string
					Total   string
					Success string
					Percent string
				}

				// Datastat declaration
				type Datastat struct {
					Controlid string
					Check     string
					Status    string
				}

				// scan builds page context from the request
				func scan(r *http.Request) Context {
					context := Context{
						Title: "GoVuln Scanner 0.7",
						Node:  "",
					}
					if r != nil {
						context.Node = r.PostFormValue("name")
					}
					return context
				}

				// auth removed; no session username

				// scandata aggregates results from all cis modules into []Datastat
				func scandata(user string, host string, pass string) []Datastat {
					resultcisscan1 := cislinuxone.Cislinuxone(user, host, pass)
					resultcisscan2 := cislinuxtwo.Cislinuxtwo(user, host, pass)
					resultcisscan3 := cislinuxthree.Cislinuxthree(user, host, pass)
					resultcisscan4 := cislinuxfour.Cislinuxfour(user, host, pass)
					resultcisscan5 := cislinuxfive.Cislinuxfive(user, host, pass)
					resultcisscan6 := cislinuxsix.Cislinuxsix(user, host, pass)

					combo := []Datastat{}

					// use JSON roundtrip to convert package-specific types to local Datastat
					var jb []byte
					var err error
					jb, err = json.Marshal(resultcisscan1)
					Use(err)
					var items []Datastat
					if err = json.Unmarshal(jb, &items); err == nil {
						combo = append(combo, items...)
					}

					jb, err = json.Marshal(resultcisscan2)
					Use(err)
					if err = json.Unmarshal(jb, &items); err == nil {
						combo = append(combo, items...)
					}
					jb, err = json.Marshal(resultcisscan3)
					Use(err)
					if err = json.Unmarshal(jb, &items); err == nil {
						combo = append(combo, items...)
					}
					jb, err = json.Marshal(resultcisscan4)
					Use(err)
					if err = json.Unmarshal(jb, &items); err == nil {
						combo = append(combo, items...)
					}
					jb, err = json.Marshal(resultcisscan5)
					Use(err)
					if err = json.Unmarshal(jb, &items); err == nil {
						combo = append(combo, items...)
					}
					jb, err = json.Marshal(resultcisscan6)
					Use(err)
					if err = json.Unmarshal(jb, &items); err == nil {
						combo = append(combo, items...)
					}

					return combo
				}

			// endscan prepares a Context with score/total/percent strings
			func endscan(r *http.Request, score int, total int, percent float64) Context {
				context := Context{}
				context.Total = strconv.Itoa(total)
				context.Success = strconv.Itoa(score)
				context.Percent = floatToString(percent)
				return context
			}

				// StreamHandler streams check results as Server-Sent Events (SSE).
				func StreamHandler(w http.ResponseWriter, r *http.Request) {
					fl, ok := w.(http.Flusher)
					if !ok {
						http.Error(w, "streaming unsupported", http.StatusInternalServerError)
						return
					}
					ctx := r.Context()

					q := r.URL.Query()
					user := q.Get("user")
					host := q.Get("name")
					pass := q.Get("password")

					w.Header().Set("Content-Type", "text/event-stream")
					w.Header().Set("Cache-Control", "no-cache")
					w.Header().Set("Connection", "keep-alive")

					// small helper to send an event
					sendEvent := func(event string, v interface{}) {
						var b []byte
						switch t := v.(type) {
						case string:
							b = []byte(t)
						default:
							jb, err := json.Marshal(v)
							if err != nil {
								return
							}
							b = jb
							_ = t
						}
						fmt.Fprintf(w, "event: %s\n", event)
						fmt.Fprintf(w, "data: %s\n\n", b)
						fl.Flush()
					}

					// Notify client we've started
					sendEvent("started", "scanning")

					// helper to stream results from each CIS module sequentially
					streamModule := func(results interface{}) {
						// results will be a slice of module-specific structs; we iterate using reflection via json roundtrip
						jb, err := json.Marshal(results)
						if err != nil {
							return
						}
						// decode into []Datastat to standardize
						var items []Datastat
						if err := json.Unmarshal(jb, &items); err != nil {
							return
						}
						for _, it := range items {
							// if client disconnected, stop processing
							select {
							case <-ctx.Done():
								return
							default:
							}
							sendEvent("check", it)
							// small delay to allow UI to update smoothly
							time.Sleep(50 * time.Millisecond)
						}
					}

					// Call modules lazily. If client disconnects (ctx.Done()), stop starting new modules.
					// Use interface{} return so each module can return its package-specific slice type.
					modules := []func() interface{}{
						func() interface{} { return cislinuxone.Cislinuxone(user, host, pass) },
						func() interface{} { return cislinuxtwo.Cislinuxtwo(user, host, pass) },
						func() interface{} { return cislinuxthree.Cislinuxthree(user, host, pass) },
						func() interface{} { return cislinuxfour.Cislinuxfour(user, host, pass) },
						func() interface{} { return cislinuxfive.Cislinuxfive(user, host, pass) },
						func() interface{} { return cislinuxsix.Cislinuxsix(user, host, pass) },
					}

					for _, m := range modules {
						select {
						case <-ctx.Done():
							// client cancelled — notify and stop
							sendEvent("stopped", "client cancelled")
							return
						default:
						}
						results := m()
						// if client cancelled while module ran, stop streaming
						select {
						case <-ctx.Done():
							sendEvent("stopped", "client cancelled")
							return
						default:
						}
						streamModule(results)
					}

					// calculate score and send final summary
					report := scandata(user, host, pass)
					score, total := 0, 0
					for _, item := range report {
						if strings.Contains(item.Check, "Not Scored") != true {
							if item.Status == "PASS" {
								score = score + 1
							}
							total = total + 1
						}
					}
					percent := percentOf(score, total)
					summary := map[string]string{
						"Total":   strconv.Itoa(total),
						"Success": strconv.Itoa(score),
						"Percent": floatToString(percent),
					}
					sendEvent("score", summary)
					sendEvent("done", "finished")
				}

				// ScanHandler functions
				func ScanHandler(w http.ResponseWriter, r *http.Request) {
					err := r.ParseForm()
					if err != nil {
						// Handle error here via logging and then return
					}
					var user, host, pass string
					host = r.PostFormValue("name")
					user = r.PostFormValue("user")
					pass = r.PostFormValue("password")
					log.Println(r.Method)
					w.Header().Add("Content Type", "text/html")
					// Load templates from files
					tmplDir := filepath.Join(".", "templates")
					titlePath := filepath.Join(tmplDir, "title.html")
					mbodyPath := filepath.Join(tmplDir, "mbody.html")
					endresPath := filepath.Join(tmplDir, "endres.html")

					// Render navbar + title
					t, err := template.ParseFiles(titlePath)
					Use(err)
					data := scan(r)
					// attach username if present
					data.Node = data.Node
					var tpl bytes.Buffer
					t.Execute(&tpl, data)
					result := tpl.String()

					// Fetch CIS report
					report := scandata(user, host, pass)

					// Calculate Score
					score, total := 0, 0
					for _, item := range report {
						if strings.Contains(item.Check, "Not Scored") != true {
							if item.Status == "PASS" {
								score = score + 1
							}
							total = total + 1
						}
					}
					percent := percentOf(score, total)

					// Render result
					s, err := template.ParseFiles(endresPath)
					Use(err)
					datascore := endscan(r, score, total, percent)
					var tplscore bytes.Buffer
					s.Execute(&tplscore, datascore)
					rendresult := tplscore.String()

					// Read mbody template and concatenate
					mb, err := os.ReadFile(mbodyPath)
					Use(err)
					doc := result + string(mb) + rendresult

					// Start rendering Page
					templates := template.New("doc")
					templates.Parse(doc)
					templates.Execute(w, report)
				}

				func indexHandler(w http.ResponseWriter, req *http.Request) {
					w.Header().Add("Content Type", "text/html")
					tmplPath := filepath.Join(".", "templates", "dex.html")
					t, err := template.ParseFiles(tmplPath)
					Use(err)
					product := scan(req)
					t.Execute(w, product)
				}

				func main() {
					var port int
					flag.IntVar(&port, "p", 8000, "specify port to use. defaults to 8000")
					flag.Parse()
					http.HandleFunc("/", indexHandler)
					http.HandleFunc("/scan", ScanHandler)
					// serve static files (css/js/images)
					fs := http.FileServer(http.Dir("./static"))
					http.Handle("/static/", http.StripPrefix("/static/", fs))
					http.HandleFunc("/stream", StreamHandler)
					log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), nil))
				}
