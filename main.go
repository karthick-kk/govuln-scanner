package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"govuln-scanner/cislinuxfive"
	"govuln-scanner/cislinuxfour"
	"govuln-scanner/cislinuxone"
	"govuln-scanner/cislinuxsix"
	"govuln-scanner/cislinuxthree"
	"govuln-scanner/cislinuxtwo"
	"govuln-scanner/remexec"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
)

func Use(vals ...interface{}) {
	for _, val := range vals {
		_ = val
	}
}

func percentOf(part int, total int) float64 {
	if total == 0 {
		return 0
	}
	return (float64(part) * float64(100)) / float64(total)
}

func floatToString(inputnum float64) string {
	return strconv.FormatFloat(inputnum, 'f', 0, 64)
}

type Context struct {
	Title   string
	Node    string
	Total   string
	Success string
	Percent string
}

type Datastat struct {
	Controlid string
	Check     string
	Status    string
}

func scan(w http.ResponseWriter, r *http.Request) Context {
	context := Context{
		Title: "GoVuln Scanner 0.7",
		Node:  "",
	}
	if r != nil {
		context.Node = r.PostFormValue("name")
	}
	return context
}

func scandata(user string, host string, pass string, key string) []Datastat {
	log.Printf("DEBUG: scandata called with user: %s, host: %s, pass: [%d chars], key: [%d chars]\n", user, host, len(pass), len(key))

	conn, err := remexec.NewSSHConnection(user, host, pass, key)
	if err != nil {
		log.Printf("ERROR: Failed to create SSH connection: %v\n", err)
		return []Datastat{}
	}
	defer conn.Close()
	log.Printf("DEBUG: Single SSH connection established for optimized scanning\n")

	resultcisscan1 := cislinuxone.CislinuxoneOptimized(conn)
	log.Printf("DEBUG: cislinuxone completed, results: %d\n", len(resultcisscan1))

	resultcisscan2 := cislinuxtwo.CislinuxtwoOptimized(conn)
	log.Printf("DEBUG: cislinuxtwo completed, results: %d\n", len(resultcisscan2))

	resultcisscan3 := cislinuxthree.CislinuxthreeOptimized(conn)
	log.Printf("DEBUG: cislinuxthree completed, results: %d\n", len(resultcisscan3))

	resultcisscan4 := cislinuxfour.CislinuxfourOptimized(conn)
	log.Printf("DEBUG: cislinuxfour completed, results: %d\n", len(resultcisscan4))

	resultcisscan5 := cislinuxfive.CislinuxfiveOptimized(conn)
	log.Printf("DEBUG: cislinuxfive completed, results: %d\n", len(resultcisscan5))

	resultcisscan6 := cislinuxsix.CislinuxsixOptimized(conn)
	log.Printf("DEBUG: cislinuxsix completed, results: %d\n", len(resultcisscan6))

	combo := []Datastat{}

	// use JSON roundtrip to convert package-specific types to local Datastat
	var jb []byte
	var err2 error
	jb, err2 = json.Marshal(resultcisscan1)
	Use(err2)
	var items []Datastat
	if err2 = json.Unmarshal(jb, &items); err2 == nil {
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

func endscan(datasetscore []Datastat) Context {
	context := Context{}
	total := len(datasetscore)
	score := 0
	for _, v := range datasetscore {
		if v.Status == "PASS" {
			score++
		}
	}
	percent := percentOf(score, total)
	
	context.Total = strconv.Itoa(total)
	context.Success = strconv.Itoa(score)
	context.Percent = floatToString(percent)
	return context
}

func StreamHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("DEBUG: StreamHandler called")
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
	key := q.Get("key")
	log.Printf("DEBUG: StreamHandler params - user: %s, host: %s, pass: [%d chars], key: [%d chars]\n", user, host, len(pass), len(key))

	// optional key parameter is base64-encoded PEM; if present, decode and use
	if k := q.Get("key"); k != "" {
		if decoded, err := base64.StdEncoding.DecodeString(k); err == nil {
			key = string(decoded)
			log.Println("DEBUG: StreamHandler decoded base64 key")
		}
	}

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

	// Call modules lazily using optimized connection. If client disconnects (ctx.Done()), stop starting new modules.
	// Create single SSH connection for streaming scan
	conn, err := remexec.NewSSHConnection(user, host, pass, key)
	if err != nil {
		log.Printf("ERROR: Failed to create SSH connection for streaming: %v\n", err)
		sendEvent("error", "SSH connection failed: "+err.Error())
		return
	}
	defer conn.Close()
	log.Printf("DEBUG: Single SSH connection established for streaming scan\n")

	// Use interface{} return so each module can return its package-specific slice type.
	modules := []func() interface{}{
		func() interface{} { return cislinuxone.CislinuxoneOptimized(conn) },
		func() interface{} { return cislinuxtwo.CislinuxtwoOptimized(conn) },
		func() interface{} { return cislinuxthree.CislinuxthreeOptimized(conn) },
		func() interface{} { return cislinuxfour.CislinuxfourOptimized(conn) },
		func() interface{} { return cislinuxfive.CislinuxfiveOptimized(conn) },
		func() interface{} { return cislinuxsix.CislinuxsixOptimized(conn) },
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
	report := scandata(user, host, pass, key)
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
	log.Println("DEBUG: ScanHandler called with method:", r.Method)

	// Parse multipart form for file uploads (32MB max)
	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		log.Printf("DEBUG: Error parsing multipart form: %v, trying regular form\n", err)
		err = r.ParseForm()
		if err != nil {
			log.Printf("DEBUG: Error parsing form: %v\n", err)
			return
		}
	}

	var user, host, pass, key string
	host = r.FormValue("name")
	user = r.FormValue("user")
	pass = r.FormValue("password")
	key = r.FormValue("key")

	// Handle file upload for private key
	if file, _, err := r.FormFile("keyfile"); err == nil {
		defer file.Close()
		keyBytes := make([]byte, 32768) // Max 32KB key file
		n, err := file.Read(keyBytes)
		if err != nil {
			log.Printf("DEBUG: Error reading key file: %v\n", err)
		} else {
			keyContent := string(keyBytes[:n])
			// If it looks like base64 encoded, decode it
			if decoded, err := base64.StdEncoding.DecodeString(keyContent); err == nil {
				key = string(decoded)
				log.Println("DEBUG: Decoded base64 key from file")
			} else {
				key = keyContent
				log.Println("DEBUG: Using raw key content from file")
			}
		}
	} else if key != "" {
		// Handle base64-encoded key from hidden form field
		if decoded, err := base64.StdEncoding.DecodeString(key); err == nil {
			key = string(decoded)
			log.Println("DEBUG: Decoded base64 key from form field")
		}
	}

	log.Printf("DEBUG: Form values - host: %s, user: %s, pass: [%d chars], key: [%d chars]\n", host, user, len(pass), len(key))

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
	data := scan(w, r)
	// attach username if present
	data.Node = data.Node
	var tpl bytes.Buffer
	t.Execute(&tpl, data)
	result := tpl.String()

	// Fetch CIS report
	report := scandata(user, host, pass, key)

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

	s, err := template.ParseFiles(endresPath)
	Use(err)
	datascore := endscan(report)
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
	product := scan(w, req)
	t.Execute(w, product)
}

func main() {
	var port int
	flag.IntVar(&port, "p", 8000, "specify port to use. defaults to 8000")
	flag.Parse()
	log.Printf("Starting server on port %d", port)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET / - serving index")
		indexHandler(w, r)
	})
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("POST /scan - received request")
		ScanHandler(w, r)
	})
	// serve static files (css/js/images)
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("POST /stream - received request")
		StreamHandler(w, r)
	})
	log.Printf("Server listening on http://localhost:%d", port)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), nil))
}
