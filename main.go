package main

import (
	"bytes"
	"govuln-scanner/cislinuxfive"
	"govuln-scanner/cislinuxfour"
	"govuln-scanner/cislinuxone"
	"govuln-scanner/cislinuxsix"
	"govuln-scanner/cislinuxthree"
	"govuln-scanner/cislinuxtwo"
	"flag"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"text/template"
)

// Use vals to create dummy vars
func Use(vals ...interface{}) {
	for _, val := range vals {
		_ = val
	}
}

// percentOf calculation
func percentOf(part int, total int) float64 {
	return (float64(part) * float64(100)) / float64(total)
}

// floatToString function
func floatToString(inputnum float64) string {
	// to convert a float number to a string
	return strconv.FormatFloat(inputnum, 'f', 0, 64)
}

// CmdExec Execute a command
func CmdExec(args ...string) (string, error) {

	baseCmd := args[0]
	cmdArgs := args[1:]

	cmd := exec.Command(baseCmd, cmdArgs...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func scan(r *http.Request) Context {
	//out, err := CmdExec("../go/bin/go", "version")
	context := Context{
		Title: "GoVuln Scanner 0.6 R1",
		Node:  "",
	}
	context.Node = r.PostFormValue("name")
	//Use(err)
	return context
}

func endscan(r *http.Request, score int, total int, percent float64) Context {
	context := Context{}

	context.Total = strconv.Itoa(total)
	context.Success = strconv.Itoa(score)
	context.Percent = floatToString(percent)

	return context
}

func scandata(user string, host string, pass string) []Datastat {
	resultcisscan1 := cislinuxone.Cislinuxone(user, host, pass)
	resultcisscan2 := cislinuxtwo.Cislinuxtwo(user, host, pass)
	resultcisscan3 := cislinuxthree.Cislinuxthree(user, host, pass)
	resultcisscan4 := cislinuxfour.Cislinuxfour(user, host, pass)
	resultcisscan5 := cislinuxfive.Cislinuxfive(user, host, pass)
	resultcisscan6 := cislinuxsix.Cislinuxsix(user, host, pass)

	combo := []Datastat{}

	for _, additem := range resultcisscan1 {
		combo = append(combo, Datastat(additem))
	}
	for _, additem := range resultcisscan2 {
		combo = append(combo, Datastat(additem))
	}
	for _, additem := range resultcisscan3 {
		combo = append(combo, Datastat(additem))
	}
	for _, additem := range resultcisscan4 {
		combo = append(combo, Datastat(additem))
	}
	for _, additem := range resultcisscan5 {
		combo = append(combo, Datastat(additem))
	}
	for _, additem := range resultcisscan6 {
		combo = append(combo, Datastat(additem))
	}
	//fmt.Println(combo)

	return combo
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
	templates := template.New("template")

	// Render navbar + title
	t := template.New("action")
	t, err = t.Parse(title)
	Use(err)
	data := scan(r)
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
	s := template.New("action")
	s, err = t.Parse(endres)
	Use(err)
	datascore := endscan(r, score, total, percent)
	var tplscore bytes.Buffer
	s.Execute(&tplscore, datascore)
	rendresult := tplscore.String()

	doc := result + mbody + rendresult
	// Start rendering Page
	templates.New("doc").Parse(doc)
	templates.Lookup("doc").Execute(w, report)

}

func indexHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content Type", "text/html")
	templates := template.New("template")
	templates.New("dex").Parse(dex)
	product := scan(req)
	templates.Lookup("dex").Execute(w, product)
}

func main() {
	var port int
	flag.IntVar(&port, "p", 8000, "specify port to use. defaults to 8000")
	flag.Parse()
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/scan", ScanHandler)
	http.ListenAndServe(":"+strconv.Itoa(port), nil)
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

const title = `
<!DOCTYPE html>
<html>
<head>
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
<nav class="navbar navbar-inverse navbar-fixed-top">
<div class="container-fluid">
    <div class="navbar-header">
    <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#myNavbar">
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
    </button>
    <a class="navbar-brand" href="/">GoVuln Scanner</a>
    </div>
    <div class="collapse navbar-collapse" id="myNavbar">
    <ul class="nav navbar-nav">
    </ul>
    <ul class="nav navbar-nav navbar-right">
        <li><a href="#"><span class="glyphicon glyphicon-user"></span> Sign Up</a></li>
        <li><a href="#"><span class="glyphicon glyphicon-log-in"></span> Login</a></li>
    </ul>
    </div>
</div>
</nav> 
</head>
<body data-spy="scroll" data-target=".navbar" data-offset="50" href="top">
<br>
<br>
<br>
<div class="container">
		<h4>Node: {{.Node}}</h4>
		<a href="#score" class="btn btn-block btn-warning">Seek to Benchmark Score</a>
</div>
<div class="container">
`
const mbody = `
<table class="table table-striped">
    <thead>
    <tr>
        <th scope="col">Test number</th>
        <th scope="col">Message</th>
        <th scope="col">Level</th>
    </tr>
    </thead>
    <tbody>
    {{range $y, $x := . }}
    <tr>
      <td>{{ $x.Controlid }}</td>
      <td>{{ $x.Check }}</td>
      {{if eq $x.Status "FAIL"}}
      <td class="danger">{{ $x.Status }}</td>
      {{ else }}
      <td class="success">{{ $x.Status }}</td>
      {{ end }}
    </tr>
    {{end}}        
    </tbody>
</table>
</div>
`
const endres = `
<div class="container">
<br>
<table id="score" class="table table-striped">
	<tr>
	<th>Total Checks(Scored): {{.Total}}</th>
	<th>Items Passed: {{.Success}}</th>
	<th>Benchmark Score: {{.Percent}}</th>
	<th><a href="#top">Back To Top</a></th>
	</tr>
</table>
</div>
</body>
</html>
`

const dex = `
<!DOCTYPE html>
<html>
    <head>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
        <nav class="navbar navbar-inverse">
        <div class="container-fluid">
            <div class="navbar-header">
            <button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#myNavbar">
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="#">GoVuln Scanner</a>
            </div>
            <div class="collapse navbar-collapse" id="myNavbar">
            <ul class="nav navbar-nav">
            </ul>
            <ul class="nav navbar-nav navbar-right">
                <li><a href="#"><span class="glyphicon glyphicon-user"></span> Sign Up</a></li>
                <li><a href="#"><span class="glyphicon glyphicon-log-in"></span> Login</a></li>
            </ul>
            </div>
        </div>
        </nav> 
        <div class="container">
                <h4> {{.Title}} </h4>
        </div>
    </head>
    <body>
        <div class="container">
        <form class="form-inline" action="/scan" method="post">
        <label class="sr-only" for="inlineFormInputName2">Name</label>
		<input type="text" name="name" value="" class="form-control mb-2 mr-sm-2" id="inlineFormInputName2" placeholder="Hostname/IP">
		<div class="form-group">
		<label class="sr-only" for="exampleInputName3">User</label>
		<input type="text" name="user" value="" class="form-control" id="exampleInputName3" placeholder="User">
		</div>
		<div class="form-group">
			<label class="sr-only" for="exampleInputPassword3">Password</label>
			<input type="password" name="password" value="" class="form-control" id="exampleInputPassword3" placeholder="Password">
		</div>
        <button type="submit" class="btn btn-primary mb-2">Submit</button>
        </form>
        </div>
    </body>
</html>
`
