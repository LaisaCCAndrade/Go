package handler

import (
	"log"
	"net/http"
	"text/template"

	"Luan/Desktop/GoLang/Go/database"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type SignupData struct {
	Name, Email, Password, About string
}

type TemplateData struct {
	Signupsuccess, LoginFailure string
}

var store *sessions.CookieStore

func init() {
	store = sessions.NewCookieStore([]byte("secret-key"))
}

func makeTemplate(path string) *template.Template {
	files := []string{path, "templates/footer.html", "templates/base.html"}

	return template.Must(template.ParseFiles(files...))
}

var (
	homeTmpl = makeTemplate("templates/home.html")
	aboutTmpl = makeTemplate("templates/about.html")
	aboutFormTmpl = makeTemplate("templates/aboutForm.html")
	signupTmpl = makeTemplate("templates/signup.html")
	loginTmpl = makeTemplate("templates/login.html")
	logoutTmpl = makeTemplate("templates/logout.html")
	pageErrorTmpl = makeTemplate("templates/pageerror.html")
)

func Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		if err := pageErrorTmpl.Execute(w, nil); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := homeTmpl.Execute(w, nil); err != nil {
		log.Fatal(err)
	}
}

func hashAndSalt(pass []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)

	if err != nil {
		log.Fatal(err)
	}

	return string(hash)
}

func comparePassword(hashPassword string, plainPass []byte) bool {
	byteHash := []byte(hashPassword)

	if err := bcrypt.CompareHashAndPassword(byteHash, plainPass); err != nil {
		log.Println(err)

		return false
	}

	return true
}

func Signup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {

		if err := signupTmpl.Execute(w, nil); err != nil {
			log.Fatal(err)
		}

		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm-password")
	hashPassword := hashAndSalt([]byte(password)) 

	if comparePassword(hashPassword, []byte(confirmPassword)) {
		stuff := SignupData{name, email, hashPassword, ""} 
		database.InsertData(stuff)

		sm := TemplateData{Signupsuccess: "Sua conta foi criada com sucesso"}

		if err := loginTmpl.Execute(w, sm); err != nil {
			log.Fatal(err)
		}

		http.Redirect(w, r, "/login", http.StatusFound)
	} else {
		fm := struct {Falha string} {Falha: "As senhas não coincidem"}

		if err := signupTmpl.Execute(w, fm); err != nil {
			log.Fatal(err)
		}
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {

		if err := loginTmpl.Execute(w, nil); err != nil {
			log.Fatal(err)
		}
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	match := database.FindAccount(email, password)

	if match == true {
		session, _ := store.Get(r, "session-name")
		session.Values["authenticated"] = true
		session.Save(r, w)

		http.Redirect(w, r, "/about", http.StatusFound)
	} else {
		fm := TemplateData{LoginFailure: "Digite o e-mail ou senha corretos"}
		if err := loginTmpl.Execute(w, fm); err != nil {
			log.Fatal(err)
		}
	}
}

func About(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")

	var authenticated interface{} = session.Values["authenticated"]

	if authenticated != nil {
		isAuthenticated := session.Values["authenticated"].(bool)

		if !isAuthenticated {
			if err := loginTmpl.Execute(w, nil); err != nil {
				panic(err)
			}
			return
		}

		showAbout(w, r)
	} else {
		if err := loginTmpl.Execute(w, nil); err != nil {
			panic(err)
		}
		return
	}
}

func showAbout(w http.ResponseWriter, r *http.Request) {
	d := struct{ Aboutdata string }{Aboutdata: database.Account.About}

	if r.Method == "GET" {

		if database.Account.About == "" {

			if err := aboutFormTmpl.Execute(w, nil); err != nil {
				log.Fatal(err)
			}

			return
		} else {
	
			if err := aboutTmpl.Execute(w, d); err != nil {
				log.Fatal(err)
			}

			return
		}
	} else if r.Method == "POST" {
		content := r.FormValue("content")
		update := database.Updatedata("about", content)

		if update == true {
			d := struct{ Aboutdata string }{Aboutdata: content}

			if err := aboutTmpl.Execute(w, d); err != nil {
				log.Fatal(err)
			}

			return
		} else {
			f := struct{ Aboutfailure string }{Aboutfailure: "Seus dados não estão atualizados"}

			if err := aboutFormTmpl.Execute(w, f); err != nil {
				log.Fatal(err)
			}

			return
		}
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Save(r, w)

	if err := logoutTmpl.Execute(w, nil); err != nil {
		log.Fatal(err)
	}
}
