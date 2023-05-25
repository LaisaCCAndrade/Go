package main

import (
	"Luan/Desktop/GoLang/Go/handler"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handler.Home)

	http.HandleFunc("/about", handler.About)

	http.HandleFunc("/signup", handler.Signup)

	http.HandleFunc("/login", handler.Login)

	http.HandleFunc("/logout", handler.Logout)

	http.Handle("/static/", http.StripPrefix("/static", http.FileServer(http.Dir("static"))))

	if err := http.ListenAndServe(":3000", nil); err != nil {
		log.Fatal(err)
	}
}
