// Copyright (c) 2016 - 2020 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/sqreen/go-dvwa/vulnerable"
)

func NewRouter(templateDir string) *mux.Router {
	db, err := vulnerable.PrepareSQLDB(10)
	if err != nil {
		log.Println("could not prepare the sql database :", err)
	}

	t, err := template.ParseFiles(filepath.Join(templateDir, "category.html"))
	if err != nil {
		log.Fatalln(err)
	}

	r := mux.NewRouter()

	// /products vulnerable to SQL injections
	r.HandleFunc("/products", func(w http.ResponseWriter, r *http.Request) {
		category := r.FormValue("category")
		products, err := vulnerable.GetProducts(r.Context(), db, category)
		if err != nil {
			log.Println(err)
			return
		}
		// Render into a buffer first so that template errors can be reported
		// with a proper status code, and so that a failing client connection
		// only affects this request.
		var buf bytes.Buffer
		if err := t.Execute(&buf, products); err != nil {
			log.Println("could not execute the template:", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if _, err := buf.WriteTo(w); err != nil {
			// The client most likely disconnected; never terminate the process.
			log.Println("could not write the response:", err)
		}
	})

	// /api/health vulnerable to shell injections
	r.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		extra := r.FormValue("extra")
		output, err := vulnerable.System(r.Context(), "ping -c1 sqreen.com"+extra)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		enc := json.NewEncoder(w)
		enc.Encode(struct {
			Output string
		}{
			Output: string(output),
		})
	})

	r.PathPrefix("/").Handler(http.FileServer(http.Dir(templateDir)))

	return r
}
