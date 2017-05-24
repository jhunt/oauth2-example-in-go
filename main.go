package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

const (
	GithubScope = "read:org"
)

type Config struct {
	MyURL string `json:"my_url"`

	/* Github Client ID and Secret, from the OAuth2 App Registration screen
	   (https://github.com/settings/applications/new)
	*/
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	AuthorizeURL string `json:"authorize_url"`
	TokenURL     string `json:"token_url"`
}

func RandomString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func main() {
	var config Config
	states := make(map[string]bool)
	sessions := make(map[string]string)

	b, err := ioutil.ReadFile("config.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed reading config.json: %s\n", err)
		os.Exit(1)
	}

	err = json.Unmarshal(b, &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed parsing config.json: %s\n", err)
		os.Exit(1)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		b, _ := httputil.DumpRequest(req, true)
		fmt.Fprintf(os.Stderr, "%s\n\n\n", string(b))

		/* when the user gets here, they have no tokens or
		   authenticated sessions, and no authorizations. */

		/* generate and store a new state, so that we can verify
		   the authorization callback */
		state, err := RandomString(16)
		if err != nil {
			panic(err)
		}
		states[state] = true

		/* redirect them to the Provider URL with an appropriate
		   Authorization Request for access_token */
		where, err := url.Parse(config.AuthorizeURL)
		if err != nil {
			panic(err)
		}
		q := where.Query()
		q.Set("response_type", "code")
		q.Set("client_id", config.ClientID)
		q.Set("redirect_uri", fmt.Sprintf("%s/oauth2/callback", config.MyURL))
		q.Set("state", state)
		q.Set("scope", GithubScope)
		where.RawQuery = q.Encode()

		fmt.Fprintf(os.Stderr, "HTTP/1.1 302 Found\n")
		fmt.Fprintf(os.Stderr, "Location: %s\n\n", where)
		http.Redirect(w, req, where.String(), 302)
	})

	http.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, req *http.Request) {
		b, _ := httputil.DumpRequest(req, true)
		fmt.Fprintf(os.Stderr, "%s\n\n\n", string(b))

		state := req.URL.Query().Get("state")
		if good, ready := states[state]; !good || !ready {
			w.WriteHeader(400)
			fmt.Fprintf(os.Stderr, "martian state value; ignoring.\n")
			return
		}

		/* go make a request to github to get the access token */
		body := url.Values{}
		body.Set("client_id", config.ClientID)
		body.Set("client_secret", config.ClientSecret)
		body.Set("code", req.URL.Query().Get("code"))
		body.Set("state", state)
		body.Set("redirect_uri", config.MyURL+"/ok")
		ghreq, _ := http.NewRequest("POST", config.TokenURL, bytes.NewBufferString(body.Encode()))
		ghreq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		ghreq.Header.Add("Content-Length", fmt.Sprintf("%d", len(body.Encode())))

		b, _ = httputil.DumpRequest(ghreq, true)
		fmt.Fprintf(os.Stderr, "me -> github:\n%s\n\n\n", string(b))

		client := &http.Client{}
		ghres, err := client.Do(ghreq)
		if err != nil {
			panic(err)
		}

		b, _ = httputil.DumpResponse(ghres, true)
		fmt.Fprintf(os.Stderr, "github -> me:\n%s\n\n\n", string(b))

		b, err = ioutil.ReadAll(ghres.Body)
		if err != nil {
			panic(err)
		}
		tokens, err := url.ParseQuery(string(b))
		if err != nil {
			panic(err)
		}

		session, _ := RandomString(64)
		sessions[session] = tokens.Get("access_token")

		fmt.Fprintf(os.Stderr, "setting access token %s for session %s\n", sessions[session], session)
		fmt.Fprintf(os.Stderr, "setting authyo cookie to %s\n", session)
		http.SetCookie(w, &http.Cookie{
			Name:     "authyo",
			Value:    session,
			Path:     "/",
			HttpOnly: true,
		})
		w.WriteHeader(200)
		fmt.Fprintf(w, "yay!\n")
	})

	http.HandleFunc("/ok", func(w http.ResponseWriter, req *http.Request) {
		b, _ := httputil.DumpRequest(req, true)
		fmt.Fprintf(os.Stderr, "%s\n\n\n", string(b))

		cookie, err := req.Cookie("authyo")
		if err != nil {
			w.WriteHeader(401)
			fmt.Fprintf(w, "no cookie sent\n")
			return
		}

		if _, ok := sessions[cookie.Value]; !ok {
			w.WriteHeader(401)
			fmt.Fprintf(w, "session expired\n")
			return
		}

		w.WriteHeader(200)
		fmt.Fprintf(w, "auth*ed\n")
		fmt.Fprintf(os.Stderr, "session %s = access token %s\n", cookie.Value, sessions[cookie.Value])
	})

	fmt.Printf("listening on http://127.0.0.1:8080\n")
	http.ListenAndServe("127.0.0.1:8080", nil)
}
