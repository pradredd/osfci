package main

import (
	"flag"
	"fmt"
	"os"
	"net/http"
	"net/url"
	"io/ioutil"
	"bytes"
	"encoding/json"
	"time"
	"strings"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
)

func main() {
	username := flag.String("username", "", "Username for the session")
	password := flag.String("password", "", "Passord for the session")
	flag.Parse()

	if *username == "" {
		fmt.Println("Error : Missing mandatory parameter username")
		flag.PrintDefaults()
		os.Exit(1)
	} else {
		if *password == "" {
			fmt.Println("Error : Missing mandatory parameter password")
			flag.PrintDefaults()
			os.Exit(1)
		}
	}

	osfciurl := "https://osfci.tech/user/"
	gettokenstring := "/getToken"
	gettokenurl := fmt.Sprintf("%s%s%s", osfciurl, *username, gettokenstring)

	//fmt.Println(gettokenurl)

	client := &http.Client{}

	data := url.Values{}
	data.Add("password", *password)

	req, err := http.NewRequest("POST", gettokenurl, bytes.NewBufferString(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		//error handling
	}

	resp, err := client.Do(req)
	if err != nil {
                //error handling
        }
	fmt.Println("\nresp.Header=",resp.Header)
	//fmt.Println("resp.Status=",resp.Status)
	//fmt.Println("Content-Type=",resp.Header.Get("Content-Type"))
	//fmt.Println("Content-Length=",resp.Header.Get("Content-Length"))
	//fmt.Println("Date=",resp.Header.Get("Date"))

	myDate := time.Now().UTC().Format(http.TimeFormat)
	myDate = strings.Replace(myDate, "GMT", "+0000", -1)

	contentType := resp.Header.Get("Content-Type")

	//cookie := resp.Header.Get("Set-Cookie")

	var cookie []*http.Cookie
	cookie = resp.Cookies()

	fmt.Println("\nmyDate=",myDate)
	fmt.Println("\ncookie=",cookie)

	defer resp.Body.Close()
	f, err := ioutil.ReadAll(resp.Body)
	if err != nil {
                //error handling
        }

	body := (string(f))

	fmt.Println("\nbody =",body)

	type token struct {
		Accesskey string
		Secretkey string
	}

	var return_data *token
	return_data =new(token)
	json.Unmarshal([]byte(body),return_data)

	accessKey := return_data.Accesskey
	secretKey := return_data.Secretkey

	fmt.Println("\nSecretKey=", secretKey)
	fmt.Println("\nAccessKey=", accessKey)

	stringToSign := "GET\n\n"+contentType+"\n"+myDate+"\n"+"/ci/getServer"

	fmt.Println("\nStringtoSign = ", stringToSign)

	mac := hmac.New(sha1.New, []byte(secretKey))
	mac.Write([]byte(stringToSign))
	expectedMAC := mac.Sum(nil)
	signature:=base64.StdEncoding.EncodeToString(expectedMAC)

	fmt.Println("\nsignature=",signature)

	authorization := "OSF"+accessKey+":"+signature
	fmt.Println("\nAuthorization = ", authorization)
	sreq, err := http.NewRequest("GET", "https://osfci.tech/ci/getServer", nil)
	if err != nil{
		//handle err
	}
	sreq.Header.Add("Host","osfci.tech")
	sreq.Header.Add("Mydate", myDate)
	sreq.Header.Add("Content-Type", contentType)
	sreq.Header.Add("Authorization", authorization)

	sresp, err := http.DefaultClient.Do(sreq)
	if err != nil {
		//handle err
	}

	fmt.Println("\nsresp.Header=",sresp.Header)
	fmt.Println("\nsresp.Status=",resp.Status)

	defer sresp.Body.Close()
	sbody,err := ioutil.ReadAll(sresp.Body)
	if err != nil {
                //handle err
        }

	fmt.Println("\nBody",string(sbody))
}
