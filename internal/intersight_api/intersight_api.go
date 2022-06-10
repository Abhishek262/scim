package scim

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ApiKey        string
	SecretKeyFile string
	Endpoint      string
}

// getComputedDigest accepts json in bytes format
// Returns an encoded form of the json using sha256 hash algorithm.
func getComputedDigest(jsonPayload []byte) string {
	newpayload := []byte(string(jsonPayload))
	digest := sha256.New()
	digest.Write(newpayload)
	finalDigest := "SHA-256=" + base64.StdEncoding.EncodeToString(digest.Sum(nil))
	log.Println("Payload digest", finalDigest)
	return finalDigest
}

// readPrivateKey reads RSA PRIVATE FROM a file, parses and returns an object of rsa PrivateKey
func readPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.Open(filePath)
	if err != nil {
		log.Printf("failed to open secret key file: %s\n", err)
		return nil, err
	}
	privateKey, err := ioutil.ReadAll(privateKeyFile)
	if err != nil {
		log.Printf("failed to read secret key: %s\n", err)
		return nil, err
	}
	err = privateKeyFile.Close()
	if err != nil {
		log.Println("failed while closing file: ", err)
		return nil, err
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		log.Println("failed to parse PEM block containing the public key")
		return nil, err
	}
	privateKeyParsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("failed to parse DER encoded public key: " + err.Error())
	}
	return privateKeyParsed, nil
}

// method will be POST, GET, PATCH or DELETE
// target url is the request endpoint e.g. /api/v1/sol/Policies
// return authorization header content and current date if no error occurred, else empty string
func (s *Config) getHTTPSign(method string, targetPath string, digest string) (string, string, error) {
	privateKey, err := readPrivateKey(s.SecretKeyFile)
	if err != nil {
		return "", "", err
	}
	//currentDate := strings.Replace(time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC1123), "UTC", "GMT", -1)
	currentDate := strings.Replace(time.Now().UTC().Format(time.RFC1123), "UTC", "GMT", -1)
	host := strings.TrimPrefix(strings.TrimPrefix(s.Endpoint, "https://"), "http://")
	lStringToSign := "(request-target): " + strings.ToLower(method) + " " + strings.ToLower(targetPath) + "\ncontent-type: application/json\ndate: " + currentDate + "\ndigest: " + digest + "\nhost: " + host
	h := sha256.New()
	_, shaerr := h.Write([]byte(lStringToSign))
	if shaerr != nil {
		return "", "", shaerr
	}
	hashed := h.Sum(nil)

	rng := rand.Reader
	signature, signerr := rsa.SignPKCS1v15(rng, privateKey, crypto.SHA256, hashed[:])
	if signerr != nil {
		return "", "", signerr
	}
	encSignature := base64.StdEncoding.EncodeToString(signature)
	authorisationHeader := fmt.Sprintf(`Signature keyId="%s",algorithm="rsa-sha256",headers="(request-target) content-type date digest host",signature="%s"`, s.ApiKey, encSignature)
	return authorisationHeader, currentDate, nil
}

//SendRequest accepts url and payload json. Sends a POST request.
func (s *Config) SendRequest(url string, data []byte) ([]byte, error) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	//log.Println("URL:>", s.Endpoint+"/api/v1/"+url)
	log.Println("URL:>", s.Endpoint+"/"+url)

	payloadBytes, err := sanitizeJson(data)
	if err != nil {
		log.Printf("error in sanitizing data. error: %s", err.Error())
		return []byte(""), err
	}
	digest := getComputedDigest(payloadBytes)
	authorizationHeader, currentDate, authErr := s.getHTTPSign(http.MethodPost, "/"+url, digest)
	if authErr != nil {
		panic(authErr)
	}
	req, err := http.NewRequest(http.MethodPost, s.Endpoint+"/"+url, bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Digest", digest)
	req.Header.Set("Origin", s.Endpoint)
	req.Header.Set("Authorization", authorizationHeader)
	req.Header.Set("Date", currentDate)

	log.Println("===========>", string(payloadBytes))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()

	log.Println("response Status:", resp.Status)
	log.Println("response Headers:", resp.Header)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}
	log.Println("response Body:", string(body))
	if resp.StatusCode != http.StatusOK {
		log.Println("response Status:", resp.Status)
		log.Println("response Headers:", resp.Header)
		return body, fmt.Errorf("SendRequest failed. Url %s Status Code: %d Message: %v", url, resp.StatusCode, string(body))
	}
	return body, nil
}

func (s *Config) SendDeleteRequest(url string) ([]byte, error) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("URL:>", s.Endpoint+"/"+url)

	authorizationHeader, currentDate, authErr := s.getHTTPSign(http.MethodDelete, "/"+url, getComputedDigest([]byte("")))
	if authErr != nil {
		panic(authErr)
	}
	req, err := http.NewRequest(http.MethodDelete, s.Endpoint+"/"+url, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Digest", getComputedDigest([]byte("")))
	req.Header.Set("Origin", s.Endpoint)
	req.Header.Set("Authorization", authorizationHeader)
	req.Header.Set("Date", currentDate)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()

	log.Println("response Status:", resp.Status)
	log.Println("response Headers:", resp.Header)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}

	log.Println("response Body:", string(body))
	if resp.StatusCode != http.StatusOK {
		log.Println("response Status:", resp.Status)
		log.Println("response Headers:", resp.Header)
		return body, fmt.Errorf("SendDeleteRequest failed. Url %s Status Code: %d Message: %v", url, resp.StatusCode, string(body))
	}

	return body, nil
}

func (s *Config) SendUpdateRequest(url string, data []byte) ([]byte, error) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("URL:>", s.Endpoint+"/"+url)

	payloadBytes, err := sanitizeJson(data)
	if err != nil {
		log.Printf("error in sanitizing data. error: %s", err.Error())
		return []byte(""), err
	}
	digest := getComputedDigest(payloadBytes)
	authorizationHeader, currentDate, authErr := s.getHTTPSign(http.MethodPatch, "/"+url, digest)
	if authErr != nil {
		panic(authErr)
	}
	req, err := http.NewRequest(http.MethodPost, s.Endpoint+"/"+url, bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Digest", digest)
	req.Header.Set("Origin", s.Endpoint)
	req.Header.Set("Authorization", authorizationHeader)
	req.Header.Set("Date", currentDate)

	log.Println("===========>", string(payloadBytes))
	log.Printf("Request %+v\n", req)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}

	log.Println("response Body:", string(body))
	if resp.StatusCode != http.StatusOK {
		log.Println("response Status:", resp.Status)
		log.Println("response Headers:", resp.Header)
		return body, fmt.Errorf("SendUpdateRequest failed. Url %s Status Code: %d Message: %v", url, resp.StatusCode, string(body))
	}

	return body, nil
}

//

func (s *Config) SendPostRequest(url string, data []byte) ([]byte, error) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("SendGetRequest URL:>", s.Endpoint+"/"+url)

	convData := bytes.NewReader(data)
	req, err := http.NewRequest(http.MethodPost, s.Endpoint+"/"+url, convData)

	if err != nil {
		return []byte(""), err
	}
	targetURL := strings.TrimPrefix(req.URL.String(), s.Endpoint)
	log.Println("get data source URL", targetURL)
	digest := getComputedDigest(data)
	authorizationHeader, currentDate, authErr := s.getHTTPSign(http.MethodPost, targetURL, digest)
	if authErr != nil {
		panic(authErr)
	}
	if authErr != nil {
		panic(authErr)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Digest", digest)
	req.Header.Set("Origin", s.Endpoint)
	req.Header.Set("Authorization", authorizationHeader)
	req.Header.Set("Date", currentDate)
	log.Printf("Request url : %+v", req.URL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()
	log.Println("request :", req.Header)
	log.Println("response Status:", resp.Status)
	log.Println("response Headers:", resp.Header)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}

	log.Println("response Body:", string(body))
	if resp.StatusCode != http.StatusOK {
		log.Println("response Status:", resp.Status)
		log.Println("response Headers:", resp.Header)
		return body, fmt.Errorf("SendGetRequest failed. Url %s Status Code: %d Message: %v", url, resp.StatusCode, string(body))
	}

	return body, nil
}

// // SendGetRequest sends Get request to appliance with or without payload
// func (s *Config) SendGetRequest(url string, data []byte) ([]byte, error) {
// 	log.SetFlags(log.LstdFlags | log.Lshortfile)
// 	log.Println("SendGetRequest URL:>", s.Endpoint+"/"+url)
// 	var err error
// 	req, err := http.NewRequest(http.MethodGet, s.Endpoint+"/"+url, nil)
// 	if err != nil {
// 		return []byte(""), err
// 	}
// 	// add GET request query, if exists
// 	payloadBytes := []byte("")
// 	if string(data) != "" {
// 		data, err = sanitizeJson(data)
// 		if err != nil {
// 			log.Printf("error in sanitizing data. error: %s", err.Error())
// 			return []byte(""), err
// 		}
// 		req.URL.RawQuery = "$filter=" + (&u.URL{Path: getRequestParams(data)}).String()
// 	}
// 	targetURL := strings.TrimPrefix(req.URL.String(), s.Endpoint)
// 	log.Println("get data source URL", targetURL)
// 	digest := getComputedDigest(payloadBytes)
// 	authorizationHeader, currentDate, authErr := s.getHTTPSign(http.MethodGet, targetURL, digest)
// 	if authErr != nil {
// 		panic(authErr)
// 	}
// 	req.Header.Set("Content-Type", "application/json")
// 	req.Header.Set("Digest", digest)
// 	req.Header.Set("Origin", s.Endpoint)
// 	req.Header.Set("Authorization", authorizationHeader)
// 	req.Header.Set("Date", currentDate)

// 	log.Printf("Request url : %+v", req.URL)
// 	tr := &http.Transport{
// 		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
// 	}

// 	client := &http.Client{Transport: tr}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer func() { _ = resp.Body.Close() }()
// 	log.Println("request :", req.Header)
// 	log.Println("response Status:", resp.Status)
// 	log.Println("response Headers:", resp.Header)
// 	body, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return body, err
// 	}

// 	log.Println("response Body:", string(body))
// 	if resp.StatusCode != http.StatusOK {
// 		log.Println("response Status:", resp.Status)
// 		log.Println("response Headers:", resp.Header)
// 		return body, fmt.Errorf("SendGetRequest failed. Url %s Status Code: %d Message: %v", url, resp.StatusCode, string(body))
// 	}

// 	return body, nil
// }

// SendGetRequest sends Get request to appliance with or without payload
func (s *Config) SendGetRequest(url string, data []byte) ([]byte, error) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("SendGetRequest URL:>", s.Endpoint+"/"+url)
	var err error
	req, err := http.NewRequest(http.MethodGet, s.Endpoint+"/"+url, nil)
	if err != nil {
		return []byte(""), err
	}

	targetURL := strings.TrimPrefix(req.URL.String(), s.Endpoint)
	log.Println("get data source URL", targetURL)
	digest := getComputedDigest([]byte(""))
	authorizationHeader, currentDate, authErr := s.getHTTPSign(http.MethodGet, targetURL, digest)
	if authErr != nil {
		panic(authErr)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Digest", digest)
	req.Header.Set("Origin", s.Endpoint)
	req.Header.Set("Authorization", authorizationHeader)
	req.Header.Set("Date", currentDate)

	log.Printf("Request url : %+v", req.URL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func() { _ = resp.Body.Close() }()
	log.Println("request :", req.Header)
	log.Println("response Status:", resp.Status)
	log.Println("response Headers:", resp.Header)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}

	log.Println("response Body:", string(body))
	if resp.StatusCode != http.StatusOK {
		log.Println("response Status:", resp.Status)
		log.Println("response Headers:", resp.Header)
		return body, fmt.Errorf("SendGetRequest failed. Url %s Status Code: %d Message: %v", url, resp.StatusCode, string(body))
	}

	return body, nil
}
func sanitizeJson(in []byte) ([]byte, error) {
	log.Println("Data to be sanitized", string(in))
	var s map[string]interface{}
	err := json.Unmarshal(in, &s)
	if err != nil {
		return []byte(""), err
	}

	readOnlyProps := []string{
		"Ancestors",
		"CreateTime",
		"ModTime",
		"ReleaseTime",
		"ReleaseDate",
		"ImportedTime",
		"LastAccessTime",
		"Owners",
		"ConfigChangeDetails",
		"RunningWorkflows",
		"TimeZone",
		"CleanupTime",
		"EndTime",
		"StartTime",
	}
	for k, v := range s {
		if v == nil || v == "" {
			delete(s, k)
			continue
		}
		for _, p := range readOnlyProps {
			if k == p {
				delete(s, k)
			}
		}
	}
	b, err := json.Marshal(s)
	if err == nil {
		b = bytes.Replace(b, []byte("\\u003c"), []byte("<"), -1)
		b = bytes.Replace(b, []byte("\\u003e"), []byte(">"), -1)
		b = bytes.Replace(b, []byte("\\u0026"), []byte("&"), -1)
	}
	log.Println("Sanitized data", string(b))
	return b, err
}

func getRequestParams(in []byte) string {
	var o string
	var s map[string]interface{}
	err := json.Unmarshal(in, &s)
	if err != nil {
		return ""
	}
	for k, v := range s {
		log.Printf("Type: %+v", reflect.TypeOf(v).Kind())
		switch reflect.TypeOf(v).Kind() {
		case reflect.String:
			o += k + " eq '" + v.(string) + "'"
		case reflect.Bool:
			o += k + " eq " + strconv.FormatBool(v.(bool))
		case reflect.Int:
			o += k + " eq " + strconv.FormatInt(v.(int64), 10)
		case reflect.Float64:
			o += k + " eq " + fmt.Sprintf("%f", v.(float64))
		}
		o += " and "
	}
	o = strings.TrimSuffix(o, " and ")
	return o
}

func GetDefaultConfig() Config {
	c := Config{

		SecretKeyFile: "SecretKey.txt",
		//ApiKey:        "5c1b273a7564612d3088996a/625411267564612d3371b5be/625416347564612d3371b78b", //ritmanda-qa cloud
		ApiKey: "624d786e7564612d33e68ff0/624d786e7564612d33e68ff4/62541aff7564612d30efcc66", //ritmanda
		// Url of the cloud/appliance
		Endpoint: "https://cicdtest.starshipcloud.com",
		//Endpoint:      "https://vaiapp.cisco.com",
	}
	return c
}

// func main() {
// 	c := GetDefaultConfig()
/*data := []byte(`{
"module": "API",
"method": "Live.getLastVisitsDetails" ,
"idSite" : "1"
}`)*/
/*data := []byte(`{"Idpreference":{"ObjectType":"iam.IdpReference","Moid":"61f925c37564612d33f18259"},"UserIdOrEmail":"abc2@gmail.com","Permissions":[{"ObjectType":"iam.Permission","Moid":"61f925c47564612d33f18265"}]}`)
lBody, err := c.SendUpdateRequest("api/v1/iam/Users", data)
fmt.Println(err)
fmt.Println(string(lBody))*/

/// delete request
// lBody, err := c.SendDeleteRequest("api/v1/iam/Users/624d786e7564612d33e68ff8")
// fmt.Println(err)
// fmt.Println(err)
// fmt.Println(string(lBody))

//// create user request

// jsonStr := []byte(`{"Idpreference":{"ObjectType":"iam.IdpReference",
// "Moid":"624d786e7564612d33e68ff3"},"UserIdOrEmail":"test@test.com",
// "Permissions":[{"ObjectType":"iam.Permission","Moid":"624d786e7564612d33e68ff8"}]}`)

// lBody, err := c.SendPostRequest("api/v1/iam/Users", jsonStr)
// fmt.Println(err)
// fmt.Println(string(lBody))

//update permissions

// jsonStr := []byte(`{"UserIdOrEmail":"test@test.com",
// "Permissions":[{"ObjectType":"iam.Permission",
// "Moid":"624d786f7564612d33e68ffd"}]}`)

// lBody, err := c.SendPostRequest("api/v1/iam/Users/6266483a7564612d30c9de77", jsonStr)
// fmt.Println(err)
// fmt.Println(string(lBody))

//get with filter
// 	data := []byte(`{}`)
// 	lBody, err := c.SendGetRequest("api/v1/iam/Users?$filter=Email%20eq%20%27test@test.com%27&$select=Moid", data)
// 	fmt.Println(err)
// 	fmt.Println(err)
// 	fmt.Println(string(lBody))

// }
