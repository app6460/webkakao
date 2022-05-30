package webkakao

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
)

var (
	csrfReg, _   = regexp.Compile("csrf-token\" content=\"(.+)\"")
	cryptoReg, _ = regexp.Compile("name=\"p\" value=\"(.+)\"")
)

type (
	kakao struct {
		email       string
		password    string
		serviceURL  string
		cookies     []*http.Cookie
		csrf        string
		cryptoToken string
		referer     *url.URL
	}

	authRes struct {
		Status      int    `json:"status"`
		Message     string `json:"message"`
		ContinueURL string `json:"continue_url"`
	}
)

func (k *kakao) getloginRes() {
	param := url.Values{}
	param.Add("continue", k.serviceURL)
	res, err := http.Get("https://accounts.kakao.com/login?" + param.Encode())

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(res.Body)
	body := string(bodyBytes)
	csrf := csrfReg.FindStringSubmatch(body)
	crypto := cryptoReg.FindStringSubmatch(body)

	k.csrf = csrf[1]
	k.cryptoToken = crypto[1]
	k.cookies = append(k.cookies, res.Cookies()...)
	k.referer = res.Request.URL
}

func (k *kakao) getTiara() {
	res, err := http.Get(getTiaraUrl())

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	k.cookies = append(k.cookies, res.Cookies()...)
}

func (k *kakao) pad(data []byte) []byte {
	length := 16 - len(data)%16
	var b bytes.Buffer
	b.Write(data)
	b.Write(bytes.Repeat([]byte{byte(length)}, length))
	return b.Bytes()
}

func (k *kakao) bytesToKey(data, salt []byte, output int) ([]byte, []byte) {
	key := make([]byte, 0)
	finalKey := make([]byte, 0)
	for len(finalKey) < output {
		var b bytes.Buffer
		b.Write(key)
		b.Write(data)
		b.Write(salt)
		sum := md5.Sum(b.Bytes())
		key = sum[:]
		finalKey = append(finalKey, key...)
	}
	return finalKey[:32], finalKey[32:output]
}

func (k *kakao) AESEncrypt(message, passphrase string) string {
	salt := make([]byte, 8)
	rand.Read(salt)

	key, iv := k.bytesToKey([]byte(passphrase), salt, 48)
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}
	msg := k.pad([]byte(message))
	res := make([]byte, len(msg))

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(res, msg)

	var b bytes.Buffer
	b.Write([]byte("Salted__"))
	b.Write(salt)
	b.Write(res)
	return base64.StdEncoding.EncodeToString(b.Bytes())
}

func (k *kakao) getAuth() authRes {
	email := k.AESEncrypt(k.email, k.cryptoToken)
	pass := k.AESEncrypt(k.password, k.cryptoToken)

	data := url.Values{}
	data.Add("k", "true")
	data.Add("os", "web")
	data.Add("lang", "ko")
	data.Add("email", email)
	data.Add("password", pass)
	data.Add("webview_v", "2")
	data.Add("third", "false")
	data.Add("authenticity_token", k.csrf)
	data.Add("continue", k.serviceURL)

	req, _ := http.NewRequest("POST", "https://accounts.kakao.com/weblogin/authenticate.json", bytes.NewBuffer([]byte(data.Encode())))

	for _, v := range k.cookies {
		req.AddCookie(v)
	}

	req.Header.Add("Referer", k.referer.String())

	client := &http.Client{}
	res, err := client.Do(req)

	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	k.cookies = append(k.cookies, res.Cookies()...)

	body, _ := ioutil.ReadAll(res.Body)
	auth := authRes{}
	json.Unmarshal(body, &auth)

	return auth
}

func (k *kakao) Cookies() []*http.Cookie {
	return k.cookies
}

func (k *kakao) Referer() *url.URL {
	return k.referer
}

func New(email, pass, serviceURL string) *kakao {
	instance := kakao{}
	instance.email = email
	instance.password = pass
	instance.serviceURL = serviceURL
	return &instance
}

func (k *kakao) Login() authRes {
	k.getloginRes()
	k.getTiara()
	return k.getAuth()
}
