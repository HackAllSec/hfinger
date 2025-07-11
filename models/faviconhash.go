package models

import (
    "bytes"
    "encoding/base64"
    "errors"
    "fmt"
    "github.com/sirupsen/logrus"
    "github.com/twmb/murmur3"
    "github.com/vincent-petithory/dataurl"
    "golang.org/x/net/html"
    "golang.org/x/net/html/atom"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
)

// mmh3Hash32 generate icon hash
func mmh3Hash32(raw []byte) string {
    bckd := base64.StdEncoding.EncodeToString(raw)
    var buffer bytes.Buffer
    for i := 0; i < len(bckd); i++ {
        ch := bckd[i]
        buffer.WriteByte(ch)
        if (i+1)%76 == 0 {
            buffer.WriteByte('\n')
        }
    }
    buffer.WriteByte('\n')
    return fmt.Sprintf("%d", int32(murmur3.Sum32(buffer.Bytes())))
}

func isImageContent(contentType string) bool {
    if strings.HasPrefix(contentType, "image/") {
        return true
    }
    return false
}

// fileIconHash local file hash
func fileIconHash(url string) (hash string, err error) {
    var data []byte

    logrus.Debug("load local file:", url)

    data, err = os.ReadFile(url)
    if err != nil {
        return
    }

    ct := http.DetectContentType(data)
    logrus.Debug("local file format:", ct)

    if isImageContent(ct) {
        hash = mmh3Hash32(data)
    } else {
        err = errors.New("content is not a image")
        return
    }

    return
}

// fetchURLContent fetch content and type from url
func fetchURLContent(iconUrl string) (data []byte, contentType string, err error) {
    // fetch url
    var resp *http.Response
    resp, err = http.Get(iconUrl)
    if err != nil {
        return
    }

    // read data
    defer resp.Body.Close()
    data, err = io.ReadAll(resp.Body)
    if err != nil {
        return
    }

    // check content type by header
    contentType = resp.Header.Get("Content-type")
    if len(contentType) > 0 {
        return
    }

    // check content type by data
    contentType = http.DetectContentType(data)
    return
}

// ExtractIconFromHtml extract link icon from html
func ExtractIconFromHtml(data []byte) string {
    r := bytes.NewReader(data)
    z := html.NewTokenizer(r)

tokenize:
    for {
        tt := z.Next()

        var href string
        var isIconLink bool

        switch tt {
        case html.ErrorToken:
            // End of the document, we're done
            return ""
        case html.StartTagToken, html.SelfClosingTagToken:
            name, hasAttr := z.TagName()
            if atom.Link == atom.Lookup(name) {
                for hasAttr {
                    var k, v []byte
                    k, v, hasAttr = z.TagAttr()
                    switch string(k) {
                    case "rel":
                        cs := strings.Split(strings.ToLower(string(v)), " ")
                        for _, c := range cs {
                            if strings.EqualFold(c, "icon") {
                                isIconLink = true
                                break
                            }
                        }

                        if !isIconLink {
                            continue tokenize
                        }
                    case "href":
                        href = string(v)
                    }
                }
            }
        }
        if isIconLink && href != "" {
            return href
        }
    }
}

// IconHash
// if url is a local icon file, then calc the hash
// if url is remote icon url, the download and calc the hash
// if url is web homepage, then try to parse favicon url and download it, then calc the hash
func IconHash(iconUrl string) (hash string, err error) {
    // check if local file
    _, err = os.Stat(iconUrl)
    if err == nil {
        // 存在
        return fileIconHash(iconUrl)
    }
    //// 还有不存在的错误？
    //if !errors.Is(err, os.ErrNotExist) {
    //    return
    //}

    if !strings.Contains(iconUrl, "://") {
        err = errors.New("icon url is not valid url")
        return
    }
    var u *url.URL
    u, err = url.Parse(iconUrl)
    if err != nil {
        return
    }

    // remote url
    var data []byte
    var contentType string
    data, contentType, err = fetchURLContent(iconUrl)
    if isImageContent(contentType) {
        hash = mmh3Hash32(data)
        return
    }

    // parse icon url
    var parsedURL string
    if strings.Contains(contentType, "html") {
        logrus.Debug("try to parse favicon url")
        parsedURL = ExtractIconFromHtml(data)
    }

    if len(parsedURL) > 0 {
        logrus.Debug("parsed favicon url from html:", parsedURL)

        // inner base64
        if strings.HasPrefix(parsedURL, "data:image") {
            var dataURL *dataurl.DataURL
            dataURL, err = dataurl.DecodeString(parsedURL)
            if err != nil {
                return
            }
            if isImageContent(dataURL.MediaType.ContentType()) {
                hash = mmh3Hash32(dataURL.Data)
                return
            }
        }

        if rel, errP := url.Parse(parsedURL); errP == nil {
            newURL := u.ResolveReference(rel)
            data, contentType, err = fetchURLContent(newURL.String())
            if isImageContent(contentType) {
                hash = mmh3Hash32(data)
                return
            }
        } else {
            logrus.Debug("parsed favicon url is not valid:", errP)
        }
    }

    // just try default favicon.ico
    logrus.Debug("try default favicon.ico")
    defaultIconURL := u.Scheme + "://" + u.Host + "/favicon.ico"
    data, contentType, err = fetchURLContent(defaultIconURL)
    if isImageContent(contentType) {
        hash = mmh3Hash32(data)
        return
    }

    err = errors.New("can not find any icon")
    return
}
