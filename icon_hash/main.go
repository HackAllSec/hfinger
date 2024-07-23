package main

import (
    "flag"
    "fmt"
    "io/ioutil"
    "crypto/tls"
    "net/http"
    "hfinger/models"
)

func main() {
    url := flag.String("u", "", "The URL to process.")
    base64data := flag.String("i", "", "The base64 data of favicon.")
    flag.Usage = func() {
        fmt.Println("Usage:")
        fmt.Println("    icon_hash -u <URL>")
        flag.PrintDefaults()
        fmt.Println("Example:")
        fmt.Println("    icon_hash -u https://www.example.com/favicon.ico")
    }

    flag.Parse()

    if *url == "" && *base64data == ""{
        flag.Usage()
        return
    }
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true,
            },
        },
    }

    if *url != "" {
        resp, err := client.Get(*url)
        if err != nil {
            fmt.Printf("[!] Error: %v",err)
        }
        defer resp.Body.Close()
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            fmt.Printf("[!] Error: %v",err)
        }
        icon_hash := models.Mmh3Hash32(models.StandBase64(body))
        fmt.Println("[+]The icon_hash is:",icon_hash)
    }
    if *base64data != "" {
        icondata := []byte(*base64data)
        icon_hash := models.Mmh3Hash32(icondata)
        fmt.Println("[+]The icon_hash is:",icon_hash)
    }
    
}
