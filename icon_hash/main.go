package main

import (
    "flag"
    "fmt"
    "io/ioutil"
    "hfinger/utils"
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

    if *url != "" {
        resp, _ := utils.Get(*url)
        defer resp.Body.Close()
        body, _ := ioutil.ReadAll(resp.Body)
        icon_hash := models.Mmh3Hash32(models.StandBase64(body))
        fmt.Sprintf("[+]The icon_hash is: %d",icon_hash)
    }
    if *base64data != "" {
        icondata := []byte(*base64data)
        icon_hash := models.Mmh3Hash32(icondata)
        fmt.Sprintf("[+]The icon_hash is: %d",icon_hash)
    }
    
}
