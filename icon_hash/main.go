package main

import (
    "flag"
    "fmt"

    "hfinger/models"
)

func main() {
    url := flag.String("u", "", "The Target icon file, example: url, localfile.")
    flag.Usage = func() {
        fmt.Println("Usage:")
        fmt.Println("    icon_hash -u <Target>")
        flag.PrintDefaults()
        fmt.Println("Example:")
        fmt.Println("    icon_hash -u https://www.example.com/favicon.ico")
        fmt.Println("    icon_hash -u favicon.ico")
        fmt.Println("    icon_hash -u https://www.example.com/login")
    }

    flag.Parse()

    if *url == ""{
        flag.Usage()
        return
    }

    if *url != "" {
        icon_hash, err := models.IconHash(*url)
        if err != nil {
            fmt.Println(err.Error())
        }
        fmt.Println("[+]The icon_hash is:",icon_hash)
    }
}
