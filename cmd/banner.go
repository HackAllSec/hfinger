package cmd

import (
    "hfinger/config"
    "github.com/fatih/color"
)

func PrintBanner() {
    banner := `
 █████         ██████   ███                                        
▒▒███         ███▒▒███ ▒▒▒                                         
 ▒███████    ▒███ ▒▒▒  ████  ████████    ███████  ██████  ████████ 
 ▒███▒▒███  ███████   ▒▒███ ▒▒███▒▒███  ███▒▒███ ███▒▒███▒▒███▒▒███
 ▒███ ▒███ ▒▒▒███▒     ▒███  ▒███ ▒███ ▒███ ▒███▒███████  ▒███ ▒▒▒ 
 ▒███ ▒███   ▒███      ▒███  ▒███ ▒███ ▒███ ▒███▒███▒▒▒   ▒███     
 ████ █████  █████     █████ ████ █████▒▒███████▒▒██████  █████    
▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒     ▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒  ▒▒▒▒▒███ ▒▒▒▒▒▒  ▒▒▒▒▒     
                                        ███ ▒███                   
                                       ▒▒██████                    
                                        ▒▒▒▒▒▒                     ` + config.Version + ` By:Hack All Sec

`
    color.Green(banner)
}
