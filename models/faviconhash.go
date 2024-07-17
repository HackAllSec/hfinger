package models

import (
    "bytes"
    "encoding/base64"
    "hash"

    "github.com/twmb/murmur3"
)

func Mmh3Hash32(raw []byte) int32 {
    var h32 hash.Hash32 = murmur3.New32()
    _, err := h32.Write(raw)
    if err == nil {
        return int32(h32.Sum32())
    } else {
        return 0
    }
}

func StandBase64(braw []byte) []byte {
    bckd := base64.StdEncoding.EncodeToString(braw)
    var buffer bytes.Buffer
    for i := 0; i < len(bckd); i++ {
        ch := bckd[i]
        buffer.WriteByte(ch)
        if (i+1)%76 == 0 {
            buffer.WriteByte('\n')
        }
    }
    buffer.WriteByte('\n')
    return buffer.Bytes()
}
