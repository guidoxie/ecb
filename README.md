## ECB encryption and decryption in Go
ECB mode has security vulnerabilities and is not recommended for use, so the Go standard library does not include ECB by default.
* The padding mode used by this library is PKCS7Padding.

### Encryption Example
```
package main

import (
	"encoding/base64"
	"fmt"
	"github.com/guidoxie/ecb"
)

func main() {
	key := []byte("1234567890123456")
	encrypter, err := ecb.NewEncrypter(key)
	if err != nil {
		panic(err)
	}
	plaintext := []byte("hello")            
	cipherText := encrypter.Encrypt(plaintext) 
	// Output: 67fHA+Z12z2jlwOLTBeCPA==
	fmt.Println(base64.StdEncoding.EncodeToString(cipherText))
}
```

### Decryption Example
```
package main

import (
	"encoding/base64"
	"fmt"
	"github.com/guidoxie/ecb"
)

func main() {
	key := []byte("1234567890123456")
	decrypter, err := ecb.NewDecrypter(key)
	if err != nil {
		panic(err)
	}
	cipherText, err := base64.StdEncoding.DecodeString("67fHA+Z12z2jlwOLTBeCPA==") 
	if err != nil {
		panic(err)
	}
	plaintext := decrypter.Decrypt(cipherText) 
	// Output: hello
	fmt.Println(string(plaintext))
}
```


