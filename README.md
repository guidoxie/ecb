## AES-ECB加解密实现
ECB模式存在安全隐患，不建议使用，所以go语言没有内置ECB
* 该库使用的填充模式为PKCS7Padding

### 加密示例
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
	plainText := []byte("hello")            // 明文
	cipherText := encrypter.Encrypt(plainText) // 密文
	// Output: 67fHA+Z12z2jlwOLTBeCPA==
	fmt.Println(base64.StdEncoding.EncodeToString(cipherText))
}
```

### 解密示例
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
	cipherText, err := base64.StdEncoding.DecodeString("67fHA+Z12z2jlwOLTBeCPA==") // 密文
	if err != nil {
		panic(err)
	}
	plainText := decrypter.Decrypt(cipherText) // 明文
	// Output: hello
	fmt.Println(string(plainText))
}
```


