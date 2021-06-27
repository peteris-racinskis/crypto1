## crypto1 - cryptography homework. Wrapper for AES encryption and hand rolled block chaining modes.

### How it works

The .NET core cryptographic library is used for ECB encryption of individual message blocks, while the AESHandler class takes care of the rest - block chaining, parsing, padding, the XOR operations, etc. Yes, I know, the methods can be refactored to be more DRY, but every time I refactor something, something breaks, and dealing with this takes time.

### How to use it

1. Download one of the archived [binary distributions available here](https://github.com/peteris-racinskis/crypto1/releases/tag/v2.0) (the .NET core 5.0 runtime is packaged inside, which is the whole reason why I went with .NET over Python - but this makes the distributions fairly large), extract it somewhere;
2. Navigate to the root directory of the application where the **crypto1** executable file and **launcher.sh** is located
3. Make sure these files have exec privileges and the launch script has the correct shebang.

**The script allows one to quickly go through an example use case for all commands one by one**

```
# To demonstrate key generation, execute: (order irrelevant)
# ./launcher.sh cbc-encrypt-nokey
# ./launcher.sh cfb-encrypt-nokey
#
# For cbc pipeline, execute in order:
# ./launcher.sh cbc-encrypt
#  ^-- inspect results in outputs/
# ./launcher cbc-decrypt
#  ^-- inspect.sh results in outputs/
#
# For cfb pipeline, execute in order:
# ./launcher.sh cfb-encrypt
#  ^-- inspect results in outputs/
# ./launcher.sh cfb-decrypt
#  ^-- inspect results in outputs/
```

### Usage

**NOTE: the output file base path is always specified with the shared --outfile option**

```
crypto1
  AES encryptor/decryptor. Inputs MUST be at least 1 block in length!

Usage:
  crypto1 [options] [command]

Options:
  --cfb                use CFB rather than CBC chaining
  --outfile <outfile>  base file path ($.bin/$.token/.. added automatically)
  --version            Show version information
  -?, -h, --help       Show help and usage information

Commands:
  encrypt <plaintext>             AES encrypt the string
  decrypt <ciphertext> <key-dec>  AES decrypt the string [default: ./encrypted.bin]
```

### Commands

**Encrypt**: encrypt a file using AES and one of the two possible block chaining moddes: cbc/cfb. *All inputs are filesystem paths rather than literals*.

```
encrypt
  AES encrypt the string

Usage:
  crypto1 [options] encrypt <plaintext>

Arguments:
  <plaintext>  path to file to encrypt

Options:
  --key-enc <key-enc>  (optional) encryption key [default: ]
  --key-sig <key-sig>  (optional) signature key [default: ]
  -?, -h, --help       Show help and usage information
```

**Decrypt**: decrypt a file using AES and one of the two possible block chaining moddes: cbc/cfb. *All inputs are filesystem paths rather than literals*.

```
decrypt
  AES decrypt the string

Usage:
  crypto1 [options] decrypt [<ciphertext> <key-dec>]

Arguments:
  <ciphertext>  decrypt file path [default: ./encrypted.bin]
  <key-dec>     (hex) decryption key

Options:
  --MAC <MAC>          (hex) verification token
  --key-ver <key-ver>  (hex) verification key
  -?, -h, --help       Show help and usage information
```
