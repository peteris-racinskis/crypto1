## crypto1 - a badly-written implementation of CBC and CFB block chaining modes for AES

### How it works

The .NET core cryptographic library is used for ECB encryption of individual message blocks, while the AESHandler class takes care of the rest - block chaining, parsing, padding, the XOR operations, etc.

### How to use it

1. Download one of the archived binary distributions (the .NET core 5.0 runtime is packaged inside, which is the whole reason why I went with .NET over Python), extract it somewhere;
2. Navigate to the root directory of the application where the **crypto1** executable file is located
3. Execute it.

For the sake of simplicity (mine, the programmer's, not yours, dear user), encryptable strings are provided directly in the command line; encryption/decryption keys, MAC tokens and MAC keys are provided as hexadecimal strings separated by the symbol '-'; encrypted output can be directed into files, which have no encoding; decryption is always done by providing a filesystem path to an encrypted binary.

Example usage:

```
$ ./crypto1 --help
crypto1

Usage:
  crypto1 [options] [command]

Options:
  --cfb                use CFB rather than CBC chaining
  --outfile <outfile>  base file path ($.bin/$.token added automatically)
  --version            Show version information
  -?, -h, --help       Show help and usage information

Commands:
  encrypt <plaintext>             AES encrypt the string
  decrypt <ciphertext> <key-dec>  AES decrypt the string [default: ./encrypted.bin]

  encrypt
  AES encrypt the string
```
```
$ ./crypto1 encrypt --help
Usage:
  crypto1 [options] encrypt <plaintext>

Arguments:
  <plaintext>  text to encrypt

Options:
  --key-enc <key-enc>  (optional) encryption key [default: ]
  --key-sig <key-sig>  (optional) signature key [default: ]
  -?, -h, --help       Show help and usage information
```
```
$ ./crypto1 decrypt --help
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

Encrypt a string in CFB mode, write output to file, generate a signature token. Note that when **encrypting** a file, the **output file extension must not** be specified (as 3 different output files are generated - the encrypted binary, the token binary and a human-readable output text file). The user is not required to provide a key during encryption as one will be automatically generated.

```
$ ./crypto1 --cfb --outfile ./encrypted-test-cfb encrypt alhshgoahgoiahgeahgeahwge \
$> --key-enc 89-C7-A3-35-C3-BD-97-99-05-88-FF-80-62-0F-7A-52 \
$> --key-sig 95-81-32-5E-8D-16-7A-DF-C2-CB-26-73-CB-35-12-22
Original plaintext:
alhshgoahgoiahgeahgeahwge
Use cfb? : True
Symmetric key:
89-C7-A3-35-C3-BD-97-99-05-88-FF-80-62-0F-7A-52
Ciphertext (hex):
76-0D-A0-F9-FD-8D-58-2D-1A-87-1A-9D-06-5A-61-D0-CA-CD-23-70-D3-62-C7-A8-B9-06-49-18-6B-83-58-0D-72-2C-D7-98-EB-BA-B1-28-CB
MAC key:
95-81-32-5E-8D-16-7A-DF-C2-CB-26-73-CB-35-12-22
MAC token (hex):
8B-23-E1-99-A1-E3-55-BF-B5-62-8E-73-7B-A3-49-BC

```

Decrypt an encrypted file in CFB mode, verify the signature token. Note that when decrypting a file, the **input file extension must** be specified, as this is a direct filesystem read and could be any arbitrary path.

```
$ ./crypto1 --cfb decrypt ./encrypted-test-cfb.bin 89-C7-A3-35-C3-BD-97-99-05-88-FF-80-62-0F-7A-52 \
$> --MAC 8B-23-E1-99-A1-E3-55-BF-B5-62-8E-73-7B-A3-49-BC \
$> --key-ver 95-81-32-5E-8D-16-7A-DF-C2-CB-26-73-CB-35-12-22
Original ciphertext:
76-0D-A0-F9-FD-8D-58-2D-1A-87-1A-9D-06-5A-61-D0-CA-CD-23-70-D3-62-C7-A8-B9-06-49-18-6B-83-58-0D-72-2C-D7-98-EB-BA-B1-28-CB
Use cfb? : True
Symmetric key:
89-C7-A3-35-C3-BD-97-99-05-88-FF-80-62-0F-7A-52
Plaintext (hex):
61-6C-68-73-68-67-6F-61-68-67-6F-69-61-68-67-65-61-68-67-65-61-68-77-67-65
Plaintext (ASCII):
alhshgoahgoiahgeahgeahwge
Plaintext (Unicode):
污獨杨慯杨楯桡敧桡敧桡杷�
Signature key (hex):
95-81-32-5E-8D-16-7A-DF-C2-CB-26-73-CB-35-12-22
Provided token (hex):
8B-23-E1-99-A1-E3-55-BF-B5-62-8E-73-7B-A3-49-BC
Computed token (hex):
8B-23-E1-99-A1-E3-55-BF-B5-62-8E-73-7B-A3-49-BC
Are tokens the same? : True

```