using System;
using System.IO;
using System.CommandLine;
using System.CommandLine.Invocation;
using crypto1;

namespace commandlinetest
{
    class Program
    {
        static void Main(string[] args)
        {
            // Set up the commands and global flags
            var rootCommand = new RootCommand{
                new Option<bool>(
                    "--cfb",
                    "use CFB rather than CBC chaining"
                ),
                new Option<string>(
                    "--outfile",
                    "base file path ($.bin/$.token added automatically)"
                ),
                new Command(
                    "encrypt",
                    "AES encrypt the string"
                ),
                new Command(
                    "decrypt",
                    "AES decrypt the string"
                ),
            };
            
            // Configure encrypt command handler and arguments
            var encryptCommand = (Command)rootCommand.Children.GetByAlias("encrypt");
            encryptCommand.AddArgument(new Argument<string>(
                "plaintext",
                "text to encrypt"
            ));
            encryptCommand.AddOption(new Option<string>(
                "--key-enc",
                getDefaultValue: () => "",
                "(optional) encryption key"
            ));
            encryptCommand.Handler = CommandHandler.Create<string, string, bool, string>(
                (plaintext,keyEnc,cfb,outfile) => { 
                    var encryptor = new AESHandler(cfb,plaintext,keyEnc);
                    string hex;
                    encryptor.Encrypt();            
                    Console.WriteLine($"Use cfb? {cfb.ToString()}");
                    Console.WriteLine($"This is the key {keyEnc}");
                    Console.WriteLine($"This is the key {AESHandler.UnicodeString(encryptor.key)}");
                    Console.WriteLine($"This is the key {AESHandler.HexString(encryptor.key)}");
                    hex = $"Symmetric key:\n{AESHandler.HexString(encryptor.key)}";
                    Console.WriteLine($"This is the plaintext: {plaintext}");
                    Console.WriteLine($"This is the plaintext: {AESHandler.HexString(encryptor.byteString)}");
                    Console.WriteLine($"This is the ciphertext: {AESHandler.UnicodeString(encryptor.result)}");
                    Console.WriteLine($"This is the ciphertext: {AESHandler.HexString(encryptor.result)}");
                    hex = $"{hex}\nCiphertext (hex):\n{AESHandler.HexString(encryptor.result)}";
                    if (!string.IsNullOrEmpty(outfile)) File.WriteAllBytes($"{outfile}.bin",encryptor.result);
                    if (cfb) {
                        var token = encryptor.GenerateOMAC();
                        var tokenKey = encryptor.macKey;
                        Console.WriteLine($"This is the MAC key {AESHandler.HexString(tokenKey)}");
                        Console.WriteLine($"This is the MAC token {AESHandler.HexString(token)}");
                        if (!string.IsNullOrEmpty(outfile)) File.WriteAllBytes($"{outfile}.token",encryptor.result);
                        hex = $"{hex}\nMAC key:\n{AESHandler.HexString(tokenKey)}";
                        hex = $"{hex}\nMAC token (hex):\n{AESHandler.HexString(token)}";
                    }
                    if (!string.IsNullOrEmpty(outfile)) File.WriteAllText($"{outfile}-hex.txt",hex);
                    Console.WriteLine(hex);
                }
            );

            // Configure decrypt command handler and arguments
            var decryptCommand = (Command)rootCommand.Children.GetByAlias("decrypt");
            decryptCommand.AddArgument(new Argument<string>(
                "ciphertext",
                getDefaultValue: () => "./encrypted.bin",
                "decrypt file path"
            ));
            decryptCommand.AddArgument(new Argument<string>(
                "key-dec",
                "(hex) decryption key"
            ));
            decryptCommand.AddOption(new Option<string>(
                "--MAC",
                "(hex) verification token"
            ));
            decryptCommand.AddOption(new Option<string>(
                "--key-ver",
                "(hex) verification key"
            ));
            decryptCommand.Handler = CommandHandler.Create<string,string,bool,string,string>(
                (ciphertext,key,cfb,MAC,keyVer) => { 
                    var ct = File.ReadAllBytes(ciphertext);
                    var decryptor = new AESHandler(cfb,ct,key,MAC,keyVer);
                    Console.WriteLine($"Use cfb? {cfb.ToString()}");
                    decryptor.Decrypt();
                    Console.WriteLine($"This is the key {key}");
                    Console.WriteLine($"This is the key {AESHandler.UnicodeString(decryptor.key)}");
                    Console.WriteLine($"This is the key {AESHandler.HexString(decryptor.key)}");
                    Console.WriteLine($"This is the ciphertext: {AESHandler.UnicodeString(decryptor.byteString)}");
                    Console.WriteLine($"This is the ciphertext: {AESHandler.HexString(decryptor.byteString)}");
                    Console.WriteLine($"This is the plaintext: {AESHandler.UnicodeString(decryptor.result)}");
                    Console.WriteLine($"This is the plaintext: {AESHandler.HexString(decryptor.result)}");
                    Console.WriteLine($"This is the plaintext: {AESHandler.ASCIIString(decryptor.result)}");
                    //61-6C-68-73-68-67-6F-61-68-67-6F-69-61-68-67-65-61-68-67-65-61-68-77-67-65
                }
            );
            
            // Execute the handler
            rootCommand.Invoke(args);
        }
    }
}
