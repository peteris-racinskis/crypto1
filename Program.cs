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
                    "base file path ($.bin/$.token/.. added automatically)"
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
            rootCommand.Description = "AES encryptor/decryptor. Inputs MUST be at least 1 block in length!";
            
            // Configure encrypt command handler and arguments
            var encryptCommand = (Command)rootCommand.Children.GetByAlias("encrypt");
            encryptCommand.AddArgument(new Argument<string>(
                "plaintext",
                "path to file to encrypt"
            ));
            encryptCommand.AddOption(new Option<string>(
                "--key-enc",
                getDefaultValue: () => "",
                "(optional) encryption key"
            ));
            encryptCommand.AddOption(new Option<string>(
                "--key-sig",
                getDefaultValue: () => "",
                "(optional) signature key"
            ));
            encryptCommand.Handler = CommandHandler.Create<string, string, bool, string,string>(
                (plaintext,keyEnc,cfb,outfile,keySig) => { 
                    var encryptor = new AESHandler(cfb,plaintext,keyEnc);
                    if (!string.IsNullOrEmpty(keySig)) encryptor.macKey = 
                        AESHandler.HexToBytes(File.ReadAllText(keySig));
                    string hex = $"Original plaintext:\n{File.ReadAllText(plaintext)}";
                    encryptor.Encrypt();            
                    hex=$"{hex}\nUse cfb? : {cfb.ToString()}";
                    hex = $"{hex}\nSymmetric key:\n{AESHandler.HexString(encryptor.key)}";
                    hex = $"{hex}\nCiphertext (hex):\n{AESHandler.HexString(encryptor.result)}";
                    if (!string.IsNullOrEmpty(outfile)) 
                    {
                        File.WriteAllBytes($"{outfile}-out.bin",encryptor.result);
                        File.WriteAllText($"{outfile}-symkey.txt",AESHandler.HexString(encryptor.key));
                    }
                    if (cfb) {
                        var token = encryptor.GenerateOMAC();
                        var tokenKey = encryptor.macKey;
                        if (!string.IsNullOrEmpty(outfile)) 
                        {
                            File.WriteAllBytes($"{outfile}-mac.bin",token);
                            File.WriteAllText($"{outfile}-signkey.txt",AESHandler.HexString(tokenKey));
                        }
                        hex = $"{hex}\nMAC key:\n{AESHandler.HexString(tokenKey)}";
                        hex = $"{hex}\nMAC token (hex):\n{AESHandler.HexString(token)}";
                    }
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
            decryptCommand.Handler = CommandHandler.Create<string,string,bool,string,string,string>(
                (ciphertext,keyDec,cfb,MAC,keyVer,outfile) => { 
                    var ct = File.ReadAllBytes(ciphertext);
                    var decryptor = new AESHandler(cfb,ct,keyDec,MAC,keyVer);
                    string hex = $"Original ciphertext:\n{AESHandler.HexString(ct)}";           
                    hex=$"{hex}\nUse cfb? : {cfb.ToString()}";
                    hex = $"{hex}\nSymmetric key:\n{AESHandler.HexString(decryptor.key)}"; 
                    decryptor.Decrypt();
                    hex = $"{hex}\nPlaintext (hex):\n{AESHandler.HexString(decryptor.result)}";
                    hex = $"{hex}\nPlaintext (ASCII):\n{AESHandler.ASCIIString(decryptor.result)}";
                    hex = $"{hex}\nPlaintext (Unicode):\n{AESHandler.UnicodeString(decryptor.result)}";
                    if (!string.IsNullOrEmpty(outfile)) 
                    {
                        File.WriteAllBytes($"{outfile}-out.txt",decryptor.result);
                    }
                    if (!(string.IsNullOrEmpty(MAC) || string.IsNullOrEmpty(keyVer))) {
                        hex = $"{hex}\nSignature key (hex):\n{keyVer}";
                        hex = $"{hex}\nProvided token (hex):\n{MAC}";
                        var same = decryptor.VerifyOMAC();
                        hex = $"{hex}\nComputed token (hex):\n{AESHandler.HexString(decryptor.newMac)}";
                        hex = $"{hex}\nAre tokens the same? : {same.ToString()}";
                    }
                    Console.WriteLine(hex);
                }
            );
            
            // Execute the handler
            rootCommand.Invoke(args);
        }
    }
}
