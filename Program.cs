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
            encryptCommand.AddOption(new Option<string>(
                "--key-sig",
                getDefaultValue: () => "",
                "(optional) signature key"
            ));
            encryptCommand.Handler = CommandHandler.Create<string, string, bool, string,string>(
                (plaintext,keyEnc,cfb,outfile,keySig) => { 
                    var encryptor = new AESHandler(cfb,plaintext,keyEnc);
                    if (!string.IsNullOrEmpty(keySig)) encryptor.macKey = AESHandler.HexToBytes(keySig);
                    string hex = $"Original plaintext:\n{plaintext}";
                    encryptor.Encrypt();            
                    hex=$"{hex}\nUse cfb? : {cfb.ToString()}";
                    //Console.WriteLine($"This is the key {keyEnc}");
                    //Console.WriteLine($"This is the key {AESHandler.UnicodeString(encryptor.key)}");
                    //Console.WriteLine($"This is the key {AESHandler.HexString(encryptor.key)}");
                    hex = $"{hex}\nSymmetric key:\n{AESHandler.HexString(encryptor.key)}";
                    //Console.WriteLine($"This is the plaintext: {plaintext}");
                    //Console.WriteLine($"This is the plaintext: {AESHandler.HexString(encryptor.byteString)}");
                    //Console.WriteLine($"This is the ciphertext: {AESHandler.UnicodeString(encryptor.result)}");
                    //Console.WriteLine($"This is the ciphertext: {AESHandler.HexString(encryptor.result)}");
                    hex = $"{hex}\nCiphertext (hex):\n{AESHandler.HexString(encryptor.result)}";
                    if (!string.IsNullOrEmpty(outfile)) File.WriteAllBytes($"{outfile}.bin",encryptor.result);
                    if (cfb) {
                        var token = encryptor.GenerateOMAC();
                        //Console.WriteLine($"Plaintext input: {AESHandler.HexString(AESHandler.GetBytes(plaintext))}");
                        //Console.WriteLine($"Plaintext in object: {AESHandler.HexString(encryptor.byteString)}");
                        //Console.WriteLine($"OMAC operation actual buffer: {AESHandler.HexString(encryptor.omacBuffer)}");
                        var tokenKey = encryptor.macKey;
                        //var omacKeys = encryptor.omacKeys;
                        //Console.WriteLine($"This is the MAC key {AESHandler.HexString(tokenKey)}");
                        //Console.WriteLine($"This is the MAC token {AESHandler.HexString(token)}");
                        if (!string.IsNullOrEmpty(outfile)) File.WriteAllBytes($"{outfile}.token",encryptor.result);
                        hex = $"{hex}\nMAC key:\n{AESHandler.HexString(tokenKey)}";
                        hex = $"{hex}\nMAC token (hex):\n{AESHandler.HexString(token)}";
                        //hex = $"{hex}\nOMAC key (hex):\n{AESHandler.HexString(omacKeys[0])}";
                        //2A-03-65-BC-1A-2D-F4-BE-85-97-4D-E6-96-6B-24-44
                        //hex = $"{hex}\nOMAC key (hex):\n{AESHandler.HexString(omacKeys[1])}";
                        //54-06-CA-78-35-5A-E8-7D-0B-2F-9B-CC-2D-D7-48-88
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
                    if (!(string.IsNullOrEmpty(MAC) || string.IsNullOrEmpty(keyVer))) {
                        hex = $"{hex}\nSignature key (hex):\n{keyVer}";
                        hex = $"{hex}\nProvided token (hex):\n{MAC}";
                        var same = decryptor.VerifyOMAC();
                        //Console.WriteLine($"OMAC operation actual buffer: {AESHandler.HexString(decryptor.omacBuffer)}");
                        //var omacKeys = decryptor.omacKeys;
                        hex = $"{hex}\nComputed token (hex):\n{AESHandler.HexString(decryptor.newMac)}";
                        hex = $"{hex}\nAre tokens the same? : {same.ToString()}";
                        //hex = $"{hex}\nOMAC key (hex):\n{AESHandler.HexString(omacKeys[0])}";
                        //2A-03-65-BC-1A-2D-F4-BE-85-97-4D-E6-96-6B-24-44
                        //hex = $"{hex}\nOMAC key (hex):\n{AESHandler.HexString(omacKeys[1])}";
                        //54-06-CA-78-35-5A-E8-7D-0B-2F-9B-CC-2D-D7-48-88
                    }
                    if (!string.IsNullOrEmpty(outfile)) File.WriteAllText($"{outfile}-hex.txt",hex);
                    Console.WriteLine(hex);
                }
            );
            
            // Execute the handler
            rootCommand.Invoke(args);
        }
    }
}
