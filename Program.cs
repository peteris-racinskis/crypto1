using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.CommandLine;
using System.CommandLine.Invocation;

namespace crypto1
{
    class Program
    {
        static int Main(string[] args)
        {
            var rootCommand = new RootCommand 
            {
                new Option<int>(
                    "--int-option",
                    getDefaultValue: () => 16,
                    description: "int option"
                ),
                new Argument<string>(
                    "input-string",
                    "string to be operated on"
                ),
                new Command(
                    "encrypt",
                    "AES encrypt the string"
                ),
                new Command(
                    "decrypt",
                    "AES decrypt the string"
                )
            };
            rootCommand.Description = "Sample CLI";
            var encryptCommand = (Command)rootCommand.Children.GetByAlias("encrypt");
            var decryptCommand = (Command)rootCommand.Children.GetByAlias("decrypt");
            encryptCommand.Handler = CommandHandler.Create<int,string>(
                (intOption, inputString) => {
                    var bs = pad(inputString,intOption);
                    Console.WriteLine($"Arguments supplied: {intOption} {encryptCommand.Name} {inputString}");
                    Console.WriteLine($"Padded string: {Encoding.Unicode.GetString(bs)}");
                    Console.WriteLine($"Trimmed {trim(bs)}"); 
                    var k = pad("abc",16,true);
                    var encrypted = encrypt_ECB(bs,k);
                    Console.WriteLine($"Encrypted string {Encoding.Unicode.GetString(encrypted)}");
                    var decrypted = decrypt_ECB(encrypted,k);
                    Console.WriteLine($"Decrypted string {Encoding.Unicode.GetString(decrypted)}");
                    Console.WriteLine($"Trimmed {trim(decrypted)}");
                    encrypted = encrypt_CBC(bs,k);
                    Console.WriteLine($"Encrypted string {Encoding.Unicode.GetString(encrypted)}");
                    decrypted = decrypt_CBC(encrypted,k);
                    Console.WriteLine($"Decrypted string {Encoding.Unicode.GetString(decrypted)}");
                    Console.WriteLine($"Trimmed {trim(decrypted)}");
                }
            );
            decryptCommand.Handler = CommandHandler.Create<int,string>(
                (intOption, inputString) => {
                    var bs = pad(inputString,intOption);
                    Console.WriteLine($"Arguments supplied: {intOption} {decryptCommand.Name} {inputString}");
                    Console.WriteLine($"Padded string: {Encoding.Default.GetString(bs)}");
                    Console.WriteLine($"Trimmed {trim(bs)}"); 
                }
            );
            Console.WriteLine("helo");
            rootCommand.Invoke(args);
            return 0;
        }

        public static byte[] pad(string s, int blockLength, bool key = false){

            //  byte string from character string
            var byteString = Encoding.Unicode.GetBytes(s);

            // calculate the number of blocks and padding bytes
            var blockCount = (int)(byteString.Length / blockLength) + 1;
            var padLength = blockCount * blockLength - byteString.Length;

            // add a whole block if no space for the pad count
            padLength = (padLength == 0) ? blockLength : padLength;

            // create the padding and preamble byte arrays
            var padding = Enumerable.Repeat<byte>((byte)padLength,padLength).ToArray();;
            var preamble = key ? new byte[0] : new byte[blockLength];

            // cryptographically secure RNG
            var rngcsp = RandomNumberGenerator.Create();
            if (preamble.Length != 0) rngcsp.GetBytes(preamble);

            return preamble.Concat(byteString).Concat(padding).ToArray();
        }

        public static string trim(byte[] bs, int blockLength = 16)
        {
            // .. <- range operator
            // ^  <- inverse indexing operator
            return Encoding.Unicode.GetString(bs[blockLength..^(int)bs[^1]]);
        }

        /* 
         Have to handroll the CBC implementation, so use ECB and XOR the 
         vectors myself.
        */
               
        public static byte[] encrypt_ECB(byte[] bs, byte[] key)//string keySource)
        {
            var sizeBytes = 16;
            var result = new byte[bs.Length];
            var block = new byte[sizeBytes];
            for (int i = 0; i < bs.Length - 1; i += sizeBytes) {
                block = AES_encrypt_block(bs[i..(i+sizeBytes)],key);
                Array.Copy(block,0,result,i,sizeBytes);
            }
            return result;
        }        

        public static byte[] encrypt_CBC(byte[] bs, byte[] key)//string keySource)
        {
            var sizeBytes = 16;
            var result = new byte[bs.Length];
            var block = new byte[sizeBytes];
            var iv = new byte[sizeBytes];
            for (int i = 0; i < bs.Length - 1; i += sizeBytes) {
                block = xorVectors(iv,bs,i);
                block = AES_encrypt_block(block,key);
                Array.Copy(block,0,result,i,sizeBytes);
                iv = result[i..(i+sizeBytes)];
            }
            return result;
        }

        public static byte[] decrypt_ECB(byte[] ct, byte[] key)//string keySource)
        {
            var sizeBytes = 16;
            var result = new byte[ct.Length];
            var block = new byte[sizeBytes];
            for (int i = 0; i < ct.Length; i += sizeBytes) {
                block = AES_decrypt_block(ct[i..(i+sizeBytes)],key);
                Array.Copy(block,0,result,i,sizeBytes);
            }
            return result;
        }

        public static byte[] decrypt_CBC(byte[] ct, byte[] key)//string keySource)
        {
            var sizeBytes = 16;
            var result = new byte[ct.Length];
            var block = new byte[sizeBytes];
            var iv = new byte[sizeBytes];
            for (int i = 0; i < ct.Length; i += sizeBytes) {
                block = AES_decrypt_block(ct[i..(i+sizeBytes)],key);
                block = xorVectors(block,iv,0);
                Array.Copy(block,0,result,i,sizeBytes);
                iv = ct[i..(i+sizeBytes)];
            }
            return result;
        }
        
        public static byte[] xorVectors(byte[] vec1, byte[] vec2, int offset){
            var result = new byte[vec1.Length];
            for(int i = 0; i < vec1.Length; i++) {
                result[i] = (byte)(vec1[i] ^ vec2[i+offset]);
            }
            return result;
        }

        /*
            The single block AES was trickier to get right than I thought
            so I ended up copy & pasting a solution that works (reusing the 
            encryptor/decryptor objects would introduce weird behaviour).
            The API is really not designed for being used like this, you're
            supposed to put it into structures that operate on data streams.
        */

        private static byte[] AES_transform(byte[] source, byte[] key, bool encrypt = true){
            byte[] output_buffer = new byte[source.Length];
             using (AesManaged aesAlg = new AesManaged())
            {
                
                aesAlg.Mode = CipherMode.ECB;
                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = key;
                var transformer = encrypt ? 
                    aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV) :
                    aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                transformer.TransformBlock(source, 0, source.Length, output_buffer, 0);
            }

            return output_buffer;
        }

        private static byte[] AES_encrypt_block(byte[] plainText, byte[] Key)
        {
           return AES_transform(plainText,Key,true);
        }

        private static byte[] AES_decrypt_block(byte[] cipherText, byte[] Key)
        {
           return AES_transform(cipherText,Key,false);
        }

        /*

        private static byte[] AES_encrypt_block(byte[] plainText, byte[] Key)
        {
            byte[] output_buffer = new byte[plainText.Length];

            using (AesManaged aesAlg = new AesManaged())
            {
                
                aesAlg.Mode = CipherMode.ECB;
                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = Key;
                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                encryptor.TransformBlock(plainText, 0, plainText.Length, output_buffer, 0);
            }

            return output_buffer;
        }

        private static byte[] AES_decrypt_block(byte[] cipherText, byte[] Key)
        {
            byte[] output_buffer = new byte[cipherText.Length];

            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Mode = CipherMode.ECB;
                aesAlg.BlockSize = 128;
                aesAlg.KeySize = 128;
                aesAlg.Padding = PaddingMode.None;
                aesAlg.Key = Key;
                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                decryptor.TransformBlock(cipherText, 0, cipherText.Length, output_buffer, 0);
            }

            return output_buffer;
        }
        
        public static byte[] encrypt_CBC(byte[] bs, byte[] key)//string keySource)
        {
            Aes myAes = Aes.Create();
            var sizeBytes = myAes.BlockSize / 8;
            myAes.Mode = CipherMode.ECB;
            myAes.Key = key;//pad(keySource, 32, true);
            var encryptor = myAes.CreateEncryptor();
            var iv = myAes.IV;
            var result = new byte[bs.Length];
            var block = new byte[sizeBytes];
            for (int i = 0; i < bs.Length - 1; i += sizeBytes) {
                //block = xorVectors(iv,bs,i);
                //block = bs[i..(i+sizeBytes)];
                encryptor.TransformBlock(block,0,sizeBytes,result,i);
                iv = result[i..(i+sizeBytes)];
            }
            return result;
        }
        */

        /*
        public static byte[] decrypt_CBC(byte[] ct, byte[] key)//string keySource)
        {
            Aes myAes = Aes.Create();
            var sizeBytes = myAes.BlockSize / 8;
            myAes.Mode = CipherMode.ECB;
            myAes.Key = key;//pad(keySource, 32, true);
            //myAes.Padding = PaddingMode.None;
            var decryptor = myAes.CreateDecryptor(myAes.Key,myAes.IV);
            var iv = myAes.IV;
            //var ctPad = new byte[ct.Length+sizeBytes];
            //Array.Copy(ct,ctPad,ct.Length);
            var result = new byte[ct.Length];
            var block = new byte[sizeBytes];
            for (int i = sizeBytes; i < ct.Length; i += sizeBytes) {
                iv = ct[(i-sizeBytes)..(i)];
                decryptor.TransformBlock(ct,i,sizeBytes,block,0);
                block = xorVectors(block,iv,0);
                Console.WriteLine(Encoding.Unicode.GetString(block));
                //block = ct[i..(i+sizeBytes)];
                Array.Copy(block,0,result,i-sizeBytes,sizeBytes);
            }
            // Shift the bytes back by a block
            //Array.Copy(result,sizeBytes,result,0,result.Length-sizeBytes);
            // fill final block
            //decryptor.TransformFinalBlock()
            //block = xorVectors(block,iv,0);
            //Array.Copy(decryptor.TransformFinalBlock(ct,ct.Length-sizeBytes,sizeBytes),0,result,result.Length-sizeBytes,sizeBytes);
            return result;
        }

        */
    }
}
