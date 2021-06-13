using System;
using System.Text;
using System.Linq;
using System.Buffers.Binary;
using System.Collections;
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
                    var unpaddedBs = Encoding.Unicode.GetBytes(inputString);
                    Console.WriteLine($"Arguments supplied: {intOption} {encryptCommand.Name} {inputString}");
                    Console.WriteLine($"Padded string: {Encoding.Unicode.GetString(bs)}");
                    Console.WriteLine($"Trimmed {trim(bs)}"); 
                    Console.WriteLine("ECB");
                    var k = pad("abc",16,true);
                    var encrypted = encrypt_ECB(bs,k);
                    Console.WriteLine($"Encrypted string {Encoding.Unicode.GetString(encrypted)}");
                    var decrypted = decrypt_ECB(encrypted,k);
                    Console.WriteLine($"Decrypted string {Encoding.Unicode.GetString(decrypted)}");
                    Console.WriteLine($"Trimmed {trim(decrypted)}");
                    Console.WriteLine("CBC");
                    encrypted = encrypt_CBC(bs,k);
                    Console.WriteLine($"Encrypted string {Encoding.Unicode.GetString(encrypted)}");
                    decrypted = decrypt_CBC(encrypted,k);
                    Console.WriteLine($"Decrypted string {Encoding.Unicode.GetString(decrypted)}");
                    Console.WriteLine($"Trimmed {trim(decrypted)}");
                    Console.WriteLine("CFB");
                    encrypted = encrypt_CFB(bs,k);
                    Console.WriteLine($"Encrypted string {Encoding.Unicode.GetString(encrypted)}");
                    decrypted = decrypt_CFB(encrypted,k);
                    Console.WriteLine($"Decrypted string {Encoding.Unicode.GetString(decrypted)}");
                    Console.WriteLine($"Trimmed {trim(decrypted)}");
                    var mac = generate_OMAC(bs,k);
                    Console.WriteLine($"OMAC token {Encoding.Unicode.GetString(mac)}");
                    var sameLen = encrypt_CBC_CS(unpaddedBs,k);
                    Console.WriteLine($"Unpadded CBC {sameLen.Length} {Encoding.Unicode.GetString(sameLen)}");
                    var decr = decrypt_CBC_CS(sameLen,k);
                    Console.WriteLine($"Unpadded CBC {sameLen.Length} {Encoding.Unicode.GetString(decr)}");
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
            var padding = Enumerable.Repeat<byte>(0,padLength).ToArray();
            var preamble = key ? new byte[0] : new byte[blockLength];

            // cryptographically secure RNG
            var rngcsp = RandomNumberGenerator.Create();
            if (preamble.Length != 0) rngcsp.GetBytes(preamble);

            return preamble.Concat(byteString).Concat(padding).ToArray();
        }

        public static byte[] pad_zero(byte[] block, int len)
        {
            var output = new byte[len];
            Array.Copy(block,output,block.Length);
            return output;
        }

        public static byte[] pad_ECB_bits(byte[] ct, byte[] key, int len, int blockSize = 16)
        {
            var output = new byte[len];
            // Copy cyphertext into buffer
            //Array.Copy(ct,output,ct.Length);
            // get padding bits
            var finalBlockLength = ct.Length % blockSize;
            var finalBlock = new byte[blockSize];
            Array.Copy(ct,ct.Length-finalBlockLength,finalBlock,0,finalBlockLength);
            var penultimateBlock = ct[^(blockSize+finalBlockLength)..^finalBlockLength];
            var ECB_decrypted = AES_decrypt_block(penultimateBlock,key);
            // According to slides: need to xor C_n-1 with { C_n, 0.0 }
            //var xored = xorVectors()
            Console.WriteLine($"Unpadded CBC {Encoding.Unicode.GetString(ECB_decrypted)}");
            Array.Copy(ECB_decrypted,finalBlockLength,finalBlock,finalBlockLength,blockSize-finalBlockLength);


            // copy padding bits
            Array.Copy(ct,output,output.Length-2*blockSize);
            Array.Copy(penultimateBlock, 0, output, output.Length-2*blockSize, blockSize);
            Array.Copy(finalBlock, 0, output, output.Length-blockSize, blockSize);
            return output;
        }

        public static byte[] swap_final_blocks(byte[] buffer, int blockSize = 16) 
        {
            var output = new byte[buffer.Length];
            Array.Copy(buffer,output,buffer.Length-2*blockSize);
            Array.Copy(buffer,buffer.Length-2*blockSize,output,output.Length-blockSize,blockSize);
            Array.Copy(buffer,buffer.Length-blockSize,output,output.Length-2*blockSize,blockSize);
            return output;
        }

        public static string trim(byte[] bs, int blockLength = 16, int prepend = 1)
        {
            // .. <- range operator
            // ^  <- inverse indexing operator
            return Encoding.Unicode.GetString(bs[(prepend*blockLength)..^(int)bs[^1]]);
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

        public static byte[] encrypt_CBC_CS(byte[] bs, byte[] key)
        {
            var sizeBytes = 16;
            var blockMultiple = (int)(bs.Length / sizeBytes) + 1;
            var padded = pad_zero(bs,blockMultiple * sizeBytes);
            var result = new byte[padded.Length];
            var block = new byte[sizeBytes];
            var iv = Enumerable.Repeat<byte>(0,sizeBytes).ToArray();
            for (int i = 0; i < padded.Length; i += sizeBytes) {
                block = xorVectors(iv,padded,i);
                block = AES_encrypt_block(block,key);
                Array.Copy(block,0,result,i,sizeBytes);
                iv = result[i..(i+sizeBytes)];
            }
            result = swap_final_blocks(result);
            return result[..bs.Length];
        }

        public static byte[] encrypt_CFB(byte[] bs, byte[] key)//string keySource)
        {
            var sizeBytes = 16;
            var result = new byte[bs.Length];
            var block = new byte[sizeBytes];
            var iv = new byte[sizeBytes];
            // random initialization vector
            var rngcsp = RandomNumberGenerator.Create();
            rngcsp.GetBytes(iv);
            for (int i = 0; i < bs.Length - 1; i += sizeBytes) {
                block = AES_encrypt_block(iv,key);
                block = xorVectors(block,bs,i);
                Array.Copy(block,0,result,i,sizeBytes);
                iv = result[i..(i+sizeBytes)];
            }
            return result;
        }

        public static List<byte[]> keygen_OMAC(byte[] key) 
        {
            var key1 = new byte[key.Length];
            var key2 = new byte[key.Length];
            var cLookup = new Dictionary<int,int> {
                { 8 ,   0x1b },
                { 16,   0x87 },
                { 32,   0x425},
            };
            var c = new BitArray(BitConverter.GetBytes(cLookup[key.Length]));
            // k0 -> k1
            var k1 = new BitArray(key);
            k1 = !k1[^1] ? k1.LeftShift(1) : k1.LeftShift(1).Xor(c);
            // k1 -> k2
            var k2 = new BitArray(k1);
            k2 = !k2[^1] ? k2.LeftShift(1) : k2.LeftShift(1).Xor(c);
            // Put into byte arrays
            k1.CopyTo(key1,0);
            k2.CopyTo(key2,0);
            return new List<byte[]> { key1 , key2 };
        }

        public static byte[] generate_OMAC(byte[] bs, byte[] key)
        {
            var keys = keygen_OMAC(key);
            var sizeBytes = 16;
            var lastBlock = bs.Length % sizeBytes;
            var keyXOR = (lastBlock == 0) ?
                xorVectors(bs[^sizeBytes..],keys[0],0) :
                xorVectors(bs[^lastBlock..],keys[1],0);
            // reusable XOR vector starts at all 0's
            var block = Enumerable.Repeat<byte>(0,sizeBytes).ToArray();
            for (int i = 0; i < bs.Length; i += sizeBytes) {
                block = xorVectors(block,bs,i);
                block = AES_encrypt_block(block,key);
            }
            return block;
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
        
        public static byte[] decrypt_CBC_CS(byte[] ct, byte[] key)//string keySource)
        {
            var sizeBytes = 16;
            var blockMultiple = (int)(ct.Length / sizeBytes) + 1;
            var padded = pad_ECB_bits(ct,key,blockMultiple*sizeBytes);
            padded = swap_final_blocks(padded);
            var result = new byte[padded.Length];
            var block = new byte[sizeBytes];
            var iv = Enumerable.Repeat<byte>(0,sizeBytes).ToArray();
            for (int i = 0; i < ct.Length; i += sizeBytes) {
                block = AES_decrypt_block(padded[i..(i+sizeBytes)],key);
                block = xorVectors(block,iv,0);
                Array.Copy(block,0,result,i,sizeBytes);
                iv = padded[i..(i+sizeBytes)];
            }
            return result[..ct.Length];
        }

        public static byte[] decrypt_CFB(byte[] ct, byte[] key)//string keySource)
        {
            var sizeBytes = 16;
            var result = new byte[ct.Length];
            var block = new byte[sizeBytes];
            var iv = new byte[sizeBytes];
            for (int i = 0; i < ct.Length; i += sizeBytes) {
                block = AES_encrypt_block(iv,key);
                block = xorVectors(block,ct,i);
                Array.Copy(block,0,result,i,sizeBytes);
                iv = ct[i..(i+sizeBytes)];
            }
            return result;
        }

        public static byte[] xorVectors(byte[] vec1, byte[] vec2, int offset){
            var result = new byte[vec1.Length];
            for(int i = 0; i < Math.Min(vec1.Length,vec2.Length-offset); i++) {
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
