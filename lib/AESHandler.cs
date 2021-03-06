using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;


namespace crypto1 
{
    public class AESHandler
    {
        public byte[] key { get; set; }
        public byte[] byteString { get; set; }
        public byte[] result { get; set; }
        public byte[] mac { get; set; }
        public byte[] newMac { get; set; }
        public byte[] macKey { get; set; }
        public bool cfbMode { get; set; }
        private static int sizeBytes = 16;
        private static int keySizeBytes = 16;

        
        public AESHandler() {}

        /// <summary>
        /// Constructor for encrypting a string
        /// </summary>
        /// <param name="paramKey"> Optional key (hexadecimal format as per exampe)</param>
        public AESHandler(bool mode, string plaintextPath, string keyPath = null)
        {
            cfbMode = mode;
            byteString = File.ReadAllBytes(plaintextPath);
            key = (!string.IsNullOrEmpty(keyPath)) ? HexToBytes(File.ReadAllText(keyPath)) : Keygen();
        }

        /// <summary>
        /// Constructor for decrypting a file
        /// </summary>
        public AESHandler(bool mode, byte[] ct, string keyPath, string macPath = null, string keyVerPath = null)
        {
            cfbMode = mode;
            byteString = ct;
            key = HexToBytes(File.ReadAllText(keyPath));
            if (!string.IsNullOrEmpty(macPath)) {
                mac = File.ReadAllBytes(macPath);
            }
            if (!string.IsNullOrEmpty(keyVerPath)) {
                macKey = HexToBytes(File.ReadAllText(keyVerPath));
            }
        }

        public void Encrypt()
        {
            if(cfbMode) EncryptCFBNoPad();
            else EncryptCBCCS();
        }
        
        public void Decrypt()
        {
            if(cfbMode) DecryptCFBNoPad();
            else DecryptCBCCS();
        }

        public static string UnicodeString(byte[] prop)
        {
            return Encoding.Unicode.GetString(prop);
        }

        public static string ASCIIString(byte[] prop)
        {
            return Encoding.ASCII.GetString(prop);
        }


        public static string HexString(byte[] prop)
        {
            return BitConverter.ToString(prop);
        }

        public static byte[] GetBytes(string s)
        {
            return Encoding.Default.GetBytes(s);
        }

        public static string GetString(byte[] buffer)
        {
            return Encoding.Default.GetString(buffer);
        }

        public static byte[] HexToBytes(string s)
        {
            if (s == null) return null;
            var strings = s.Split('-');
            var output = new byte[strings.Length];
            for (int i = 0; i < strings.Length; i++){
                output[i] = Convert.ToByte(strings[i], 16);
            }
            return KeyValid(output) ? output : Keygen();
        }

        public static bool KeyValid(byte[] key)
        {
            return key.Length == keySizeBytes;
        }

        public static byte[] PadZero(byte[] block, int len)
        {
            var output = new byte[len];
            Array.Copy(block,output,block.Length);
            return output;
        }

        public static byte[] PadZeroStart(byte[] pt, int blockSize = 16)
        {
            var output = new byte[blockSize+pt.Length];
            Array.Copy(pt,0,output,blockSize,pt.Length);
            return output;
        }

        public static byte[] Keygen()
        {
            var buf = new byte[keySizeBytes];
            // Some weirdness with how encryption works under the hood in .NET
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.GenerateKey();
                Array.Copy(aes.Key,buf,keySizeBytes);
            }            
            return buf;
        }
        
        public static byte[] PadECBBits(byte[] ct, byte[] key, int len, int blockSize = 16)
        {
            var output = new byte[len];
            var finalBlockLength = ct.Length % blockSize;
            var finalBlock = new byte[blockSize];
            Array.Copy(ct,ct.Length-finalBlockLength,finalBlock,0,finalBlockLength);
            var penultimateBlock = ct[^(blockSize+finalBlockLength)..^finalBlockLength];
            var ECB_decrypted = AES_decrypt_block(penultimateBlock,key);
            Array.Copy(ECB_decrypted,finalBlockLength,finalBlock,finalBlockLength,blockSize-finalBlockLength);
            // copy padding bits
            Array.Copy(ct,output,output.Length-2*blockSize);
            Array.Copy(penultimateBlock, 0, output, output.Length-2*blockSize, blockSize);
            Array.Copy(finalBlock, 0, output, output.Length-blockSize, blockSize);
            return output;
        }

        public static byte[] SwapFinalBlocks(byte[] buffer, int blockSize = 16) 
        {
            var output = new byte[buffer.Length];
            Array.Copy(buffer,output,buffer.Length-2*blockSize);
            Array.Copy(buffer,buffer.Length-2*blockSize,output,output.Length-blockSize,blockSize);
            Array.Copy(buffer,buffer.Length-blockSize,output,output.Length-2*blockSize,blockSize);
            return output;
        }

        /* 
         Have to handroll the CBC implementation, so use ECB and XOR the 
         vectors myself.
        */

        public void EncryptCBCCS()
        {
            var blockMultiple = (int)(byteString.Length / sizeBytes) + 1;
            var padded = PadZero(byteString,blockMultiple * sizeBytes);
            result = new byte[padded.Length];
            var block = new byte[sizeBytes];
            var iv = Enumerable.Repeat<byte>(0,sizeBytes).ToArray();
            for (int i = 0; i < padded.Length; i += sizeBytes) {
                block = xorVectors(iv,padded,i);
                block = AES_encrypt_block(block,key);
                Array.Copy(block,0,result,i,sizeBytes);
                iv = result[i..(i+sizeBytes)];
            }
            result = SwapFinalBlocks(result);
            result = result[..byteString.Length];
        }
        public void EncryptCFBNoPad()
        {
            // This was messing up my OMAC! I was padding the 
            // plaintext and then computing the signature!
            // ^ solution: make a local copy
            var byteStringCopy = PadZeroStart(byteString);
            result = new byte[byteStringCopy.Length];
            var block = new byte[sizeBytes];
            var iv = new byte[sizeBytes];
            // random initialization vector
            var rngcsp = RandomNumberGenerator.Create();
            rngcsp.GetBytes(iv);
            for (int i = 0; i < byteStringCopy.Length - 1; i += sizeBytes) {
                block = AES_encrypt_block(iv,key);
                block = xorVectors(block,byteStringCopy,i);
                Array.Copy(block,0,result,i,Math.Min(sizeBytes,result.Length-i));
                iv = result[i..(Math.Min(i+sizeBytes,result.Length))];
            }
        }

        public static List<byte[]> KeygenOMAC(byte[] key) 
        {
            var key1 = new byte[key.Length];
            var key2 = new byte[key.Length];
            var cLookup = new Dictionary<int,int> {
                { 8 ,   0x1b },
                { 16,   0x87 },
                { 32,   0x425},
            };
            var ints = new Int32[]{ cLookup[key.Length], 0, 0, 0};
            var c = new BitArray(ints);
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

        public byte[] ComputeOMAC(byte[] buffer)
        {   
            // Make a copy of the array
            var buf = new byte[buffer.Length];  
            Array.Copy(buffer,buf,buf.Length);
            // unless expicitly initialized, get new key
            macKey = macKey ?? Keygen(); 
            var keys = KeygenOMAC(macKey);
            // Calculate last block length, XOR with the key
            var lastBlock = buf.Length % sizeBytes;
            var keyXOR = (lastBlock == 0) ?
                xorVectors(buf[^sizeBytes..],keys[0],0) :
                xorVectors(buf[^lastBlock..],keys[1],0);
            Array.Copy(keyXOR,0,buf,buf.Length-lastBlock,lastBlock);
            // Grind the whole thing through AES
            var block = Enumerable.Repeat<byte>(0,sizeBytes).ToArray();
            for (int i = 0; i < buf.Length; i += sizeBytes) {
                block = xorVectors(block,buf,i);
                block = AES_encrypt_block(block,key);
            }
            //omacKeys = keys;
            return block;
        }

        public byte[] GenerateOMAC()
        {
            return ComputeOMAC(byteString);
        }

        public bool VerifyOMAC()
        {
            newMac = ComputeOMAC(result);
            return ByteSpanCompare(mac,newMac);
        }

        public void DecryptCBCCS()
        {
            var blockMultiple = (int)(byteString.Length / sizeBytes) + 1;
            var padded = PadECBBits(byteString,key,blockMultiple*sizeBytes);
            padded = SwapFinalBlocks(padded);
            result = new byte[padded.Length];
            var block = new byte[sizeBytes];
            var iv = Enumerable.Repeat<byte>(0,sizeBytes).ToArray();
            for (int i = 0; i < byteString.Length; i += sizeBytes) {
                block = AES_decrypt_block(padded[i..(i+sizeBytes)],key);
                block = xorVectors(block,iv,0);
                Array.Copy(block,0,result,i,sizeBytes);
                iv = padded[i..(i+sizeBytes)];
            }
            result = result[..byteString.Length];
        }

        public void DecryptCFBNoPad()
        {
            result = new byte[byteString.Length];
            var block = new byte[sizeBytes];
            var iv = new byte[sizeBytes];
            for (int i = 0; i < byteString.Length; i += sizeBytes) {
                block = AES_encrypt_block(iv,key);
                block = xorVectors(block,byteString,i);
                Array.Copy(block,0,result,i,Math.Min(sizeBytes,result.Length-i));
                iv = byteString[i..Math.Min(i+sizeBytes,result.Length)];
            }
            result = result[sizeBytes..];
        }

        public static byte[] xorVectors(byte[] vec1, byte[] vec2, int offset){
            var result = new byte[vec1.Length];
            for(int i = 0; i < Math.Min(vec1.Length,vec2.Length-offset); i++) {
                result[i] = (byte)(vec1[i] ^ vec2[i+offset]);
            }
            return result;
        }

        public static bool ByteSpanCompare(ReadOnlySpan<byte> a1, ReadOnlySpan<byte> a2)
        {
            return a1.SequenceEqual(a2);
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


    }
}