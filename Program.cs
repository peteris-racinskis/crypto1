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
                )
            };
            rootCommand.Description = "Sample CLI";
            rootCommand.Handler = CommandHandler.Create<int,string,string>(
                (intOption, Action, inputString) => {
                    var bs = pad(inputString,intOption);
                    Console.WriteLine($"Arguments supplied: {intOption} {Action} {inputString}");
                    Console.WriteLine($"Padded string: {Encoding.Default.GetString(bs)}");
                    Console.WriteLine($"Trimmed {trim(bs)}");
                }
            );
            Console.WriteLine("helo");
            return rootCommand.InvokeAsync(args).Result;
        }

        public static byte[] pad(string s, int blockLength, bool key = false){

            //  byte string from character string
            var byteString = Encoding.Default.GetBytes(s);

            // calculate the number of blocks and padding bytes
            var blockCount = (int)(byteString.Length / blockLength) + 1;
            var padLength = blockCount * blockLength - byteString.Length;

            // add a whole block if no space for the pad count
            padLength = (padLength == 0) ? blockLength : padLength;

            // create the padding and preamble byte arrays
            var padding = new byte[padLength];
            var preamble = key ? new byte[0] : new byte[blockLength];

            // cryptographically secure RNG
            var rngcsp = RandomNumberGenerator.Create();
            rngcsp.GetBytes(padding,0,padLength-1);

            // fill the result
            padding[padLength-1] = (byte)padLength;
            if (preamble.Length != 0) rngcsp.GetBytes(preamble);
            var result = preamble.Concat(byteString).Concat(padding).ToArray();

            // linter thinks the type cast won't work even though it does.
            return result;
        }

        public static string trim(byte[] bs, int blockLength = 16)
        {
            // .. <- range operator
            // ^  <- inverse indexing operator
            return Encoding.Default.GetString(bs[blockLength..^(int)bs[^1]]);
        }

        public static byte[] encrypt(byte[] bs)
        {
            return new byte[1];
        }

        public static byte[] decrypt(byte[] bs)
        {
            return new byte[1];
        }
    }
}
