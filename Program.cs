using System;
using System.IO;
using System.Linq;
using Crypt;
using CommandLine;
using CommandLine.Text;

namespace crypt
{
    class Options
    {
        [Option('E', "encode", Required = false, HelpText = "Input file to encode.")]
        public string EncryptFilename { get; set; }

        [Option('D', "decode", Required = false, HelpText = "Input file to decode.")]
        public string DecryptFilename { get; set; }

        [Option('O', "output", Required = false, HelpText = "Output file.")]
        public string OutputFilename { get; set; }

        [Option('T', "test", Required = false, HelpText = "Input file to test encoding/decoding")]
        public string TestFilename { get; set; }

        [Option('P', "password", Required = false, HelpText = "Password.")]
        public string Password { get; set; }

        [Option('V', "verbose", DefaultValue = true, HelpText = "Verbose operation")]
        public bool Verbose { get; set; }

        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            return HelpText.AutoBuild(this, (HelpText current) => HelpText.DefaultParsingErrorsHandler(this, current));
        }

        public Mode Mode { get; set; }
    }

    enum Mode
    {
        Encryption,
        Decryption,
        Testing
    }

    class Program
    {
        static void Main(string[] args)
        {
            var program = new Program();
            Options options = program.EnsureArgs(args);
            switch (options.Mode)
            {
                case Mode.Encryption:
                    program.Encrypt(options);
                    break;

                case Mode.Decryption:
                    program.Decrypt(options);
                    break;

                case Mode.Testing:
                    program.Test(options);
                    break;
            }
        }

        private void Encrypt(Options options)
        {
            try
            {
                byte[] plaintext = File.ReadAllBytes(options.EncryptFilename);
                File.WriteAllBytes(options.OutputFilename, Crypto.Encrypt(plaintext, options.Password));
            }
            catch (Exception e)
            {
                Console.WriteLine($"Cannot encrypt file [{options.EncryptFilename}] due to: {e.Message}");
            }
        }

        private void Decrypt(Options options)
        {
            try
            {
                byte[] ciphertext = File.ReadAllBytes(options.DecryptFilename);
                File.WriteAllBytes(options.OutputFilename, Crypto.Decrypt(ciphertext, options.Password));
            }
            catch (Exception e)
            {
                Console.WriteLine($"Cannot encrypt file [{options.EncryptFilename}] due to: {e.Message}");
            }
        }

        private void Test(Options options)
        {
            string password = "Dim3loC@nt@nd0, Chico!";
            try
            {
                Console.Write($"Encoding/Decoding [{options.TestFilename}]...");
                byte[] plaintext = File.ReadAllBytes(options.TestFilename);
                byte[] ciphertext = Crypto2.Encrypt(plaintext, password);
                byte[] utest = Crypto2.Decrypt(ciphertext, password);
                Console.WriteLine(plaintext.SequenceEqual(utest) ? "Good" : "Failed!");
                Console.WriteLine($" Encypted: {plaintext.Length,10} characters");
                Console.WriteLine($"Decrypted: {ciphertext.Length,10} characters");
            }
            catch (Exception e)
            {
                Console.WriteLine("Failed");
                Console.WriteLine($"Error: {e.Message}");
            }
        }

        private Options EnsureArgs(string[] args)
        {
            var options = new Options();
            var parser = new Parser();
            if (parser.ParseArguments(args, options))
            {
                if (options.EncryptFilename != null && options.DecryptFilename != null)
                {
                    Console.WriteLine("Error: Must provide either -E or -D, not both");
                    Environment.Exit(-1);
                }
                if (options.TestFilename != null)
                {
                    if (!File.Exists(options.TestFilename))
                    {
                        Console.WriteLine($"Error: File {options.TestFilename} does not exist.");
                        Environment.Exit(-1);
                    }
                    options.Mode = Mode.Testing;
                }
                else
                {
                    if (options.EncryptFilename != null)
                    {
                        if (!File.Exists(options.EncryptFilename))
                        {
                            Console.WriteLine($"File {options.EncryptFilename} does not exist.");
                            Environment.Exit(-1);
                        }
                        options.Mode = Mode.Encryption;
                    }
                    else if (options.DecryptFilename != null)
                    {
                        if (!File.Exists(options.DecryptFilename))
                        {
                            Console.WriteLine($"Error: File {options.DecryptFilename} does not exist.");
                            Environment.Exit(-1);
                        }
                        options.Mode = Mode.Decryption;
                    }
                    else
                    {
                        // ERROR!
                        Console.WriteLine(options.GetUsage());
                        Console.WriteLine("Error: Must provide either -E or -D or -T option");
                        Environment.Exit(-1);
                    }

                    if (!IsStrongPassword(options.Password))
                    {
                        Console.WriteLine("Error: Must provide a strong password (Capitals, lowercase and symbols)");
                        Environment.Exit(-1);
                    }

                }

                return options;
            }

            Environment.Exit(-1);
            return null;
        }

        private bool IsStrongPassword(string password)
        {
            return true;
        }

    }
}
