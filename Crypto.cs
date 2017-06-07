
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Crypt
{
    public static class Crypto
    {
        #region Settings

        private static int _iterations = 2;
        private static int _keySize = 128;

        private static string _hash = "SHA1";
        private static string _salt = "aselrias38490a32"; // Random
        private static string _vector = "8947az34awl34kjq"; // Random

        #endregion

        //public static string Encrypt(string plaintext, string password)
        //{
        //    return Encrypt<AesManaged>(Encoding.UTF8.GetBytes(plaintext), password);
        //}

        public static byte[] Encrypt(byte[] bytes, string password)
        {
            return Encrypt<AesManaged>(bytes, password);
        }
        public static byte[] Encrypt<T>(byte[] plaintext, string password)
            where T : SymmetricAlgorithm, new()
        {
            int padSize = _keySize / 8;
            byte[] saltBytes = CreateRandomBytes(padSize);
            PasswordDeriveBytes derivedPass = new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);

            byte[] ciphertext = new byte[0];
            using (T cipher = new T())
            {
                cipher.Mode = CipherMode.CBC;
                //cipher.Padding = PaddingMode.PKCS7;
                cipher.KeySize = _keySize;
                cipher.Key = derivedPass.GetBytes(padSize);
                cipher.IV = CreateRandomBytes(padSize);

                using (ICryptoTransform encryptor = cipher.CreateEncryptor())
                {
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            cs.Write(plaintext, 0, plaintext.Length);
                            cs.FlushFinalBlock();
                        }
                        ciphertext = ms.ToArray();
                    }
                }
                cipher.Clear();
            }

            return ciphertext;// Convert.ToBase64String(encrypted);
        }

        //public static byte[] Decrypt(byte[] ciphertext, string password)
        //{
        //    //return Decrypt<AesManaged>(Convert.FromBase64String(ciphertext), password);
        //    return Decrypt<AesManaged>(ciphertext, password);
        //}

        public static byte[] Decrypt(byte[] ciphertext, string password)
        {
            return Decrypt<AesManaged>(ciphertext, password);
        }
        public static byte[] Decrypt<T>(byte[] ciphertext, string password) where T : SymmetricAlgorithm, new()
        {
            int padSize = _keySize / 8;
            byte[] saltBytes = CreateRandomBytes(padSize);
            PasswordDeriveBytes derivedPass = new PasswordDeriveBytes(password, saltBytes, _hash, _iterations);

            byte[] decrypted;
            using (T cipher = new T())
            {
                cipher.Mode = CipherMode.CBC;
                //cipher.Padding = PaddingMode.PKCS7;
                cipher.KeySize = _keySize;
                cipher.Key = derivedPass.GetBytes(padSize);
                cipher.IV = CreateRandomBytes(padSize);

                try
                {
                    using (ICryptoTransform decryptor = cipher.CreateDecryptor())
                    {
                        using (MemoryStream ms = new MemoryStream(ciphertext))
                        {
                            using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                            {
                                //decrypted = new byte[ciphertext.Length];
                                cs.Write(ciphertext, 0, ciphertext.Length);
                                //writer.FlushFinalBlock();
                            }
                            decrypted = ms.ToArray();

                            //using (CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read))
                            //{

                            //    decrypted = new byte[ciphertext.Length];
                            //    decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                            //}
                        }
                    }
                }
                catch (Exception ex)
                {
                    return new byte[0];
                }

                cipher.Clear();
            }

            return decrypted;// Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
        }

        public static byte[] CreateRandomBytes(int length)
        {
            // Create a buffer
            byte[] randBytes;

            if (length >= 1)
            {
                randBytes = new byte[length];
            }
            else
            {
                randBytes = new byte[1];
            }

            // Create a new RNGCryptoServiceProvider.
            RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();

            // Fill the buffer with random bytes.
            rand.GetBytes(randBytes);

            // return the bytes.
            return randBytes;
        }

        public static void ClearBytes(byte[] buffer)
        {
            // Check arguments.
            if (buffer == null)
            {
                throw new ArgumentException("buffer");
            }

            // Set each byte in the buffer to 0.
            for (int x = 0; x < buffer.Length; x++)
            {
                buffer[x] = 0;
            }
        }















        private static readonly byte[] SALT = new byte[] { 0x26, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x22, 0x3c };

        public static byte[] Encrypt1(byte[] plaintext, string password)
        {
            Rijndael rijndael = Rijndael.Create();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
            rijndael.Key = pdb.GetBytes(32);
            rijndael.IV = pdb.GetBytes(16);
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(plaintext, 0, plaintext.Length);
                cryptoStream.Close();
                return memoryStream.ToArray();
            }
        }

        public static byte[] Decrypt2(byte[] ciphertext, string password)
        {
            Rijndael rijndael = Rijndael.Create();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
            rijndael.Key = pdb.GetBytes(32);
            rijndael.IV = pdb.GetBytes(16);
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                cryptoStream.Close();
                return memoryStream.ToArray();
            }
        }

    }
}
