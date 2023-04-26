using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace KomunikacePomociModernichSifer
{
    public class cAES
    {
        public byte[] Key { get; set; }
        public byte[] Iv { get; set; }

        public cAES() {
            using (Aes aes = Aes.Create())
            {
                Key = aes.Key;
                Iv = aes.IV;
            }
        }

        public static byte[] HexStringToByteArray(string hexString)
        {
            int length = hexString.Length;
            byte[] byteArray = new byte[length / 2];
            for (int i = 0; i < length; i += 2)
            {
                byteArray[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }
            return byteArray;
        }
        public static void printByte(byte[] byteArray)
        {
            foreach (byte b in byteArray)
            {
                Console.Write(string.Format("{0:X2}", b));
            }
            Console.WriteLine();
        }

        public static byte[] Encrypt(byte[] key, byte[] iv, string message)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            byte[] encrypted;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter swEncrypt = new BinaryWriter(csEncrypt))
                        {
                            swEncrypt.Write(data);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        public static string Decrypt(byte[] key, byte[] iv, byte[] encrypted)
        {
            byte[] received;
            
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (BinaryReader srDecrypt = new BinaryReader(csDecrypt))
                        {
                            received = srDecrypt.ReadBytes((int)msDecrypt.Length);
                        }
                    }
                }
            }
            
            return Encoding.UTF8.GetString(received);
        }
    }
}
