using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KomunikacePomociModernichSifer
{
    public class cRSA
    {
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }
        public static string ByteArrayToHexString(byte[] byteArray)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in byteArray)
            {
                sb.Append(string.Format("{0:X2}", b));
            }
            return sb.ToString();
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
        public cRSA()
        {
            using (RSA rsa = RSA.Create())
            {
                PublicKey = rsa.ExportRSAPublicKey();
                PrivateKey = rsa.ExportRSAPrivateKey();
            }
        }

        public static byte[] Encrypt(byte[] publicKey, string message)
        {
            byte[] original = Encoding.UTF8.GetBytes(message);
            byte[] encrypted;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(publicKey, out int amount);
                encrypted = rsa.Encrypt(original, RSAEncryptionPadding.Pkcs1);
            }
            return encrypted;
        }

        public static string Decrypt(byte[] privateKey, byte[] message)
        {
            byte[] received;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(privateKey, out int amount);
                received = rsa.Decrypt(message, RSAEncryptionPadding.Pkcs1);
            }
            return Encoding.UTF8.GetString(received);
        }





        public static byte[] EncryptUsingPrivateKey(byte[] privateKey, string message)
        {
            byte[] original = Encoding.UTF8.GetBytes(message);
            byte[] encrypted;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(privateKey, out int amount);
                encrypted = rsa.Encrypt(original, RSAEncryptionPadding.Pkcs1);
            }
            return encrypted;
        }
        public static string DecryptUsingPublicKey(byte[] publicKey, byte[] message)
        {
            byte[] received;
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(publicKey, out int amount);
                received = rsa.Decrypt(message, RSAEncryptionPadding.Pkcs1);
            }
            return Encoding.UTF8.GetString(received);
        }

        public static byte[] Sign(string message, byte[] privateKey)
        {
            byte[] original = Encoding.UTF8.GetBytes(message);
            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out _);
            byte[] signature = rsa.SignData(original, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rsa.Dispose();

            return signature;
        }
        public static bool VerifySignature(string message, byte[] signature, string publicKey)
        {
            byte[] original = Encoding.UTF8.GetBytes(message);
            RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(HexStringToByteArray(publicKey), out _);
            bool verifiedSignature = (bool)rsa.VerifyData(original, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rsa.Dispose();
            return verifiedSignature;
        }
    }
}
