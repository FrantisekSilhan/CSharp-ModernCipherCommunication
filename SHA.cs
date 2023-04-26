using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace KomunikacePomociModernichSifer
{
    public class SHA
    {
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
        public static string GenerateHash(string message)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                return ByteArrayToHexString(sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(message)));
            }
            
        }
        public static void PrintMessage(string message)
        {
            Console.WriteLine("--------------------");
            Console.WriteLine(message);
            Console.WriteLine();
            Console.WriteLine("Hash: SHA256");
            Console.WriteLine(GenerateHash(message));
            Console.WriteLine("--------------------");
        }

        public static bool VerifyHash(string message, string hash)
        {
            return GenerateHash(message) == hash;
        }
    }
}