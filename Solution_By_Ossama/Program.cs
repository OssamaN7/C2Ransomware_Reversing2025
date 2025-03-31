using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Solution_By_ossama
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=######################### Déchiffremente #########################=");
            Console.WriteLine();

            Console.WriteLine("[Clés statiques]");
            Console.WriteLine($"Clé statique (G): {Y.G()}");
            Console.WriteLine($"Clé IV (H): {Y.H()}");
            Console.WriteLine();

            Console.WriteLine("[Informations ]");
            Console.WriteLine($"URL C2: {Y.L()}");
            Console.WriteLine($"Username: {Y.O()}");
            Console.WriteLine($"Password: {Y.N()}");
            Console.WriteLine($"Clé secondaire (NBN): {Y.NBN()}");
            Console.WriteLine();

          
            Console.WriteLine("[Simulation du processus de chiffrement sur un fichier test ]");
            SimulateKeyGeneration();

            Console.WriteLine("\n....");
            Console.ReadKey();
        }

        static void SimulateKeyGeneration()
        {
            
            string testFolder = "fichiertest.txt";
            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

           
            string staticKey = Y.G();
            string dynamicKey = null; 

            Console.WriteLine("Mode offline (dynamicKey = null)");
            byte[] compKey = Y.ComputeCompositeKey(dynamicKey, staticKey, testFolder, timestamp);
            Console.WriteLine($"Clé composite (SHA256): {BitConverter.ToString(compKey).Replace("-", "")}");

           
            byte[] iv = Encoding.ASCII.GetBytes(Y.H().Substring(0, 16));
            Console.WriteLine($"IV (16 premiers occc de H: {BitConverter.ToString(iv).Replace("-", "")}");
        }
    }

    public static class Y
    {
        public static string G()
        {
            char[] array = new char[]
            {
                'A', 'A', '$', 'F', '2', '-', 'D', '8', 'C', '1',
                'E', '7', 'B', '9', 'F', '3', 'A', '3', '5', '@',
                'C', '8', '@', '!', 'B', 'B', '2', 'E', '1', 'F',
                '0', 'A', '7', 'C', '3', 'D'
            };
            return new string(array);
        }

        public static string H()
        {
            char[] array = new char[]
            {
                'D', '1', '@', 'E', '2', '#', 'F', '3', '%', 'A',
                '4', 'B', '5', '&', 'C', '6', 'D', '1', '@', 'E',
                '2', '#', 'F', '3', '%', 'A', '4', 'B', '5', '&',
                'C', '6', 'D', '1', '@', 'E', '2', '#', 'F', '3',
                '%', 'A', '4', 'B', '5', '&', 'C', '6'
            };
            return new string(array);
        }

        public static string L()
        {
            string text = "OF/sfn87WwjfIX14p17jp8mu5uavNFecb4D97pgVfZc=";
            byte[] bytes = Encoding.ASCII.GetBytes(Y.G().Substring(0, 16));
            byte[] bytes2 = Encoding.ASCII.GetBytes(Y.H().Substring(0, 16));
            return M(Convert.FromBase64String(text), bytes, bytes2);
        }

        public static string O()
        {
            string text = "3Npd3p5V7JSh6JZ5gqRmZg==";
            byte[] bytes = Encoding.ASCII.GetBytes(Y.G().Substring(0, 16));
            byte[] bytes2 = Encoding.ASCII.GetBytes(Y.H().Substring(0, 16));
            return M(Convert.FromBase64String(text), bytes, bytes2);
        }

        public static string N()
        {
            string text = "IeLkqcSXkaE8QamE7i4DEY3N7NmqJvAl1fzI7gIQkbo=";
            byte[] bytes = Encoding.ASCII.GetBytes(Y.G().Substring(0, 16));
            byte[] bytes2 = Encoding.ASCII.GetBytes(Y.H().Substring(0, 16));
            return M(Convert.FromBase64String(text), bytes, bytes2);
        }

        public static string NBN()
        {
            string text = "Wil860ds3vJiRDi+iTntnfknYML8iTowJsQe0uwmTms=";
            byte[] bytes = Encoding.ASCII.GetBytes(Y.G().Substring(0, 16));
            byte[] bytes2 = Encoding.ASCII.GetBytes(Y.H().Substring(0, 16));
            return M(Convert.FromBase64String(text), bytes, bytes2);
        }

        public static string M(byte[] d, byte[] k, byte[] i)
        {
            string text;
            using (Aes aes = Aes.Create())
            {
                aes.Key = k;
                aes.IV = i;
                ICryptoTransform cryptoTransform = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream memoryStream = new MemoryStream(d))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            text = streamReader.ReadToEnd();
                        }
                    }
                }
            }
            return text;
        }

        public static byte[] ComputeCompositeKey(string dkey, string skey, string folder, string timestamp)
        {
            string text = (dkey ?? "") + skey + folder + timestamp;
            byte[] array;
            using (SHA256 sha = SHA256.Create())
            {
                array = sha.ComputeHash(Encoding.ASCII.GetBytes(text));
            }
            return array;
        }
    }
}