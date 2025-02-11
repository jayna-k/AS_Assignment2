using System.Security.Cryptography;

namespace AS_Assignment2.Services
{
    public static class AesEncryption
    {
        public interface IEncryptionService
        {
            string Encrypt(string plainText);
            string Decrypt(string cipherText);
        }

        public class AesEncryptionService : IEncryptionService
        {
            private readonly byte[] _key;
            private readonly byte[] _iv;

            public AesEncryptionService(IConfiguration config)
            {
                _key = Convert.FromBase64String(config["Encryption:Key"]);
                _iv = Convert.FromBase64String(config["Encryption:IV"]);

                if (_key.Length != 32) // 32 bytes for AES-256
                    throw new ArgumentException("Encryption key must be 32 bytes (256 bits).");

                if (_iv.Length != 16) // 16 bytes for AES
                    throw new ArgumentException("Initialization Vector (IV) must be 16 bytes (128 bits).");
            }

            public string Encrypt(string plainText)
            {
                using var aes = Aes.Create();
                aes.Key = _key;
                aes.IV = _iv;

                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using var ms = new MemoryStream();
                using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
                using (var sw = new StreamWriter(cs))
                {
                    sw.Write(plainText);
                }
                return Convert.ToBase64String(ms.ToArray());
            }

            public string Decrypt(string cipherText)
            {
                var buffer = Convert.FromBase64String(cipherText);
                using var aes = Aes.Create();
                aes.Key = _key;
                aes.IV = _iv;

                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using var ms = new MemoryStream(buffer);
                using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
                using var sr = new StreamReader(cs);
                return sr.ReadToEnd();
            }
        }
    }
}

