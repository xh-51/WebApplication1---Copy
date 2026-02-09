using Microsoft.AspNetCore.DataProtection;

namespace WebApplication1.Services
{
    /// <summary>
    /// Service for encrypting and decrypting sensitive data before saving to database
    /// Similar to the pattern shown in Register.cshtml.cs example
    /// </summary>
    public class EncryptionService
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly IDataProtector _protector;

        public EncryptionService(IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
            // Use CreateProtector method to generate the secret instance
            // To do that, you will need a secret string
            // Use Protect method to encrypt and Unprotect method to decrypt
            _protector = _dataProtectionProvider.CreateProtector("MySecretKey");
        }

        /// <summary>
        /// Encrypts sensitive data before saving to database
        /// Example: CreditCard = protector.Protect(RModel.CreditCard)
        /// </summary>
        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            return _protector.Protect(plainText);
        }

        /// <summary>
        /// Decrypts data when retrieving from database
        /// Example: string decryptedValue = protector.Unprotect(encryptedValueFromDatabase)
        /// </summary>
        public string Decrypt(string encryptedText)
        {
            if (string.IsNullOrEmpty(encryptedText))
                return encryptedText;

            return _protector.Unprotect(encryptedText);
        }
    }
}
