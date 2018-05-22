/*
inspired by http://kent-boogaart.com/blog/password-protected-encryption-provider-for-akavache
*/

using System;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using Akavache;
using XfAkavacheAndI.iOS.PlatformImplementations;
using Security;

[assembly: Xamarin.Forms.Dependency(typeof(PlatformCustomAkavacheEncryptionProvider))]
namespace XfAkavacheAndI.iOS.PlatformImplementations
{
    public class PlatformCustomAkavacheEncryptionProvider : IEncryptionProvider
    {
        private readonly IScheduler _scheduler;

        private readonly PlatformEncryptionKeyHelper _encryptionKeyHelper;


        private SecKey _privateKey = null;
        private SecKey _publicKey  = null;

        public PlatformCustomAkavacheEncryptionProvider()
        {
            _scheduler = BlobCache.TaskpoolScheduler ??
                         throw new ArgumentNullException(nameof(_scheduler), "Scheduler is null");

            _encryptionKeyHelper = new PlatformEncryptionKeyHelper(BlobCache.ApplicationName.ToLower());
            GetOrCreateKeys();
        }

        public IObservable<byte[]> DecryptBlock(byte[] block)
        {
            if (block == null)
            {
                throw new ArgumentNullException(nameof(block), "block can't be null");
            }

            return Observable.Start(() => Decrypt(block), _scheduler);
        }

        public IObservable<byte[]> EncryptBlock(byte[] block)
        {
            if (block == null)
            {
                throw new ArgumentNullException(nameof(block), "block can't be null");
            }

            return Observable.Start(() => Encrypt(block), _scheduler);
        }


        private void GetOrCreateKeys()
        {
            if (!_encryptionKeyHelper.KeysExist())
                _encryptionKeyHelper.CreateKeyPair();

            _privateKey = _encryptionKeyHelper.GetPrivateKey();
            _publicKey = _encryptionKeyHelper.GetPublicKey();
        }

        private byte[] Encrypt(byte[] rawBytes)
        {
            if (_publicKey == null)
            {
                throw new ArgumentNullException(nameof(_publicKey), "Public key cannot be null");
            }

            var code = _publicKey.Encrypt(SecPadding.PKCS1, rawBytes, out var encryptedBytes);

            return code == SecStatusCode.Success ? encryptedBytes : null;
        }

        private byte[] Decrypt(byte[] encyrptedBytes)
        {
            if (_privateKey == null)
            {
                throw new ArgumentNullException(nameof(_privateKey), "Private key cannot be null");
            }

            var code = _privateKey.Decrypt(SecPadding.PKCS1, encyrptedBytes, out var decryptedBytes);

            return code == SecStatusCode.Success ? decryptedBytes : null;
        }


    }
}