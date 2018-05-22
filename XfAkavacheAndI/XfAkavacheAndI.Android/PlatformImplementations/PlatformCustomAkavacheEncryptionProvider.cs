/*
inspired by http://kent-boogaart.com/blog/password-protected-encryption-provider-for-akavache
*/

using System;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using Akavache;
using Android.App;
using Java.Security;
using Javax.Crypto;
using XfAkavacheAndI.Android.PlatformImplementations;
using CipherMode = Javax.Crypto.CipherMode;

[assembly: Xamarin.Forms.Dependency(typeof(PlatformCustomAkavacheEncryptionProvider))]
namespace XfAkavacheAndI.Android.PlatformImplementations
{
    public class PlatformCustomAkavacheEncryptionProvider : IEncryptionProvider
    {
        private readonly IScheduler _scheduler;

        private static readonly string KeyStoreName = $"{BlobCache.ApplicationName.ToLower()}_secureStore";

        private readonly PlatformEncryptionKeyHelper _encryptionKeyHelper;

        private const string TRANSFORMATION = "RSA/ECB/PKCS1Padding";
        private IKey _privateKey = null;
        private IKey _publicKey = null;

        public PlatformCustomAkavacheEncryptionProvider()
        {
            _scheduler = BlobCache.TaskpoolScheduler ?? throw new ArgumentNullException(nameof(_scheduler), "Scheduler is null");

            _encryptionKeyHelper = new PlatformEncryptionKeyHelper(Application.Context, KeyStoreName);
            GetOrCreateKeys();
        }

        public IObservable<byte[]> DecryptBlock(byte[] block)
        {
            if (block == null)
            {
                throw new ArgumentNullException(nameof(block), "block cannot be null");
            }

            return Observable.Start(() => Decrypt(block), _scheduler);
        }

        public IObservable<byte[]> EncryptBlock(byte[] block)
        {
            if (block == null)
            {
                throw new ArgumentNullException(nameof(block), "block cannot be null");
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


        public byte[] Encrypt(byte[] rawBytes)
        {
            if (_publicKey == null)
            {
                throw new ArgumentNullException(nameof(_publicKey), "Public key cannot be null");
            }

            var cipher = Cipher.GetInstance(TRANSFORMATION);
            cipher.Init(CipherMode.EncryptMode, _publicKey);

            return cipher.DoFinal(rawBytes);
        }

        public byte[] Decrypt(byte[] encyrptedBytes)
        {
            if (_privateKey == null)
            {
                throw new ArgumentNullException(nameof(_privateKey), "Private key cannot be null");
            }

            var cipher = Cipher.GetInstance(TRANSFORMATION);
            cipher.Init(CipherMode.DecryptMode, _privateKey);

            return cipher.DoFinal(encyrptedBytes);
        }


    }
}