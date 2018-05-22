/*
Inspired from https://proandroiddev.com/secure-data-in-android-encryption-7eda33e68f58
*/

using Android.Content;
using Android.OS;
using Android.Security;
using Android.Security.Keystore;
using Java.Math;
using Java.Security;
using Javax.Security.Auth.X500;
using Calendar = Android.Icu.Util.Calendar;
using CalendarField = Android.Icu.Util.CalendarField;

namespace XfAkavacheAndI.Android.PlatformImplementations
{
    public class PlatformEncryptionKeyHelper
    {
        //do not change this name, this is where the keys have to be stored on Android
        static readonly  string   KEYSTORE_NAME = "AndroidKeyStore";
        private readonly KeyStore _androidKeyStore;

        private readonly Context _context;
        private readonly string  _keyName;

        //Supported sizes: 512, 768, 1024, 2048, 3072, 4096
        //default is 2048
        //Higher value means longer processing time!
        public int KeySize { get; set; } = 2048;

        public PlatformEncryptionKeyHelper(Context context, string keyName)
        {
            _context = context;
            _keyName = keyName.ToLowerInvariant();

            _androidKeyStore = KeyStore.GetInstance(KEYSTORE_NAME);
            _androidKeyStore.Load(null);
        }

        public bool DeleteKey()
        {
            if (!_androidKeyStore.ContainsAlias(_keyName))
                return false;

            _androidKeyStore.DeleteEntry(_keyName);
            return true;
        }

        public bool KeysExist()
        {
            return _androidKeyStore.ContainsAlias(_keyName);
        }

        public IKey GetPrivateKey()
        {
            if (!_androidKeyStore.ContainsAlias(_keyName))
                return null;

            return _androidKeyStore.GetKey(_keyName, null);
        }

        public IKey GetPublicKey()
        {
            if (!_androidKeyStore.ContainsAlias(_keyName))
                return null;

            return _androidKeyStore.GetCertificate(_keyName)?.PublicKey;
        }



        public void CreateKeyPair()
        {
            DeleteKey();

            KeyPairGenerator keyGenerator =
                KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmRsa, KEYSTORE_NAME);

            if (Build.VERSION.SdkInt >= BuildVersionCodes.JellyBeanMr2 &&
                Build.VERSION.SdkInt <= BuildVersionCodes.LollipopMr1)
            {
                var calendar = Calendar.GetInstance(_context.Resources.Configuration.Locale);
                var endDate = Calendar.GetInstance(_context.Resources.Configuration.Locale);
                endDate.Add(CalendarField.Year, 20);

                //this API is obsolete after Android M, but I am supporting Android L, so I need this
#pragma warning disable 618
                var builder = new KeyPairGeneratorSpec.Builder(_context)
#pragma warning restore 618
                              .SetAlias(_keyName).SetSerialNumber(BigInteger.One)
                              .SetSubject(new X500Principal($"CN={_keyName} CA Certificate"))
                              .SetStartDate(calendar.Time)
                              .SetEndDate(endDate.Time).SetKeySize(KeySize);

                keyGenerator.Initialize(builder.Build());
            }
            else if (Build.VERSION.SdkInt >= BuildVersionCodes.M)
            {
                var builder =
                    new KeyGenParameterSpec.Builder(_keyName, KeyStorePurpose.Encrypt | KeyStorePurpose.Decrypt)
                        .SetBlockModes(KeyProperties.BlockModeEcb)
                        .SetEncryptionPaddings(KeyProperties.EncryptionPaddingRsaPkcs1)
                        .SetRandomizedEncryptionRequired(false).SetKeySize(KeySize);

                keyGenerator.Initialize(builder.Build());
            }

            keyGenerator.GenerateKeyPair();
        }

    }
}