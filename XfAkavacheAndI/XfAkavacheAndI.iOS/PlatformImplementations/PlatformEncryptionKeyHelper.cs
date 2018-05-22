using System;
using System.Collections;
using System.Collections.Generic;
using Security;
using Foundation;
using System.Diagnostics;
using System.Linq;
using ObjCRuntime;

namespace XfAkavacheAndI.iOS.PlatformImplementations
{
    public class PlatformEncryptionKeyHelper
    {
        private readonly bool _shouldSyncAcrossDevices;

        private readonly string _keyName;

        public int KeySize { get; set; } = 2048;

        public PlatformEncryptionKeyHelper(string keyname, bool shouldSyncAcrossDevices = false)
        {
            _keyName = !string.IsNullOrEmpty(keyname) ? keyname.ToLowerInvariant() : $"{nameof(PlatformEncryptionKeyHelper).ToLowerInvariant()}";

            _shouldSyncAcrossDevices = shouldSyncAcrossDevices;
        }

        public bool KeysExist()
        {
            return GetPrivateKey() != null;
        }
        public bool Delete()
        {
            var findExisting = new SecRecord(SecKind.Key)
            {
                ApplicationTag = NSData.FromString(this._keyName, NSStringEncoding.UTF8),
                KeyType = SecKeyType.RSA,
                Synchronizable = this._shouldSyncAcrossDevices
            };

            SecStatusCode code = SecKeyChain.Remove(findExisting);

            return code == SecStatusCode.Success;
        }

        public SecKey GetPrivateKey()
        {
            var privateKey = SecKeyChain.QueryAsConcreteType(
                new SecRecord(SecKind.Key)
                {
                    ApplicationTag = NSData.FromString(this._keyName, NSStringEncoding.UTF8),
                    KeyType = SecKeyType.RSA,
                    Synchronizable = this._shouldSyncAcrossDevices
                },
                out var code);

            return code == SecStatusCode.Success ? privateKey as SecKey : null;
        }

        public SecKey GetPublicKey()
        {
            return GetPrivateKey()?.GetPublicKey();
        }

        public bool CreateKeyPair()
        {
            Delete();
            var keyParams = CreateRsaParams();

            SecKey.CreateRandomKey(keyParams, out var keyCreationError);

            if (keyCreationError != null)
            {
                Debug.WriteLine($"{keyCreationError.LocalizedFailureReason}\n{keyCreationError.LocalizedDescription}");
            }

            return keyCreationError == null;
        }
        
        private NSDictionary CreateRsaParams()
        {
            IList<object> keys = new List<object>();
            IList<object> values = new List<object>();

            //creating the private key params
            keys.Add(IosConstants.Instance.KSecAttrApplicationTag);
            keys.Add(IosConstants.Instance.KSecAttrIsPermanent);
            keys.Add(IosConstants.Instance.KSecAttrAccessible);

            values.Add(NSData.FromString(this._keyName, NSStringEncoding.UTF8));
            values.Add(NSNumber.FromBoolean(true));
            values.Add(IosConstants.Instance.KSecAccessibleWhenUnlocked);

            NSDictionary privateKeyAttributes = NSDictionary.FromObjectsAndKeys(values.ToArray(), keys.ToArray());

            keys.Clear();
            values.Clear();

            //creating the keychain entry params
            //no need for public key params, as it will from the private key once it is needed
            keys.Add(IosConstants.Instance.KSecAttrKeyType);
            keys.Add(IosConstants.Instance.KSecAttrKeySize);
            keys.Add(IosConstants.Instance.KSecPrivateKeyAttrs);

            values.Add(IosConstants.Instance.KSecAttrKeyTypeRSA);
            values.Add(NSNumber.FromInt32(this.KeySize));
            values.Add(privateKeyAttributes);

            return NSDictionary.FromObjectsAndKeys(values.ToArray(), keys.ToArray());
        }


    }

    //Xamarin does not expose these values, so we have to pick them up manually
    internal class IosConstants
    {
        private static IosConstants _instance;

        public static IosConstants Instance => _instance ?? (_instance = new IosConstants());

        public readonly NSString KSecAttrKeyType;
        public readonly NSString KSecAttrKeySize;
        public readonly NSString KSecAttrKeyTypeRSA;
        public readonly NSString KSecAttrIsPermanent;
        public readonly NSString KSecAttrApplicationTag;
        public readonly NSString KSecPrivateKeyAttrs;
        public readonly NSString KSecClass;
        public readonly NSString KSecClassKey;
        public readonly NSString KSecPaddingPKCS1;
        public readonly NSString KSecAccessibleWhenUnlocked;
        public readonly NSString KSecAttrAccessible;

        public IosConstants()
        {
            var handle = Dlfcn.dlopen(Constants.SecurityLibrary, 0);

            try
            {
                KSecAttrApplicationTag = Dlfcn.GetStringConstant(handle, "kSecAttrApplicationTag");
                KSecAttrKeyType = Dlfcn.GetStringConstant(handle, "kSecAttrKeyType");
                KSecAttrKeyTypeRSA = Dlfcn.GetStringConstant(handle, "kSecAttrKeyTypeRSA");
                KSecAttrKeySize = Dlfcn.GetStringConstant(handle, "kSecAttrKeySizeInBits");
                KSecAttrIsPermanent = Dlfcn.GetStringConstant(handle, "kSecAttrIsPermanent");
                KSecPrivateKeyAttrs = Dlfcn.GetStringConstant(handle, "kSecPrivateKeyAttrs");
                KSecClass = Dlfcn.GetStringConstant(handle, "kSecClass");
                KSecClassKey = Dlfcn.GetStringConstant(handle, "kSecClassKey");
                KSecPaddingPKCS1 = Dlfcn.GetStringConstant(handle, "kSecPaddingPKCS1");
                KSecAccessibleWhenUnlocked = Dlfcn.GetStringConstant(handle, "kSecAttrAccessibleWhenUnlocked");
                KSecAttrAccessible = Dlfcn.GetStringConstant(handle, "kSecAttrAccessible");

            }
            finally
            {
                Dlfcn.dlclose(handle);
            }
        }
    }
}