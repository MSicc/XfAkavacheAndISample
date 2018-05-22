using System;
using System.Collections.Generic;
using System.IO;
using System.Reactive.Linq;
using System.Text;
using Akavache;
using Akavache.Sqlite3;
using XfAkavacheAndI.Abstractions;
using XfAkavacheAndI.iOS.PlatformImplementations;
using Splat;

//doing registrations manually
//https://github.com/akavache/Akavache/blob/501b397d8c071366c3b6783aae3e98695b3d7442/src/Akavache.Sqlite3/Registrations.cs


[assembly: Xamarin.Forms.Dependency(typeof(PlatformBlobCacheInstanceHelper))]
namespace XfAkavacheAndI.iOS.PlatformImplementations
{
    public class PlatformBlobCacheInstanceHelper : IBlobCacheInstanceHelper
    {
        private IFilesystemProvider _filesystemProvider;

        public PlatformBlobCacheInstanceHelper()
        {

        }

        public void Init()
        {
            _filesystemProvider = Locator.Current.GetService<IFilesystemProvider>();
            GetLocalMachineCache();
            GetSecretLocalMachineCache();
        }

        public IBlobCache LocalMachineCache { get; set; }
        public ISecureBlobCache SecretLocalMachineCache { get; set; }

        private void GetLocalMachineCache()
        {

            var localCache = new Lazy<IBlobCache>(() =>
            {
                _filesystemProvider.CreateRecursive(_filesystemProvider.GetDefaultLocalMachineCacheDirectory()).SubscribeOn(BlobCache.TaskpoolScheduler).Wait();
                return new SQLitePersistentBlobCache(Path.Combine(_filesystemProvider.GetDefaultLocalMachineCacheDirectory(), "blobs.db"), BlobCache.TaskpoolScheduler);
            });

            this.LocalMachineCache = localCache.Value;
        }

        private void GetSecretLocalMachineCache()
        {
            var secretCache = new Lazy<ISecureBlobCache>(() =>
            {
                _filesystemProvider.CreateRecursive(_filesystemProvider.GetDefaultSecretCacheDirectory()).SubscribeOn(BlobCache.TaskpoolScheduler).Wait();
                return new SQLiteEncryptedBlobCache(Path.Combine(_filesystemProvider.GetDefaultSecretCacheDirectory(), "secret.db"), new PlatformCustomAkavacheEncryptionProvider(), BlobCache.TaskpoolScheduler);
            });

            this.SecretLocalMachineCache = secretCache.Value;
        }

        //TODO: implement other cache types if necessary at some point
    }

}
