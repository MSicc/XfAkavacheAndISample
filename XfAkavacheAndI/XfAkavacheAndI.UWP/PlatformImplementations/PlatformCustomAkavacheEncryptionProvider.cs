using System;
using System.Collections.Generic;
using System.Linq;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.DataProtection;
using Windows.Storage.Streams;
using Akavache;
using XfAkavacheAndI.UWP.PlatformImplementations;

[assembly: Xamarin.Forms.Dependency(typeof(PlatformCustomAkavacheEncryptionProvider))]
namespace XfAkavacheAndI.UWP.PlatformImplementations
{
    public class PlatformCustomAkavacheEncryptionProvider : IEncryptionProvider
    {
        private readonly IScheduler _scheduler;

        private string _localUserDescriptor = "LOCAL=user";
        private string _localMachineDescriptor = "LOCAL=machine";

        public bool UseForAllUsers { get; set; } = false;

        public PlatformCustomAkavacheEncryptionProvider()
        {
            _scheduler = BlobCache.TaskpoolScheduler ??
                         throw new ArgumentNullException(nameof(_scheduler), "Scheduler is null");
        }

        public IObservable<byte[]> EncryptBlock(byte[] block)
        {
            if (block == null)
            {
                throw new ArgumentNullException(nameof(block), "block can't be null");
            }

            return Observable.Start(() => Encrypt(block).GetAwaiter().GetResult(), _scheduler);
        }

        public IObservable<byte[]> DecryptBlock(byte[] block)
        {
            if (block == null)
            {
                throw new ArgumentNullException(nameof(block), "block can't be null");
            }

            return Observable.Start(() => Decrypt(block).GetAwaiter().GetResult(), _scheduler);
        }


        public async Task<byte[]> Encrypt(byte[] data)
        {
            var provider = new DataProtectionProvider(UseForAllUsers ? _localMachineDescriptor : _localUserDescriptor);

            var contentBuffer = CryptographicBuffer.CreateFromByteArray(data);
            var contentInputStream = new InMemoryRandomAccessStream();
            var protectedContentStream = new InMemoryRandomAccessStream();

            //storing data in the stream
            IOutputStream outputStream = contentInputStream.GetOutputStreamAt(0);
            var dataWriter = new DataWriter(outputStream);
            dataWriter.WriteBuffer(contentBuffer);
            await dataWriter.StoreAsync();
            await dataWriter.FlushAsync();

            //reopening in input mode
            IInputStream encodingInputStream = contentInputStream.GetInputStreamAt(0);

            IOutputStream protectedOutputStream = protectedContentStream.GetOutputStreamAt(0);
            await provider.ProtectStreamAsync(encodingInputStream, protectedOutputStream);
            await protectedOutputStream.FlushAsync();

            //verify that encryption happened
            var inputReader = new DataReader(contentInputStream.GetInputStreamAt(0));
            var protectedReader = new DataReader(protectedContentStream.GetInputStreamAt(0));

            await inputReader.LoadAsync((uint)contentInputStream.Size);
            await protectedReader.LoadAsync((uint)protectedContentStream.Size);

            var inputBuffer = inputReader.ReadBuffer((uint)contentInputStream.Size);
            var protectedBuffer = protectedReader.ReadBuffer((uint)protectedContentStream.Size);

            if (!CryptographicBuffer.Compare(inputBuffer, protectedBuffer))
            {
               return protectedBuffer.ToArray();
            }
            else
            {
                return null;
            }
        }

        public async Task<byte[]> Decrypt(byte[] encryptedBytes)
        {
            var provider = new DataProtectionProvider();

            var encryptedContentBuffer = CryptographicBuffer.CreateFromByteArray(encryptedBytes);
            var contentInputStream = new InMemoryRandomAccessStream();
            var unprotectedContentStream = new InMemoryRandomAccessStream();

            IOutputStream outputStream = contentInputStream.GetOutputStreamAt(0);
            var dataWriter = new DataWriter(outputStream);
            dataWriter.WriteBuffer(encryptedContentBuffer);
            await dataWriter.StoreAsync();
            await dataWriter.FlushAsync();

            IInputStream decodingInputStream = contentInputStream.GetInputStreamAt(0);

            IOutputStream protectedOutputStream = unprotectedContentStream.GetOutputStreamAt(0);
            await provider.UnprotectStreamAsync(decodingInputStream, protectedOutputStream);
            await protectedOutputStream.FlushAsync();

            DataReader reader2 = new DataReader(unprotectedContentStream.GetInputStreamAt(0));
            await reader2.LoadAsync((uint)unprotectedContentStream.Size);
            IBuffer unprotectedBuffer = reader2.ReadBuffer((uint)unprotectedContentStream.Size);

            return unprotectedBuffer.ToArray();
        }


    }   
}
