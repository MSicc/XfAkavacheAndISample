using System;
using System.Collections.Generic;
using System.Text;
using Akavache;

namespace XfAkavacheAndI.Abstractions
{
    public interface IBlobCacheInstanceHelper
    {
        void Init();

        IBlobCache LocalMachineCache { get; set; }

        ISecureBlobCache SecretLocalMachineCache { get; set; }
    }
}
