using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Crypt
{
    static class StreamExtensions
    {
        public static byte[] ReadAllBytes(this BinaryReader reader)
        {
            using (var ms = new MemoryStream())
            {
                reader.BaseStream.CopyTo(ms);
                return ms.ToArray();
            }
        }
    }
}
