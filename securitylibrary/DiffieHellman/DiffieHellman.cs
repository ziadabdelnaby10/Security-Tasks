using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            long Ya , Yb;
            Ya = power(alpha , xa , q);
            Yb = power(alpha, xb, q);

            List<int> keys = new List<int>();
            keys.Add((int)power(Yb , xa , q));
            keys.Add((int)power(Ya, xb, q));
            return keys;
            //throw new NotImplementedException();
        }

        public long power(long x, long y, long p)
        {
            long res = 1; // Initialize result

            x = x % p; // Update x if it is more than or
                       // equal to p

            if (x == 0)
                return 0; // In case x is divisible by p;

            while (y > 0)
            {

                // If y is odd, multiply x with result
                if ((y & 1) != 0)
                    res = (res * x) % p;

                // y must be even now
                y = y >> 1; // y = y/2
                x = (x * x) % p;
            }
            return res;
        }
    }
}
