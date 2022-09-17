using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> list = new List<long>();
            long K = power(y, k, q);
            list.Add(power(alpha , k , q));
            list.Add((K*m)%q);
            return list;
            //throw new NotImplementedException();
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            long k = power(c1 , x , q);
            long K = GetMultiplicativeInverse(k, q);
            long m = (c2 * K) % q;
            return (int)m;
            //throw new NotImplementedException();

        }

        public long GetMultiplicativeInverse(long number, long baseN)
        {
            long a1 = 1, a2 = 0, a3 = baseN;
            long b1 = 0, b2 = 1, b3 = number;

            while (b3 != 0 && b3 != 1)
            {
                long q = a3 / b3;
                long B1 = a1 - (q * b1);
                long B2 = a2 - (q * b2);
                long B3 = a3 - (q * b3);

                a1 = b1;
                a2 = b2;
                a3 = b3;
                b1 = B1;
                b2 = B2;
                b3 = B3;
            }

            if (b3 == 0)
            {
                return -1;
            }
            else if (b3 == 1)
            {
                if (b2 < -1)
                {
                    b2 += baseN;
                }
                return b2;
            }

            return -1;
            
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
