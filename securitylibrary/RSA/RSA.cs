using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            long n = p * q;
            return (int)power(M, e, n);
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

        public int Decrypt(int p, int q, int C, int e)
        {
            long Qn = (p - 1) * (q - 1);
            long d = GetMultiplicativeInverse(e, (int)Qn);
            long n = p * q;
            return (int)power(C , d , n);
            //throw new NotImplementedException();
        }

        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int a1 = 1, a2 = 0, a3 = baseN;
            int b1 = 0, b2 = 1, b3 = number;
            while (b3 != 0 && b3 != 1)
            {
                int q = a3 / b3;
                int B1 = a1 - (q * b1), B2 = a2 - (q * b2), B3 = a3 - (q * b3);

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
    }
}