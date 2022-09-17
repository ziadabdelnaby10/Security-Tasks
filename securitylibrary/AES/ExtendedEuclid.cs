using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
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
                if(b2 < -1)
                {
                    b2 += baseN;
                }
                return b2;
            }

            return -1;
            //mod inverse
            //int g , x = -1, y = -1;
            //Tuple<int, int, int> gcd_res = GCDExtended(number, baseN, x, y);

            //g = gcd_res.Item1;
            //x = gcd_res.Item2;
            //y = gcd_res.Item3;
            //if (g != 1)
            //    return -1;
            //else
            //{
            //    int res = (x % baseN + baseN) % baseN;
            //    return res;
            //}
            //throw new NotImplementedException();
        }
        public int GCD(int a, int b)
        {
            return b == 0 ? a : GCD(b, a % b);
        }

        Tuple<int , int , int> GCDExtended(int number, int baseN, int x, int y)
        {
            if (number == 0)
            {
                x = 0;
                y = 1;
                return Tuple.Create(number, x , y);
            }

            int gcd, x1 = -1, y1 = -1;
            Tuple <int , int , int> res = GCDExtended(baseN % number, number, x1, y1);
            gcd = res.Item1;
            x1 = res.Item2;
            y1 = res.Item3;

            x = y1 - (baseN / number) * x1;
            y = x1;

            return Tuple.Create(gcd, x, y);
        }
    }
}
