using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {

       public int getDet(int[,] matrix)
        {
            int det = (matrix[0, 0] * matrix[1, 1]) - (matrix[1, 0] * matrix[0, 1]);
            return det;
        }
        public int gcd(int n1, int n2)
        {
            if (n2 == 0)
            {
                return n1;
            }
            else
            {
                return gcd(n2, n1 % n2);
            }
        }
        public bool validateDet(int det)
        {
            if (gcd(det, 26) == 1) return true;
            return false;
        }
        public int[,] getInverse(int[,] miniMatrix)
        {
            int[,] matrixInverse = new int[2, 2];
            int detValue = ((miniMatrix[0, 0] * miniMatrix[1, 1]) -
                (miniMatrix[0, 1] * miniMatrix[1, 0])) % 26;
            int x = 0;
            for (int i = 1; i < 26; i++)
            {
                if (((detValue * i) % 26) == 1)
                {
                    x = i;
                    break;
                }
            }
            matrixInverse[0, 0] = ((miniMatrix[1, 1] % 26) * x) % 26;
            matrixInverse[0, 1] = (((((-1 * miniMatrix[0, 1]) % 26) + 26) % 26) * x) % 26;
            matrixInverse[1, 0] = (((((-1 * miniMatrix[1, 0]) % 26) + 26) % 26) * x) % 26;
            matrixInverse[1, 1] = (miniMatrix[0, 0] % 26 * x) % 26;

            return matrixInverse;
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int plainLen = plainText.Count / 2;
            int[,] plainMap = new int[2, plainLen];
            int[,] cyphrMap = new int[2, plainLen];
            int x = 0;
            for (int i = 0; i < plainLen; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    plainMap[j, i] = plainText[x];
                    x++;
                }
            }
            x = 0;
            for (int i = 0; i < plainLen; i++)
            {
                for (int j = 0; j < 2; j++)
                {
                    cyphrMap[j, i] = cipherText[x];
                    x++;
                }
            }
            int[,] matrix = new int[2, 2];
            bool p = false;
            int a = 0, b = 0;
            for (int i = 0; i < plainLen - 1; i++)
            {
                for (int j = i + 1; j < plainLen; j++)
                {
                    matrix[0, 0] = plainMap[0, i];
                    matrix[0, 1] = plainMap[0, j];
                    matrix[1, 0] = plainMap[1, i];
                    matrix[1, 1] = plainMap[1, j];
                    int det = getDet(matrix);
                    if (validateDet(det))
                    {
                        p = true;
                        a = i; b = j;
                        break;
                    }
                    
                }
            }

            int[,] ciphr = new int[2, 2];
            if (p)
            {
                matrix[0, 0] = plainMap[0, a];
                matrix[0, 1] = plainMap[0, b];
                matrix[1, 0] = plainMap[1, a];
                matrix[1, 1] = plainMap[1, b];

                ciphr[0, 0] = cyphrMap[0, a];
                ciphr[0, 1] = cyphrMap[0, b];
                ciphr[1, 0] = cyphrMap[1, a];
                ciphr[1, 1] = cyphrMap[1, b];
            }
            else
            {
                throw (new InvalidAnlysisException());
            }
            matrix = getInverse(matrix);

            List<int> key = new List<int>();
            key.Add(((ciphr[0, 0] * matrix[0, 0]) + (ciphr[0, 1] * matrix[1, 0])) % 26);
            key.Add(((ciphr[0, 0] * matrix[0, 1]) + (ciphr[0, 1] * matrix[1, 1])) % 26);
            key.Add(((ciphr[1, 0] * matrix[0, 0]) + (ciphr[1, 1] * matrix[1, 0])) % 26);
            key.Add(((ciphr[1, 0] * matrix[0, 1]) + (ciphr[1, 1] * matrix[1, 1])) % 26);
            return key;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int det = 0;
            List<int> inverseKey = new List<int>();
            List<int> multi = new List<int>();
            if (key.Count == 4)
            {
                List<int> keyTranspose = new List<int>();
                det = 1 / (key[0] * key[3] - key[1] * key[2]);
                if (det >= 1 || det <= -1)
                {
                    keyTranspose.Add(key[3]);
                    keyTranspose.Add(-1 * key[1]);
                    keyTranspose.Add(-1 * key[2]);
                    keyTranspose.Add(key[0]);
                    for (int j = 0; j < keyTranspose.Count; j++)
                    {
                        inverseKey.Add(keyTranspose[j] * det);
                    }

                    int i = 0;

                    while (i < cipherText.Count)
                    {
                        if (i < cipherText.Count && i + 1 < cipherText.Count)
                        {
                            int x = (inverseKey[0] * cipherText[i] + inverseKey[1] * cipherText[i + 1]) % 26;
                            while (x < 0)
                            {
                                x += 26;
                            }
                            multi.Add(x);
                            int x2 = (inverseKey[2] * cipherText[i] + inverseKey[3] * cipherText[i + 1]) % 26;
                            while (x2 < 0)
                            {
                                x2 += 26;
                            }
                            multi.Add(x2);
                            i += 2;
                        }
                    }
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
            else
            {
                int b = 0;
                List<int> key2 = new List<int>();
                det = key[0] * (key[4] * key[8] - key[5] * key[7]) -
                    key[1] * (key[3] * key[8] - key[5] * key[6])
                    + key[2] * (key[3] * key[7] - key[4] * key[6]);
                det = det % 26;
                while (det < 0)
                {
                    det += 26;
                }
                if (det > 0)
                {
                    bool flag = false;
                    for (int j = 0; j < key.Count; j++)
                    {
                        if (key[j] < 0 || key[j] > 26)
                            flag = true;
                    }
                    if (flag == false)
                    {
                        int x = 26;
                        bool check = false;
                        for (int j = 2; j < x; j++)
                        {
                            if (x % j == 0 && det % j == 0)
                            {
                                check = true;
                                break;
                            }
                        }
                        if (check == true)
                        {
                            throw new NotImplementedException();
                        }
                        else
                        {
                            int y = 26 - det;
                            if (1 / y < 1)
                            {
                                int s = x + 1;
                                int c = 0;
                                while (true)
                                {
                                    if (s % y != 0)
                                    {
                                        s = s + 1;
                                    }
                                    else
                                    {
                                        if (s % x != 1)
                                        {
                                            s = s + 1;
                                        }
                                        else
                                        {
                                            break;
                                        }
                                    }

                                }
                                c = s / y;
                                b = x - c;
                            }
                            else
                            {
                                b = 26 - y;
                            }
                            int y0 = (b * Convert.ToInt32((Math.Pow(-1, 0 + 0)) * (key[4] * key[8] - key[5] * key[7]))) % 26;
                            while (y0 < 0)
                            {
                                y0 += 26;
                            }
                            key2.Add(y0);

                            int y1 = (b * Convert.ToInt32(Math.Pow(-1, 0 + 1)) * (key[3] * key[8] - key[5] * key[6])) % 26;
                            while (y1 < 0)
                            {
                                y1 += 26;
                            }
                            key2.Add(y1);
                            int y2 = (b * Convert.ToInt32(Math.Pow(-1, 0 + 2)) * (key[3] * key[7] - key[4] * key[6])) % 26;
                            while (y2 < 0)
                            {
                                y2 += 26;
                            }
                            key2.Add(y2);

                            int y3 = (b * Convert.ToInt32(Math.Pow(-1, 1 + 0)) * (key[1] * key[8] - key[2] * key[7])) % 26;
                            while (y3 < 0)
                            {
                                y3 += 26;
                            }
                            key2.Add(y3);

                            int y4 = (b * Convert.ToInt32(Math.Pow(-1, 1 + 1)) * (key[0] * key[8] - key[2] * key[6])) % 26;
                            while (y4 < 0)
                            {
                                y4 += 26;
                            }
                            key2.Add(y4);

                            int y5 = (b * Convert.ToInt32(Math.Pow(-1, 1 + 2)) * (key[0] * key[7] - key[1] * key[6])) % 26;
                            while (y5 < 0)
                            {
                                y5 += 26;
                            }
                            key2.Add(y5);

                            int y6 = (b * Convert.ToInt32(Math.Pow(-1, 2 + 0)) * (key[1] * key[5] - key[2] * key[4])) % 26;
                            while (y6 < 0)
                            {
                                y6 += 26;
                            }
                            key2.Add(y6);

                            int y7 = (b * Convert.ToInt32(Math.Pow(-1, 2 + 1)) * (key[0] * key[5] - key[2] * key[3])) % 26;
                            while (y7 < 0)
                            {
                                y7 += 26;
                            }
                            key2.Add(y7);

                            int y8 = (b * Convert.ToInt32(Math.Pow(-1, 2 + 2)) * (key[0] * key[4] - key[1] * key[3])) % 26;
                            while (y8 < 0)
                            {
                                y8 += 26;
                            }
                            key2.Add(y8);

                            inverseKey.Add(key2[0]);
                            inverseKey.Add(key2[3]);
                            inverseKey.Add(key2[6]);
                            inverseKey.Add(key2[1]);
                            inverseKey.Add(key2[4]);
                            inverseKey.Add(key2[7]);
                            inverseKey.Add(key2[2]);
                            inverseKey.Add(key2[5]);
                            inverseKey.Add(key2[8]);


                            //List<int> multi = new List<int>();
                            int i = 0;
                            while (i < cipherText.Count)
                            {
                                if (i < cipherText.Count && i + 1 < cipherText.Count)
                                {
                                    int x0 = (inverseKey[0] * cipherText[i] + inverseKey[1] * cipherText[i + 1] + inverseKey[2] * cipherText[i + 2]) % 26;
                                    while (x0 < 0)
                                    {
                                        x0 += 26;
                                    }
                                    multi.Add(x0);
                                    int x2 = (inverseKey[3] * cipherText[i] + inverseKey[4] * cipherText[i + 1] + inverseKey[5] * cipherText[i + 2]) % 26;
                                    while (x2 < 0)
                                    {
                                        x2 += 26;
                                    }
                                    multi.Add(x2);
                                    int x3 = (inverseKey[6] * cipherText[i] + inverseKey[7] * cipherText[i + 1] + inverseKey[8] * cipherText[i + 2]) % 26;
                                    while (x3 < 0)
                                    {
                                        x3 += 26;
                                    }
                                    multi.Add(x3);

                                    i += 3;


                                }
                            }
                        }

                    }
                }
                else if (det == 0)
                {
                    throw new NotImplementedException();
                }
            }
            return multi;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            int key_nm = key.Count;
            key_nm = (int)Math.Sqrt(key_nm);
            int plain_nm = plainText.Count / key_nm;
            List<int> ans = new List<int>();
            for (int i = 0; i < plain_nm; i++)
            {
                for (int j = 0; j < key_nm; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < key_nm; k++)
                    {
                        int key_indx = j * key_nm + k;
                        int plain_indx = i * key_nm;
                        sum += key[key_indx] * plainText[k + plain_indx];
                    }
                    ans.Add(sum % 26);
                }

            }
            return ans;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int det = 0;
            List<int> inversePlain = new List<int>();
            List<int> key = new List<int>();
            int b = 0;
            List<int> plainText2 = new List<int>();
            det = plainText[0] * (plainText[4] * plainText[8] - plainText[5] * plainText[7]) -
                plainText[1] * (plainText[3] * plainText[8] - plainText[5] * plainText[6])
                + plainText[2] * (plainText[3] * plainText[7] - plainText[4] * plainText[6]);
            det = det % 26;
            while (det < 0)
            {
                det += 26;
            }
            if (det > 0)
            {
                bool flag = false;
                for (int j = 0; j < plainText.Count; j++)
                {
                    if (plainText[j] < 0 || plainText[j] > 26)
                        flag = true;
                }
                if (flag == false)
                {
                    int x = 26;
                    bool check = false;
                    for (int j = 2; j < x; j++)
                    {
                        if (x % j == 0 && det % j == 0)
                        {
                            check = true;
                            break;
                        }
                    }
                    if (check == true)
                    {
                        throw new NotImplementedException();
                    }
                    else
                    {
                        int y = 26 - det;
                        if (1 / y < 1)
                        {
                            int s = x + 1;
                            int c = 0;
                            while (true)
                            {
                                if (s % y != 0)
                                {
                                    s = s + 1;
                                }
                                else
                                {
                                    if (s % x != 1)
                                    {
                                        s = s + 1;
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }

                            }
                            c = s / y;
                            b = x - c;
                        }
                        else
                        {
                            b = 26 - y;
                        }
                        int y0 = (b * Convert.ToInt32((Math.Pow(-1, 0 + 0)) * (plainText[4] * plainText[8] - plainText[5] * plainText[7]))) % 26;
                        while (y0 < 0)
                        {
                            y0 += 26;
                        }
                        plainText2.Add(y0);

                        int y1 = (b * Convert.ToInt32(Math.Pow(-1, 0 + 1)) * (plainText[3] * plainText[8] - plainText[5] * plainText[6])) % 26;
                        while (y1 < 0)
                        {
                            y1 += 26;
                        }
                        plainText2.Add(y1);
                        int y2 = (b * Convert.ToInt32(Math.Pow(-1, 0 + 2)) * (plainText[3] * plainText[7] - plainText[4] * plainText[6])) % 26;
                        while (y2 < 0)
                        {
                            y2 += 26;
                        }
                        plainText2.Add(y2);

                        int y3 = (b * Convert.ToInt32(Math.Pow(-1, 1 + 0)) * (plainText[1] * plainText[8] - plainText[2] * plainText[7])) % 26;
                        while (y3 < 0)
                        {
                            y3 += 26;
                        }
                        plainText2.Add(y3);

                        int y4 = (b * Convert.ToInt32(Math.Pow(-1, 1 + 1)) * (plainText[0] * plainText[8] - plainText[2] * plainText[6])) % 26;
                        while (y4 < 0)
                        {
                            y4 += 26;
                        }
                        plainText2.Add(y4);

                        int y5 = (b * Convert.ToInt32(Math.Pow(-1, 1 + 2)) * (plainText[0] * plainText[7] - plainText[1] * plainText[6])) % 26;
                        while (y5 < 0)
                        {
                            y5 += 26;
                        }
                        plainText2.Add(y5);

                        int y6 = (b * Convert.ToInt32(Math.Pow(-1, 2 + 0)) * (plainText[1] * plainText[5] - plainText[2] * plainText[4])) % 26;
                        while (y6 < 0)
                        {
                            y6 += 26;
                        }
                        plainText2.Add(y6);

                        int y7 = (b * Convert.ToInt32(Math.Pow(-1, 2 + 1)) * (plainText[0] * plainText[5] - plainText[2] * plainText[3])) % 26;
                        while (y7 < 0)
                        {
                            y7 += 26;
                        }
                        plainText2.Add(y7);

                        int y8 = (b * Convert.ToInt32(Math.Pow(-1, 2 + 2)) * (plainText[0] * plainText[4] - plainText[1] * plainText[3])) % 26;
                        while (y8 < 0)
                        {
                            y8 += 26;
                        }
                        plainText2.Add(y8);

                        inversePlain.Add(plainText2[0]);
                        inversePlain.Add(plainText2[3]);
                        inversePlain.Add(plainText2[6]);
                        inversePlain.Add(plainText2[1]);
                        inversePlain.Add(plainText2[4]);
                        inversePlain.Add(plainText2[7]);
                        inversePlain.Add(plainText2[2]);
                        inversePlain.Add(plainText2[5]);
                        inversePlain.Add(plainText2[8]);


                        List<int> cipherTextTranspose = new List<int>();
                        cipherTextTranspose.Add(cipherText[0]);
                        cipherTextTranspose.Add(cipherText[3]);
                        cipherTextTranspose.Add(cipherText[6]);
                        cipherTextTranspose.Add(cipherText[1]);
                        cipherTextTranspose.Add(cipherText[4]);
                        cipherTextTranspose.Add(cipherText[7]);
                        cipherTextTranspose.Add(cipherText[2]);
                        cipherTextTranspose.Add(cipherText[5]);
                        cipherTextTranspose.Add(cipherText[8]);


                        //List<int> multi = new List<int>();
                        int i = 0;
                        while (i < cipherTextTranspose.Count)
                        {
                            if (i < cipherTextTranspose.Count && i + 1 < cipherTextTranspose.Count)
                            {
                                int x0 = (cipherTextTranspose[i] * inversePlain[0] + cipherTextTranspose[i + 1] * inversePlain[1] + cipherTextTranspose[i + 2] * inversePlain[2]) % 26;
                                while (x0 < 0)
                                {
                                    x0 += 26;
                                }
                                key.Add(x0);
                                int x2 = (cipherTextTranspose[i] * inversePlain[3] + cipherTextTranspose[i + 1] * inversePlain[4] + cipherTextTranspose[i + 2] * inversePlain[5]) % 26;
                                while (x2 < 0)
                                {
                                    x2 += 26;
                                }
                                key.Add(x2);
                                int x3 = (cipherTextTranspose[i] * inversePlain[6] + cipherTextTranspose[i + 1] * inversePlain[7] + cipherTextTranspose[i + 2] * inversePlain[8]) % 26;
                                while (x3 < 0)
                                {
                                    x3 += 26;
                                }
                                key.Add(x3);

                                i += 3;


                            }
                        }
                    }

                }
            }
            else if (det == 0)
            {
                throw new NotImplementedException();
            }
            return key;
        }

    }
}
