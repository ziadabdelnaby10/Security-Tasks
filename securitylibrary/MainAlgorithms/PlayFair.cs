using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public char[,] makeMap(string key)
        {
            char[,] array = new char[6, 6];
            IDictionary<char, bool> alphabet = new Dictionary<char, bool>();
            for (char i = 'a'; i <= 'z'; i++)
            {
                alphabet.Add(i, false);
            }

            string k = key.Trim();
            Console.WriteLine(k);
            int j = 0, t = 0;
            alphabet['j'] = true;
            for (int i = 0; i < k.Length; i++)
            {
                if (t == 5)
                {
                    j++;
                    t = 0;
                }
                if (alphabet[k[i]] == false)
                {
                    array[j, t] = k[i];
                    alphabet[k[i]] = true;
                    t++;
                }
            }
            for (char i = 'a'; i <= 'z'; i++)
            {
                if (t == 5)
                {
                    j++;
                    t = 0;
                }
                if (alphabet[i] == false)
                {
                    array[j, t] = i;
                    alphabet[i] = true;
                    t++;
                }
            }
            for (int i = 0; i < 5; i++)
            {
                for (int q = 0; q < 5; q++)
                {
                    Console.Write(array[i, q] + " ");
                }
                Console.WriteLine();
            }
            return array;

        }
        public string Decrypt(string cipherText, string key)
        {
            string result = "";
            char[,] array = makeMap(key);

            cipherText = (cipherText.ToLower()).Trim();

            int length = cipherText.Length;
            cipherText.Replace('j', 'i');
            int[] indeces = new int[(length * 2) + 2];
            int r = 0, X1 = 0, X2 = 0;
            for (int i = 0; i < length; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (cipherText[i] == array[j, k])
                        {
                            indeces[r] = j; indeces[r + 1] = k; Console.WriteLine(cipherText[i]);

                        }
                        if (array[j, k] == 'x') { X1 = j; X2 = k; }
                    }
                }
                r += 2;
            }
            for (int i = 0; i < indeces.Length - 3; i += 4)
            {
                int x1 = indeces[i], y1 = indeces[i + 1], x2 = 0, y2 = 0;
                if (i + 5 > indeces.Length)
                {
                    x2 = X1;
                    y2 = X2;
                }
                else
                {
                    x2 = indeces[i + 2]; y2 = indeces[i + 3];
                }
                //Duplicates
                if (x1 == x2 && y1 == y2)
                {
                    x2 = X1;
                    y2 = X2;
                    i -= 2;
                }


                // Same Raw
                if (x1 == x2)
                {
                    if (y1 == 0) y1 = 5;
                    if (y2 == 0) y2 = 5;
                    result += array[x1, y1 - 1].ToString() + array[x2, y2 - 1].ToString();
                }

                //Same Colomn
                else if (y1 == y2)
                {
                    if (x1 == 0) x1 = 5;
                    if (x2 == 0) x2 = 5;
                    result += array[x1 - 1, y1].ToString() + array[x2 - 1, y2].ToString();
                }

                //Square
                else
                {
                   
                    result += array[x1, y2].ToString() + array[x2, y1].ToString();
                }
            }
            string res2 = "";
            for (int i =0;i<result.Length;i+=2)
            {
                if ( result[i + 1] == 'x' && i+2 >= result.Length)
                {
                    res2 += result[i].ToString();
                }
                else if (result[i+1]== 'x' && result[i] == result[i+2])
                {
                    res2 += result[i].ToString();
                }
                else
                {
                    res2 += result[i].ToString() + result[i + 1].ToString();
                }
            }
            return res2;
        }
        public string Encrypt(string plainText, string key)
        {
            string result = "";
            char[,] array = makeMap(key);
            plainText = plainText.Trim();
            int length = plainText.Length;
            plainText.Replace('j', 'i');
            int[] indeces = new int[(length * 2) + 2];
            int r = 0, X1 = 0, X2 = 0;
            for (int i = 0; i < length; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    for (int k = 0; k < 5; k++)
                    {
                        if (plainText[i] == array[j, k])
                        {
                            indeces[r] = j; indeces[r + 1] = k; Console.WriteLine(plainText[i]);

                        }
                        if (array[j, k] == 'x') { X1 = j; X2 = k; }
                    }
                }
                r += 2;
            }
            for (int i = 0; i < indeces.Length - 3; i += 4)
            {

                int x1 = indeces[i], y1 = indeces[i + 1], x2 = 0, y2 = 0;
                if (i + 5 > indeces.Length)
                {
                    x2 = X1;
                    y2 = X2;
                }
                else
                {
                    x2 = indeces[i + 2]; y2 = indeces[i + 3];
                }
                //Duplicates
                if (x1 == x2 && y1 == y2)
                {
                    x2 = X1;
                    y2 = X2;
                    i -= 2;
                }


                // Same Raw
                if (x1 == x2)
                {
                    if (y1 == 4) y1 = -1;
                    if (y2 == 4) y2 = -1;
                    result += array[x1, y1 + 1].ToString() + array[x2, y2 + 1].ToString();
                }

                //Same Colomn
                else if (y1 == y2)
                {
                    if (x1 == 4) x1 = -1;
                    if (x2 == 4) x2 = -1;
                    result += array[x1 + 1, y1].ToString() + array[x2 + 1, y2].ToString();
                }

                //Square
                else
                {
                    result += array[x1, y2].ToString() + array[x2, y1].ToString();
                }
            }
            return result;
        }
    }

}


