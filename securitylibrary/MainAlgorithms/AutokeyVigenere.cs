using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
         public string Analyse(string plainText, string cipherText)
        {
            char[,] array = makeMap();
            cipherText = cipherText.ToLower();
            string result = "";
            for (int i = result.Length; i < plainText.Length; i++)
            {
                int x = (int)plainText[i] - (int)'a';
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == array[x, j])
                    {
                        result += (char)(j + (int)'a');
                        break;
                    }
                }

            }
            string tmp = ""; int ptr = 0, c = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                tmp += plainText[i];
                if (!result.Contains(tmp))
                {
                    ptr = i - 1; break;
                }
                c++;

            }
            int rem = result.Length - ptr - 1;
            result = result.Remove(rem, result.Length - rem);


            return result;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[,] array = makeMap();
            cipherText = cipherText.ToLower();
                string result = "";
            int p = cipherText.Length - key.Length;
            int u = 0;
            while (result.Length < cipherText.Length || p > 0)
            {

                // Convert from cipher & key to plain with key length 
                for (int i = result.Length; i < key.Length; i++)
                {
                    int x = (int)key[i] - (int)'a';
                    for (int j = 0; j < 26; j++)
                    {
                        if (cipherText[i] == array[j, x])
                        {
                            result += (char)(j + (int)'a');
                            break;
                        }
                    }

                }
                // Convert the plain to key and add 

                for (; u < result.Length; u++)
                {
                    if (p == 0) break;
                    key += result[u].ToString();
                    p--;
                }
                p = cipherText.Length - key.Length;
                /*
                 *save : 
                 * 
                 */
                
            }
            return result;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] array = makeMap();
              string result = "";
        int p = plainText.Length - key.Length;
            for (int i = 0;  i <p;i++)
            {
                key += plainText[i]; 
            }
          
            for (int i =0;i<plainText.Length;i++)
            {
                int x = (int)plainText[i] - (int)'a';
                int y = (int)key[i] - (int)'a';
                result+= array[x, y].ToString();
            }
            return result;
        }

        public char[,] makeMap()
        {
            char[,] array = new char[27,27];

            for (char i = 'a' ; i<='z';i++)
            {
                int k = 0;
                char t = i, q = 'a';
                for (int j = 0; j < 26; j++)
                {
                    int x = (int)i - (int)'a';
                    array[x, j] = t;
                    if (t == 'z')
                    {
                        k = j + 1; break;
                    }
                    t++;

                }

                for (int j = k; j < 26; j++)
                {
                    if (q == t) { break; }
                    int x = (int)i - (int)'a';
                    array[x, j] = q;
                    q++;
                }
            }
                return array;
        }
    }
}


