using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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

            int last = -1;
            for (int i = 1; i < result.Length; i++)
            {
                if (result[0] == result[i])
                {
                    if (result[1] == result[i + 1] && i < result.Length)
                    {
                        last = i;
                        break;
                    }
                }
            }
            return result.Substring(0, last);

            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string orig_text = "";
            string new_key = generate_key(cipherText, key);
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length && i < new_key.Length; i++)
            {
                int x = (cipherText[i] - new_key[i] + 26) % 26;
                x += 'A';
                orig_text += (char)(x);
            }
            return orig_text.ToLower();
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] array = makeMap();
            string result = "";
            string new_key = generate_key(plainText, key);
            plainText = plainText.ToLower();

            for (int i = 0; i < plainText.Length; i++)
            {
                int x = (int)plainText[i] - (int)'a';
                int y = (int)new_key[i] - (int)'a';
                result += array[x, y].ToString();
            }
            return result.ToUpper();
            //throw new NotImplementedException();
        }

        public string generate_key(string plainText, string key)
        {
            int x = plainText.Length;

            for (int i = 0; ; i++)
            {
                if (x == i)
                    i = 0;
                if (key.Length == plainText.Length)
                    break;
                key += (key[i]);
            }
            return key;
        }
        public char[,] makeMap()
        {
            char[,] array = new char[27, 27];

            for (char i = 'a'; i <= 'z'; i++)
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