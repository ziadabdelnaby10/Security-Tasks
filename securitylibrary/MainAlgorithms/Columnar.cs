using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            char x1 = cipherText[0], x2 = cipherText[1];
            int y1=0, y2=0;bool p = false;
            for (int i =0;i<plainText.Length;i++)
            {
                p = false;
                if (plainText[i] == x1)
                {
                    y1 = i;
                    for (int j = i+1;j < plainText.Length;j++)
                    {
                        if (plainText[j] == x2)
                        {
                            y2 = j;
                            if (y2 - y1 <= 2)
                                break;
                            else
                            {
                                p = true;
                                break;
                            }
                        }
                    }
                    if (p) break;
                }
            }
            int q = y2 - y1 ,x =0,o=0;
            char[,] map = new char[(plainText.Length/q) +1 , q+1];
           for (int i = 0;i <plainText.Length;i++)
            {
                map[o,x] = plainText[i];
                x++;
                if (x == q)
                {
                    o++;
                    x = 0;
                }
               
            }
           // plainText  25 
           // q = 7 
           // plain / q = 3
            string[] plainstrs = new string[plainText.Length];
            string[] cipherstrs = new string[cipherText.Length];
            for (int j = 0; j < q; j++)
            {
                for (int i = 0;i <(plainText.Length/q)+1;i++)
                {
                
                    plainstrs[j]+=map[i,j];
                }
            }
           
            List<int> key = new List<int>(); 
            for (int i= 0;i<q; i++)
            {
                int ptr;
                if (plainstrs[i].Contains('\0'))
                {
                    string str1 = plainstrs[i].Replace('\0', 'x');
                    string str2 = plainstrs[i].TrimEnd('\0');
                    ptr = cipherText.IndexOf(str1);
                    if (ptr == -1)
                    {
                        ptr = cipherText.IndexOf(str2);
                        key.Add((ptr / str2.Length)+1);
                    }
                    else
                    {
                        key.Add((ptr / str1.Length)+1);
                    }
                }
                else
                {
                    ptr = cipherText.IndexOf(plainstrs[i]);
                    key.Add((ptr / plainstrs[i].Length)+1);
                }
                
            }

           
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //  throw new NotImplementedException();
            List<int> keyOutput = new List<int>();

            for (int i = 0; i < key.Count; i++)
            {
                keyOutput.Add(key[i]);
            }
            key.Sort();
            int rows = 0;
            int xCount = 0;
            if (cipherText.Length % key.Count == 0)
                rows = cipherText.Length / key.Count;
            else
            {
                xCount = key.Count - (cipherText.Length % key.Count);
                rows = (cipherText.Length / key.Count) + 1;
            }

            SortedDictionary<int, List<char>> keyValue = new SortedDictionary<int, List<char>>();
            for (int i = 0; i < key.Count; i++)
            {
                if (!keyValue.ContainsKey(key[i]))
                {
                    keyValue[key[i]] = new List<char>();
                    for (int j = 0; j < rows; j++)
                    {
                        keyValue[key[i]].Add('#');
                    }
                }
            }

            int minus = keyOutput.Count - 1;
            for (int i = 0; i < xCount; i++)
            {
                keyValue[keyOutput[minus]][rows - 1] = 'x';
                minus--;
            }
            int z = 0;
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    if (keyValue[key[i]][j] == '#')
                    {
                        keyValue[key[i]][j] = cipherText[z];
                        z++;
                    }
                }
            }

            char[] pl = new char[key.Count * rows];
            int indx = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < keyOutput.Count; j++)
                {
                    if (keyValue[keyOutput[j]][i] == 'x' && xCount > 0)
                        xCount--;
                    else
                        pl[indx] = keyValue[keyOutput[j]][i];
                    indx++;
                }
            }
            string res = new string(pl);
            res = res.ToLower();
            return res;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            plainText = plainText.ToLower();
            plainText = String.Concat(plainText.Where(c => !Char.IsWhiteSpace(c)));
            int len = plainText.Length;
            SortedDictionary<int, List<char>> keyValue = new SortedDictionary<int, List<char>>();
            for (int i = 0; i < key.Count; i++)
            {
                if (!keyValue.ContainsKey(key[i]))
                {
                    keyValue[key[i]] = new List<char>();
                }
            }

            int j = 0;
            int indx = 0;
            int matrixSize = 0;
            if (plainText.Length % key.Count == 0)
                matrixSize = plainText.Length / key.Count;
            else
                matrixSize = (plainText.Length / key.Count) + 1;

            matrixSize *= key.Count;

            while (j < matrixSize)
            {

                if (j >= plainText.Length)
                {
                    keyValue[key[indx]].Add('x');
                }
                else
                {
                    if (plainText[j] != ' ')
                    {
                        keyValue[key[indx]].Add(plainText[j]);
                    }
                }
                indx++;
                if (indx >= key.Count)
                    indx = indx % key.Count;
                j++;
            }
            char[] cipher = new char[matrixSize];

            int cur = 0;
            foreach (KeyValuePair<int, List<char>> val in keyValue)
            {
                for (int i = 0; i < val.Value.Count; i++)
                {
                    cipher[cur] = val.Value[i];
                    cur++;
                }
            }

            string res = new string(cipher);
            res = res.ToUpper();
            return res;
        }
    }
}
