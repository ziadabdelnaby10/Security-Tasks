using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int k = 1;
            bool flag = false;
            for (int i = 1; i < plainText.Length; i++)
            {
                if (flag == true)
                {
                    break;
                }
                else
                {
                    for (int j = 1; j < cipherText.Length; j++)
                    {
                        if (plainText[i] == cipherText[j] && j > i + 1)
                        {
                            k++;
                            break;
                        }
                        else if (plainText[i] == cipherText[j] && j < i)
                        {
                            flag = true;
                            break;
                        }
                    }
                }
            }
            return k;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            int len = 0;
            if (cipherText.Length % key != 0)
                len = (cipherText.Length / key) + 1;
            else
                len = cipherText.Length / key;

            string plainText = "";
            List<List<char>> myList = new List<List<char>>();
            for (int k = 0; k < key; k++)
            {
                myList.Add(new List<char>());
            }
            int xx = 0;
            for (int i = 0; i < myList.Count; i++)
            {
                for (int j = 0; j < len && xx < cipherText.Length; j++)
                {
                    myList[i].Add(cipherText[xx]);
                    xx++;
                }
            }
            for (int j = 0; j < myList[0].Count; j++)
            {
                for (int i = 0; i < myList.Count; i++)
                {
                    if (j < myList[i].Count)
                    {
                        plainText += myList[i][j];
                    }
                }
            }

            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            List<List<char>> myList = new List<List<char>>();
            for (int k = 0; k < key; k++)
            {
                myList.Add(new List<char>());
            }
            int i = 0;
            while (i < plainText.Length)
            {
                if (plainText[i] != ' ')
                {
                    for (int j = 0; j < key && i < plainText.Length; j++)
                    {


                        myList[j].Add(plainText[i]);
                        i++;

                    }
                }
                else
                {
                    i++;

                }
            }
            string cypher = "";
            for (int k = 0; k < key; k++)
            {
                for (int h = 0; h < myList[k].Count; h++)
                {
                    cypher += myList[k].ElementAt(h);
                }
            }
            return cypher;
        }
    }
}
