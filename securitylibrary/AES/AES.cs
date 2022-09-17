using System;


namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        private static string[,] SBOX = {
            {"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
            {"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
            {"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
            {"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
            {"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
            {"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
            {"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
            {"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
            {"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
            {"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
            {"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
            {"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
            {"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
            {"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
            {"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
            {"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" }
        };

        private static string[,] invSBox =
        {
            {"52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb"},
            {"7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb"},
            {"54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e"},
            {"08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25"},
            {"72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92"},
            {"6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84"},
            {"90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06"},
            {"d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b"},
            {"3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73"},
            {"96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e"},
            {"47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b"},
            {"fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4"},
            {"1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f"},
            {"60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef"},
            {"a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61"},
            {"17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"}
        };


        public string[,] mixCols = {
        { "02", "03", "01", "01"},
        { "01", "02", "03", "01"},
        { "01", "01", "02", "03"},
        { "03", "01", "01", "02"} };

        public string[,] invCols = {
            {"0e" , "0b" , "0d" , "09" },
            {"09" , "0e" , "0b" , "0d" },
            {"0d" , "09" , "0e" , "0b" },
            {"0b" , "0d" , "09" , "0e" }
        };

        private static string[] Rcon = { "01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" };

        public override string Decrypt(string cipherText, string key)
        {
            string plain = "0x";

            string[,] cipherState = convToState(cipherText.ToLower());
            string[,] keyState = convToState(key.ToLower());

            for (int i = 1; i <= 10; i++)
                keyState = makeKey(keyState , i);

            //add round key
            string[,] res = addKey(cipherState, keyState);

            //sub bytes

            //shift rows

            //mix columns

            //make the key
            string[,] newkey = new string[4, 4];

            for (int i = 10; i > 1; i--)
            {
                res = invShiftRows(res);
                res = invSubBytes(res);
                if (i == 10)
                    newkey = makeInvKey(keyState, i);
                else
                    newkey = makeInvKey(newkey, i);
                res = addKey(res, newkey);

                res = invMixColumns(res);
            }

            res = invShiftRows(res);
            res = invSubBytes(res);
            newkey = makeInvKey(newkey, 1);
            res = addKey(res, newkey);
            
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain += res[j, i];
                }
            }
            return plain;
        }

        public override string Encrypt(string plainText, string key)
        {
            string[,] plainState = convToState(plainText);
            string[,] keyState = convToState(key);

            //add round key
            string[,] res = addKey(plainState, keyState);

            //sub bytes

            //shift rows

            //mix columns

            //make the key
            string[,] newkey = new string[4,4];

            for(int i = 1; i <= 9; i++)
            {
                res = subBytes(res);
                res = shiftRows(res);
                res = mixColumns(res);
                if(i==1)
                    newkey = makeKey(keyState, i);
                else
                newkey = makeKey(newkey, i);
                res = addKey(res, newkey);
            }

            //last round
            res = subBytes(res);
            res = shiftRows(res);
            newkey = makeKey(newkey, 10);
            res = addKey(res, newkey);

            //mixedMatrix = mixColumns(shiftedMatrix);
            string cipher = "0x";
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    cipher += res[j, i];
                }
            }
            return cipher;
        }

        public string[,] convToState(string text)
        {
            string[,] res = new string[4, 4];
            //"0x3243F6A8885A308D313198A2e0370734"
            int pos = 2;
            for(int j=0; j<4; j++)
            {
                for(int i = 0;i < 4; i++)
                {
                    res[i,j] = text[pos].ToString().ToLower() + text[pos+1].ToString().ToLower();
                    pos+=2;
                }
            }
            return res;
        }

        public string[,] addKey(string[,] plainState , string[,] keyState)
        {
            string[,] res = new string [4, 4];
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0;j < 4; j++)
                {
                    res[i,j] = (Convert.ToInt32(plainState[i, j], 16) ^ Convert.ToInt32(keyState[i, j], 16)).ToString("X").ToLower();
                    if(res[i,j].Length == 1)
                        res[i,j] = "0" + res[i,j];
                }
            }
            return res;
        }

        public string[,] subBytes(string[,] plainMatrix)
        {
            string[,] res = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string currentPos = plainMatrix[i, j].ToLower();
                    char pos1 = currentPos[0] , pos2 = currentPos[1];
                    int posI=-1, posJ=-1;
                    if(pos1 >= '0' && pos1 <= '9')
                        posI = pos1 - '0';
                    if(pos2 >= '0' && pos2 <= '9')
                        posJ = pos2 - '0';
                    if (pos1 == 'a')
                    {
                        posI = 10;
                    }
                    if (pos1 == 'b')
                    {
                        posI = 11;
                    }
                    if (pos1 == 'c')
                    {
                        posI = 12;
                    }
                    if (pos1 == 'd')
                    {
                        posI = 13;
                    }
                    if (pos1 == 'e')
                    {
                        posI = 14;
                    }
                    if (pos1 == 'f')
                    {
                        posI = 15;
                    }
                    if (pos2 == 'a')
                    {
                        posJ = 10;
                    }
                    if (pos2 == 'b')
                    {
                        posJ = 11;
                    }
                    if (pos2 == 'c')
                    {
                        posJ = 12;
                    }
                    if (pos2 == 'd')
                    {
                        posJ = 13;
                    }
                    if (pos2 == 'e')
                    {
                        posJ = 14;
                    }
                    if (pos2 == 'f')
                    {
                        posJ = 15;
                    }
                    res[i, j] = SBOX[posI, posJ].ToLower();
                }
            }
            return res;
        }

        public string[,] invSubBytes(string[,] cipherMatrix)
        {
            string[,] res = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string currentPos = cipherMatrix[i, j].ToLower();
                    char pos1, pos2;
                    if(currentPos.Length == 1)
                    {
                        pos1 = '0';
                        pos2 = currentPos[0];
                    }
                    else
                    {
                        pos1 = currentPos[0];
                        pos2 = currentPos[1];
                    }
                    
                    int posI = -1, posJ = -1;
                    if (pos1 >= '0' && pos1 <= '9')
                        posI = pos1 - '0';
                    if (pos2 >= '0' && pos2 <= '9')
                        posJ = pos2 - '0';
                    if (pos1 == 'a')
                    {
                        posI = 10;
                    }
                    if (pos1 == 'b')
                    {
                        posI = 11;
                    }
                    if (pos1 == 'c')
                    {
                        posI = 12;
                    }
                    if (pos1 == 'd')
                    {
                        posI = 13;
                    }
                    if (pos1 == 'e')
                    {
                        posI = 14;
                    }
                    if (pos1 == 'f')
                    {
                        posI = 15;
                    }
                    if (pos2 == 'a')
                    {
                        posJ = 10;
                    }
                    if (pos2 == 'b')
                    {
                        posJ = 11;
                    }
                    if (pos2 == 'c')
                    {
                        posJ = 12;
                    }
                    if (pos2 == 'd')
                    {
                        posJ = 13;
                    }
                    if (pos2 == 'e')
                    {
                        posJ = 14;
                    }
                    if (pos2 == 'f')
                    {
                        posJ = 15;
                    }
                    res[i, j] = invSBox[posI, posJ].ToLower();
                    if(res[i , j].Length == 1)
                        res[i,j] = "0" + res[i,j];
                }
            }
            return res;
        }

        public string[] subBytes1D(string[] tempMatrix)
        {
            string[] res = new string[4];
            for (int i = 0; i < 4; i++)
            {
                string currentPos = tempMatrix[i].ToLower();
                char pos1, pos2;
                if (currentPos.Length == 1)
                {
                    pos1 = '0';
                    pos2 = currentPos[0];
                }
                else
                {
                    pos1 = currentPos[0];
                    pos2 = currentPos[1];
                }
                int posI = -1, posJ = -1;
                if (pos1 >= '0' && pos1 <= '9')
                    posI = pos1 - '0';
                if (pos2 >= '0' && pos2 <= '9')
                    posJ = pos2 - '0';
                if (pos1 == 'a')
                {
                    posI = 10;
                }
                if (pos1 == 'b')
                {
                    posI = 11;
                }
                if (pos1 == 'c')
                {
                    posI = 12;
                }
                if (pos1 == 'd')
                {
                    posI = 13;
                }
                if (pos1 == 'e')
                {
                    posI = 14;
                }
                if (pos1 == 'f')
                {
                    posI = 15;
                }
                if (pos2 == 'a')
                {
                    posJ = 10;
                }
                if (pos2 == 'b')
                {
                    posJ = 11;
                }
                if (pos2 == 'c')
                {
                    posJ = 12;
                }
                if (pos2 == 'd')
                {
                    posJ = 13;
                }
                if (pos2 == 'e')
                {
                    posJ = 14;
                }
                if (pos2 == 'f')
                {
                    posJ = 15;
                }
                res[i] = SBOX[posI, posJ].ToLower();
                if(res[i].Length == 1)
                    res[i] = "0" + res[i];
            }
            return res;
        }

        public string[,] shiftRows(string[,] plainMatrix)
        {
            string[,] res =
            {
                { plainMatrix[0,0] , plainMatrix[0,1] , plainMatrix[0,2] , plainMatrix[0,3]},
                { plainMatrix[1,1] , plainMatrix[1,2] , plainMatrix[1,3] , plainMatrix[1,0]},
                { plainMatrix[2,2] , plainMatrix[2,3] , plainMatrix[2,0] , plainMatrix[2,1]},
                { plainMatrix[3,3] , plainMatrix[3,0] , plainMatrix[3,1] , plainMatrix[3,2]}
            };
            return res;
        }

        public string[,] invShiftRows(string[,] cipherMatrix)
        {
            string[,] res = { 
                { cipherMatrix[0,0] , cipherMatrix[0,1] , cipherMatrix[0,2] , cipherMatrix[0,3]},
                { cipherMatrix[1,3] , cipherMatrix[1,0] , cipherMatrix[1,1] , cipherMatrix[1,2]},
                { cipherMatrix[2,2] , cipherMatrix[2,3] , cipherMatrix[2,0] , cipherMatrix[2,1]},
                { cipherMatrix[3,1] , cipherMatrix[3,2] , cipherMatrix[3,3] , cipherMatrix[3,0]}
            };
            return res;
        }

        public string[,] mixColumns(string[,] plainMatrix)
        {
            string[,] res = new string[4, 4];
            //int posCol = 0;
            //for(int i=0; i < 4; i++)
            //{
            //    for (int j = 0; j < 4; j++)
            //    {
            //        var x = GMul(Convert.ToByte("0x" + plainMatrix[0, posCol], 16), Convert.ToByte("0x" + mixCols[j, 0], 16)) ^
            //                GMul(Convert.ToByte("0x" + plainMatrix[1, posCol], 16), Convert.ToByte("0x" + mixCols[j, 1], 16)) ^
            //                GMul(Convert.ToByte("0x" + plainMatrix[2, posCol], 16), Convert.ToByte("0x" + mixCols[j, 2], 16)) ^
            //                GMul(Convert.ToByte("0x" + plainMatrix[3, posCol], 16), Convert.ToByte("0x" + mixCols[j, 3], 16));
            //        if(x.ToString().Length == 1)
            //            res[j, i] ="0" + x.ToString("X").ToLower();
            //        else
            //            res[j, i] = x.ToString("X").ToLower();
            //    }
            //    posCol++;
            //}

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    var x = GMul(Convert.ToByte("0x" + mixCols[i, 0], 16), Convert.ToByte("0x" + plainMatrix[0, j], 16)) ^
                        GMul(Convert.ToByte("0x" + mixCols[i, 1], 16), Convert.ToByte("0x" + plainMatrix[1, j], 16)) ^
                        GMul(Convert.ToByte("0x" + mixCols[i, 2], 16), Convert.ToByte("0x" + plainMatrix[2, j], 16)) ^
                        GMul(Convert.ToByte("0x" + mixCols[i, 3], 16), Convert.ToByte("0x" + plainMatrix[3, j], 16));
                    if (x.ToString().Length == 1)
                    {
                        res[i, j] = "0" + x.ToString("X").ToLower();
                    }
                    else
                    {
                        res[i, j] = x.ToString("X").ToLower();
                    }
                    
                }
            }
            return res;
        }

        public string[,] invMixColumns(string[,] plainMatrix)
        {
            string[,] res = new string[4, 4];
            //int posCol = 0;
            //for(int i=0; i < 4; i++)
            //{
            //    for (int j = 0; j < 4; j++)
            //    {
            //        var x = GMul(Convert.ToByte("0x" + plainMatrix[0, posCol], 16), Convert.ToByte("0x" + mixCols[j, 0], 16)) ^
            //                GMul(Convert.ToByte("0x" + plainMatrix[1, posCol], 16), Convert.ToByte("0x" + mixCols[j, 1], 16)) ^
            //                GMul(Convert.ToByte("0x" + plainMatrix[2, posCol], 16), Convert.ToByte("0x" + mixCols[j, 2], 16)) ^
            //                GMul(Convert.ToByte("0x" + plainMatrix[3, posCol], 16), Convert.ToByte("0x" + mixCols[j, 3], 16));
            //        if(x.ToString().Length == 1)
            //            res[j, i] ="0" + x.ToString("X").ToLower();
            //        else
            //            res[j, i] = x.ToString("X").ToLower();
            //    }
            //    posCol++;
            //}

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    var x = GMul(Convert.ToByte("0x" + invCols[i, 0], 16), Convert.ToByte("0x" + plainMatrix[0, j], 16)) ^
                        GMul(Convert.ToByte("0x" + invCols[i, 1], 16), Convert.ToByte("0x" + plainMatrix[1, j], 16)) ^
                        GMul(Convert.ToByte("0x" + invCols[i, 2], 16), Convert.ToByte("0x" + plainMatrix[2, j], 16)) ^
                        GMul(Convert.ToByte("0x" + invCols[i, 3], 16), Convert.ToByte("0x" + plainMatrix[3, j], 16));
                    if (x.ToString("X").Length == 1)
                    {
                        res[i, j] = "0" + x.ToString("X").ToLower();
                    }
                    else
                    {
                        res[i, j] = x.ToString("X").ToLower();
                    }

                }
            }
            return res;
        }

        public static byte GMul(Byte a, Byte b)
        {
            byte p = 0;
            byte counter;
            byte hi_bit_set;
            for (counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }
                hi_bit_set = (byte)(a & 0x80);
                a <<= 1;
                if (hi_bit_set != 0)
                {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            return p;
        }
        public string [,] makeKey(string[,] key, int roundNum)
        {
            string[,] res = new string[4, 4];
            //Rot Word
            string[] temp = { key[0,3], key[1,3], key[2,3], key[3,3] };
            string first = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = first;
            //string [,] subKey = new string[4,4];

            for (int i = 0; i < 4; i++)
            {
                    string currentPos = temp[i].ToLower();
                    char pos1 = currentPos[0], pos2 = currentPos[1];
                    int posI = -1, posJ = -1;
                    if (pos1 >= '0' && pos1 <= '9')
                        posI = pos1 - '0';
                    if (pos2 >= '0' && pos2 <= '9')
                        posJ = pos2 - '0';
                    if (pos1 == 'a')
                    {
                        posI = 10;
                    }
                    if (pos1 == 'b')
                    {
                        posI = 11;
                    }
                    if (pos1 == 'c')
                    {
                        posI = 12;
                    }
                    if (pos1 == 'd')
                    {
                        posI = 13;
                    }
                    if (pos1 == 'e')
                    {
                        posI = 14;
                    }
                    if (pos1 == 'f')
                    {
                        posI = 15;
                    }
                    if (pos2 == 'a')
                    {
                        posJ = 10;
                    }
                    if (pos2 == 'b')
                    {
                        posJ = 11;
                    }
                    if (pos2 == 'c')
                    {
                        posJ = 12;
                    }
                    if (pos2 == 'd')
                    {
                        posJ = 13;
                    }
                    if (pos2 == 'e')
                    {
                        posJ = 14;
                    }
                    if (pos2 == 'f')
                    {
                        posJ = 15;
                    }
                    temp[i] = SBOX[posI, posJ].ToLower();
            }

            //first col
            for(int i = 0;i< 4; i++)
            {
                if (i == 0)
                {
                    res[i, 0] = (Convert.ToInt32(key[i, 0], 16) ^ Convert.ToInt32(temp[i], 16) ^ Convert.ToInt32(Rcon[roundNum - 1], 16)).ToString("X").ToLower();
                    if (res[i, 0].Length == 1)
                    {
                        res[i, 0] = "0" + res[i, 0];
                    }
                }
                else
                {
                    res[i, 0] = (Convert.ToInt32(key[i, 0], 16) ^ Convert.ToInt32(temp[i], 16) ^ Convert.ToInt32("00", 16)).ToString("X").ToLower();
                    if (res[i, 0].Length == 1)
                    {
                        res[i, 0] = "0" + res[i, 0];
                    }
                }
            }
            //rest of col
            for (int i = 1; i < 4; i++)
            {
                for(int j=0; j < 4; j++)
                {
                    res[j, i] = (Convert.ToInt32(key[j, i], 16) ^ Convert.ToInt32(res[j, i - 1], 16)).ToString("X").ToLower();
                    if (res[j, i].Length == 1)
                        res[j, i] = "0" + res[j, i];
                }
            }
            return res;
        }

        public string[,] makeInvKey(string[,] key, int roundNum)
        {
            string[,] res = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                res[i,3] = (Convert.ToInt32(key[i, 3], 16) ^ Convert.ToInt32(key[i, 2], 16)).ToString("X").ToLower();
                if (res[i, 3].Length == 1)
                    res[i, 3] = "0" + res[i, 3];
            }

            for (int i = 0; i < 4; i++)
            {
                res[i, 2] = (Convert.ToInt32(key[i, 2], 16) ^ Convert.ToInt32(key[i, 1], 16)).ToString("X").ToLower();
                if (res[i, 2].Length == 1)
                    res[i, 2] = "0" + res[i, 2];
            }

            for (int i = 0; i < 4; i++)
            {
                res[i, 1] = (Convert.ToInt32(key[i, 1], 16) ^ Convert.ToInt32(key[i, 0], 16)).ToString("X").ToLower();
                if (res[i, 1].Length == 1)
                    res[i, 1] = "0" + res[i, 1];
            }

            //res[i,3] ^ key[i,0]
            //key no change
            //res shift and sub and xor with rcon

            string[] temp = { res[1, 3], res[2, 3], res[3, 3] , res[0, 3]};
            temp = subBytes1D(temp);

            for(int i=0; i < 4; i++)
            {
                //res[j, i] = (Convert.ToInt32(key[j, i], 16) ^ Convert.ToInt32(res[j, i - 1], 16)).ToString("X").ToLower();
                if(i == 0)
                {
                    res[i, 0] = (Convert.ToInt32(key[i, 0], 16) ^ Convert.ToInt32(temp[i], 16) ^ Convert.ToInt32(Rcon[roundNum - 1], 16)).ToString("X").ToLower();
                    if (res[i, 0].Length == 1)
                        res[i, 0] = "0" + res[i, 0];
                }
                else
                {
                    res[i, 0] = (Convert.ToInt32(key[i, 0], 16) ^ Convert.ToInt32(temp[i], 16) ^ Convert.ToInt32("00", 16)).ToString("X").ToLower();
                    if (res[i, 0].Length == 1)
                        res[i, 0] = "0" + res[i, 0];
                }
                
            }

            return res;
        }
    }
}
