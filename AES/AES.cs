using System;

namespace Crypto
{
    class AES
    {
        #region Implementation Multipling Polynoms

        //получение бита слова
        private static ushort ExtractBit(ushort source, ushort number)
        {
            if (number < 16)
            {
                return (ushort)((source >> number) & 1);
            }
            return 0;
        }

        //установка бита в слово
        private static ushort SetBit(ushort source, ushort number, ushort val)
        {
            if (number>15) return 0;
            if (val>1) return 0;

            if (ExtractBit(source, number) == val) return source;
            return (ushort)(source ^ (1<<number));
        }

        //умножение двух многочленов с приведением по модулю x^4+x^3+x^2+1
        private static byte PolynomsMuliply(byte a, byte b)
        {
            ushort result = 0;
            ushort temp;

            for (ushort i = 0; i < 15; i++)
            {
                temp = 0;
                for (ushort k = 0; k <= i; k++)
                {
                    ushort ak = ExtractBit(a, k);
                    ushort bik = ExtractBit(b, (ushort)(i - k));
                    temp = (ushort) (temp ^ (ak & bik));
                }
                result = SetBit(result, i, temp);
            }

            ushort mod = 283;

            //приведение по модулю втупую =) прибавлением многочлена
            if (ExtractBit(result, 14) == 1) result = (ushort)(result ^ (mod << 6));
            if (ExtractBit(result, 13) == 1) result = (ushort)(result ^ (mod << 5));
            if (ExtractBit(result, 12) == 1) result = (ushort)(result ^ (mod << 4));
            if (ExtractBit(result, 11) == 1) result = (ushort)(result ^ (mod << 3));
            if (ExtractBit(result, 10) == 1) result = (ushort)(result ^ (mod << 2));
            if (ExtractBit(result, 9) == 1) result = (ushort)(result ^ (mod << 1));
            if (ExtractBit(result, 8) == 1) result = (ushort)(result ^ mod);

            return (byte)result;
        }

        #endregion

        #region Key schedule emplementation

        private static uint[] KeyExpansion(byte[] key)
        {
            uint[] Rcon = new uint[] { 0,0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000 };
            uint[] w = new uint[60];
            for (int i = 0; i < 60; i++) w[i] = 0;
            for (int i = 0; i < 8; i++)
            {
                w[i] = (((uint)key[4 * i]) << 24) ^ ((((uint)key[4 * i + 1]) << 16)) ^ (((uint)key[4 * i + 2]) << 8) ^ key[4 * i + 3];
            }
            for (int i = 8; i < 60; i++)
            {
                uint temp = w[i - 1];
                if ((i % 8) == 0)
                {
                    temp = SubWord(RotWord(temp)) ^ Rcon[i / 8];
                }
                else if (i % 8 == 4)
                {
                    temp = SubWord(temp);
                }
                w[i] = w[i - 8] ^ temp;
            }
            return w;
        }

        private static uint SubWord(uint p)
        {
            byte p0 = (byte)(p >> 24);
            byte p1 = (byte)(p >> 16);
            byte p2 = (byte)(p >> 8);
            byte p3 = (byte)p;

            byte x = (byte)(p0 >> 4);
            byte y = (byte)(p0 & 0x0f);

            p0 = S(x, y);

            x = (byte)(p1 >> 4);
            y = (byte)(p1 & 0x0f);
            p1 = S(x, y);

            x = (byte)(p2 >> 4);
            y = (byte)(p2 & 0x0f);
            p2 = S(x, y);

            x = (byte)(p3 >> 4);
            y = (byte)(p3 & 0x0f);
            p3 = S(x, y);

            return ((((uint)p0) << 24) ^ (((uint)p1) << 16) ^ (((uint)p2) << 8) ^ p3);
        }

        private static uint RotWord(uint w)
        {
            uint temp = w >> 24;
            temp = (w << 8) ^ temp;
            return temp;
        }

        #endregion

        #region Implementation of AES Enciphering

        private static void Cipher(byte[,] in_array, out byte[,] out_array, uint[] w)
        {
            byte[,] state = in_array;
            AddRoundKey(ref state, w[0], w[1], w[2], w[3]);

            for (int round = 1; round <= 13; round++)
            {
                SubBytes(ref state);
                ShiftRows(ref state);
                MixColumns(ref state);
                AddRoundKey(ref state, w[round*4], w[round*4+1], w[round*4+2], w[round*4+3]);
            }

            SubBytes(ref state);
            ShiftRows(ref state);
            AddRoundKey(ref state, w[56], w[57], w[58], w[59]);

            out_array = state;
        }

        private static void MixColumns(ref byte[,] state)
        {
            byte[,] new_state = new byte[4, 4];
            for (int c = 0; c < 4; c++)
            {
                new_state[0, c] = (byte)(PolynomsMuliply(2,state[0,c]) ^ PolynomsMuliply(3,state[1,c]) ^ state[2,c] ^ state[3,c]);
                new_state[1, c] = (byte)(state[0, c] ^ PolynomsMuliply(2, state[1, c]) ^ PolynomsMuliply(3, state[2, c]) ^ state[3, c]);
                new_state[2, c] = (byte)(state[0, c] ^ state[1, c] ^ PolynomsMuliply(2, state[2, c]) ^ PolynomsMuliply(3, state[3, c]));
                new_state[3, c] = (byte)(PolynomsMuliply(3, state[0, c]) ^ state[1, c] ^ state[2, c] ^ PolynomsMuliply(2, state[3, c]));
            }
            state = new_state;
            return;
        }

        private static void ShiftRows(ref byte[,] state)
        {
            byte temp1 = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = temp1;

            temp1 = state[2, 0];
            byte temp2 = state[2, 1];
            state[2, 0] = state[2, 2];
            state[2, 1] = state[2, 3];
            state[2, 2] = temp1;
            state[2, 3] = temp2;

            temp1 = state[3, 0];
            temp2 = state[3, 1];
            byte temp3 = state[3, 2];
            state[3, 0] = state[3, 3];
            state[3, 1] = temp1;
            state[3, 2] = temp2;
            state[3, 3] = temp3;
        }

        private static void SubBytes(ref byte[,] state)
        {
            byte x;
            byte y;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    x = (byte)(state[i, j] >> 4);
                    y = (byte)(state[i, j] & 0xf);
                    state[i, j] = S(x, y);
                }
            }
        }

        private static void AddRoundKey(ref byte[,] state, uint w0, uint w1, uint w2, uint w3 )
        {
            state[0, 0] = (byte)(state[0, 0] ^ (w0 >> 24));
            state[1, 0] = (byte)(state[1, 0] ^ ((w0 >> 16) & 0xff));
            state[2, 0] = (byte)(state[2, 0] ^ ((w0 >> 8) & 0xff));
            state[3, 0] = (byte)(state[3, 0] ^ (w0 & 0xff));

            state[0, 1] = (byte)(state[0, 1] ^ (w1 >> 24));
            state[1, 1] = (byte)(state[1, 1] ^ ((w1 >> 16) & 0xff));
            state[2, 1] = (byte)(state[2, 1] ^ ((w1 >> 8) & 0xff));
            state[3, 1] = (byte)(state[3, 1] ^ (w1 & 0xff));

            state[0, 2] = (byte)(state[0, 2] ^ (w2 >> 24));
            state[1, 2] = (byte)(state[1, 2] ^ ((w2 >> 16) & 0xff));
            state[2, 2] = (byte)(state[2, 2] ^ ((w2 >> 8) & 0xff));
            state[3, 2] = (byte)(state[3, 2] ^ (w2 & 0xff));

            state[0, 3] = (byte)(state[0, 3] ^ (w3 >> 24));
            state[1, 3] = (byte)(state[1, 3] ^ ((w3 >> 16) & 0xff));
            state[2, 3] = (byte)(state[2, 3] ^ ((w3 >> 8) & 0xff));
            state[3, 3] = (byte)(state[3, 3] ^ (w3 & 0xff));
        }

        #region Substitution Boxes
        private static byte S(byte x, byte y)
        {
            switch (x)
            {
                case 0:
                    {
                        switch (y)
                        {
                            case 0: return 0x63;
                            case 1: return 0x7c;
                            case 2: return 0x77;
                            case 3: return 0x7b;
                            case 4: return 0xf2;
                            case 5: return 0x6b;
                            case 6: return 0x6f;
                            case 7: return 0xc5;
                            case 8: return 0x30;
                            case 9: return 0x01;
                            case 10: return 0x67;
                            case 11: return 0x2b;
                            case 12: return 0xfe;
                            case 13: return 0xd7;
                            case 14: return 0xab;
                            case 15: return 0x76;
                            default: return 0;
                        }
                    }
                case 1:
                    {
                        switch (y)
                        {
                            case 0: return 0xca;
                            case 1: return 0x82;
                            case 2: return 0xc9;
                            case 3: return 0x7d;
                            case 4: return 0xfa;
                            case 5: return 0x59;
                            case 6: return 0x47;
                            case 7: return 0xf0;
                            case 8: return 0xad;
                            case 9: return 0xd4;
                            case 10: return 0xa2;
                            case 11: return 0xaf;
                            case 12: return 0x9c;
                            case 13: return 0xa4;
                            case 14: return 0x72;
                            case 15: return 0xc0;
                            default: return 0;
                        }
                    }
                case 2:
                    {
                        switch (y)
                        {
                            case 0: return 0xb7;
                            case 1: return 0xfd;
                            case 2: return 0x93;
                            case 3: return 0x26;
                            case 4: return 0x36;
                            case 5: return 0x3f;
                            case 6: return 0xf7;
                            case 7: return 0xcc;
                            case 8: return 0x34;
                            case 9: return 0xa5;
                            case 10: return 0xe5;
                            case 11: return 0xf1;
                            case 12: return 0x71;
                            case 13: return 0xd8;
                            case 14: return 0x31;
                            case 15: return 0x15;
                            default: return 0;
                        }
                    }
                case 3:
                    {
                        switch (y)
                        {
                            case 0: return 0x04;
                            case 1: return 0xc7;
                            case 2: return 0x23;
                            case 3: return 0xc3;
                            case 4: return 0x18;
                            case 5: return 0x96;
                            case 6: return 0x05;
                            case 7: return 0x9a;
                            case 8: return 0x07;
                            case 9: return 0x12;
                            case 10: return 0x80;
                            case 11: return 0xe2;
                            case 12: return 0xeb;
                            case 13: return 0x27;
                            case 14: return 0xb2;
                            case 15: return 0x75;
                            default: return 0;
                        }
                    }
                case 4:
                    {
                        switch (y)
                        {
                            case 0: return 0x09; 
                            case 1: return 0x83;
                            case 2: return 0x2c;
                            case 3: return 0x1a;
                            case 4: return 0x1b;
                            case 5: return 0x6e;
                            case 6: return 0x5a;
                            case 7: return 0xa0;
                            case 8: return 0x52;
                            case 9: return 0x3b;
                            case 10: return 0xd6;
                            case 11: return 0xb3;
                            case 12: return 0x29;
                            case 13: return 0xe3;
                            case 14: return 0x2f;
                            case 15: return 0x84;
                            default: return 0;
                        }
                    }
                case 5:
                    {
                        switch (y)
                        {
                            case 0: return 0x53; 
                            case 1: return 0xd1;
                            case 2: return 0x00;
                            case 3: return 0xed;
                            case 4: return 0x20;
                            case 5: return 0xfc;
                            case 6: return 0xb1;
                            case 7: return 0x5b;
                            case 8: return 0x6a;
                            case 9: return 0xcb;
                            case 10: return 0xbe;
                            case 11: return 0x39;
                            case 12: return 0x4a;
                            case 13: return 0x4c;
                            case 14: return 0x58;
                            case 15: return 0xcf;
                            default: return 0;
                        }
                    }
                case 6:
                    {
                        switch (y)
                        {
                            case 0: return 0xd0; 
                            case 1: return 0xef;
                            case 2: return 0xaa;
                            case 3: return 0xfb;
                            case 4: return 0x43;
                            case 5: return 0x4d;
                            case 6: return 0x33;
                            case 7: return 0x85;
                            case 8: return 0x45;
                            case 9: return 0xf9;
                            case 10: return 0x02;
                            case 11: return 0x7f;
                            case 12: return 0x50;
                            case 13: return 0x3c;
                            case 14: return 0x9f;
                            case 15: return 0xa8;   
                            default: return 0;
                        }
                    }
                case 7: 
                    {
                        switch(y)
                        {
                            case 0: return 0x51; 
                            case 1: return 0xa3;
                            case 2: return 0x40;
                            case 3: return 0x8f;
                            case 4: return 0x92;
                            case 5: return 0x9d;
                            case 6: return 0x38;
                            case 7: return 0xf5;
                            case 8: return 0xbc;
                            case 9: return 0xb6;
                            case 10: return 0xda;
                            case 11: return 0x21;
                            case 12: return 0x10;
                            case 13: return 0xff;
                            case 14: return 0xf3;
                            case 15: return 0xd2;
                            default: return 0;
                        }                        
                    }
                case 8:
                {
                    switch (y)
                    {
                        case 0: return 0xcd;
                        case 1: return 0x0c;
                        case 2: return 0x13;
                        case 3: return 0xec;
                        case 4: return 0x5f;
                        case 5: return 0x97;
                        case 6: return 0x44;
                        case 7: return 0x17;
                        case 8: return 0xc4;
                        case 9: return 0xa7;
                        case 10: return 0x7e;
                        case 11: return 0x3d;
                        case 12: return 0x64;
                        case 13: return 0x5d;
                        case 14: return 0x19;
                        case 15: return 0x73;
                        default: return 0;
                    }
                }
                case 9:
                {
                    switch (y)
                    {
                        case 0: return 0x60; 
                        case 1: return 0x81;
                        case 2: return 0x4f;
                        case 3: return 0xdc;
                        case 4: return 0x22;
                        case 5: return 0x2a;
                        case 6: return 0x90;
                        case 7: return 0x88;
                        case 8: return 0x46;
                        case 9: return 0xee;
                        case 10: return 0xb8;
                        case 11: return 0x14;
                        case 12: return 0xde;
                        case 13: return 0x5e;
                        case 14: return 0x0b;
                        case 15: return 0xdb;
                        default: return 0;
                    }
                }
                case 10:
                {
                    switch (y)
                    {
                        case 0: return 0xe0; 
                        case 1: return 0x32;
                        case 2: return 0x3a;
                        case 3: return 0x0a;
                        case 4: return 0x49;
                        case 5: return 0x06;
                        case 6: return 0x24;
                        case 7: return 0x5c;
                        case 8: return 0xc2;
                        case 9: return 0xd3;
                        case 10: return 0xac;
                        case 11: return 0x62;
                        case 12: return 0x91;
                        case 13: return 0x95;
                        case 14: return 0xe4;
                        case 15: return 0x79;
                        default: return 0;
                    }
                }
                case 11:
                {
                    switch (y)
                    {
                        case 0: return 0xe7; 
                        case 1: return 0xc8;
                        case 2: return 0x37;
                        case 3: return 0x6d;
                        case 4: return 0x8d;
                        case 5: return 0xd5;
                        case 6: return 0x4e;
                        case 7: return 0xa9;
                        case 8: return 0x6c;
                        case 9: return 0x56;
                        case 10: return 0xf4;
                        case 11: return 0xea;
                        case 12: return 0x65;
                        case 13: return 0x7a;
                        case 14: return 0xae;
                        case 15: return 0x08;
                        default: return 0;
                    }
                }
                case 12:
                {
                    switch (y)
                    {
                        case 0: return 0xba;
                        case 1: return 0x78;
                        case 2: return 0x25;
                        case 3: return 0x2e;
                        case 4: return 0x1c;
                        case 5: return 0xa6;
                        case 6: return 0xb4;
                        case 7: return 0xc6;
                        case 8: return 0xe8;
                        case 9: return 0xdd;
                        case 10: return 0x74;
                        case 11: return 0x1f;
                        case 12: return 0x4b;
                        case 13: return 0xbd;
                        case 14: return 0x8b;
                        case 15: return 0x8a;
                        default: return 0;
                    }
                }
                case 13:
                {
                    switch (y)
                    {
                        case 0: return 0x70; 
                        case 1: return 0x3e;
                        case 2: return 0xb5;
                        case 3: return 0x66;
                        case 4: return 0x48;
                        case 5: return 0x03;
                        case 6: return 0xf6;
                        case 7: return 0x0e;
                        case 8: return 0x61;
                        case 9: return 0x35;
                        case 10: return 0x57;
                        case 11: return 0xb9;
                        case 12: return 0x86;
                        case 13: return 0xc1;
                        case 14: return 0x1d;
                        case 15: return 0x9e;
                        default: return 0;
                    }
                }
                case 14:
                {
                    switch (y)
                    {
                        case 0: return 0xe1; 
                        case 1: return 0xf8;
                        case 2: return 0x98;
                        case 3: return 0x11;
                        case 4: return 0x69;
                        case 5: return 0xd9;
                        case 6: return 0x8e;
                        case 7: return 0x94;
                        case 8: return 0x9b;
                        case 9: return 0x1e;
                        case 10: return 0x87;
                        case 11: return 0xe9;
                        case 12: return 0xce;
                        case 13: return 0x55;
                        case 14: return 0x28;
                        case 15: return 0xdf;
                        default: return 0;
                    }
                }
                case 15:
                {
                    switch (y)
                    {
                        case 0: return 0x8c;
                        case 1: return 0xa1;
                        case 2: return 0x89;
                        case 3: return 0x0d;
                        case 4: return 0xbf;
                        case 5: return 0xe6;
                        case 6: return 0x42;
                        case 7: return 0x68;
                        case 8: return 0x41;
                        case 9: return 0x99;
                        case 10: return 0x2d;
                        case 11: return 0x0f;
                        case 12: return 0xb0;
                        case 13: return 0x54;
                        case 14: return 0xbb;
                        case 15: return 0x16;
                        default: return 0;
                    }
                }
                default: return 0;
            }
        }

        #endregion

        #endregion

        #region Additional Functions

        private static byte[] ulongToByteArray(ulong nonce, ulong i)
        {
            byte[] res = new byte[16];
            for (int k = 0; k < 8; k++)
            {
                res[k] = (byte)((nonce >> 8 * k) & 0xff);
            }
            for (int k = 8; k < 16; k++)
            {
                res[k] = (byte)((i >> 8 * k) & 0xff);
            }
            return res;
        }

        private static byte[,] ArrayToSquare(byte[] array)
        {
            if (array.Length < 16) throw new ArgumentException();
            byte[,] res = new byte[4, 4];
            res[0, 0] = array[0]; res[0, 1] = array[4]; res[0, 2] = array[8]; res[0, 3] = array[12];
            res[1, 0] = array[1]; res[1, 1] = array[5]; res[1, 2] = array[9]; res[1, 3] = array[13];
            res[2, 0] = array[2]; res[2, 1] = array[6]; res[2, 2] = array[10]; res[2, 3] = array[14];
            res[3, 0] = array[3]; res[3, 1] = array[7]; res[3, 2] = array[11]; res[3, 3] = array[15];

            return res;
        }

        private static byte[] SquareToArray(byte[,] square)
        {
            byte[] res = new byte[16];
            res[0] = square[0, 0];
            res[1] = square[1, 0];
            res[2] = square[2, 0];
            res[3] = square[3, 0];
            res[4] = square[0, 1];
            res[5] = square[1, 1];
            res[6] = square[2, 1];
            res[7] = square[3, 1];
            res[8] = square[0, 2];
            res[9] = square[1, 2];
            res[10] = square[2, 2];
            res[11] = square[3, 2];
            res[12] = square[0, 3];
            res[13] = square[1, 3];
            res[14] = square[2, 3];
            res[15] = square[3, 3];
            return res;
        }

        #endregion

        #region AES Block Encryption

        private static byte[] AES_Block_Encrypt(byte[] input, uint[] key)
        {
            byte[,] output;
            byte[,] plainBlock = ArrayToSquare(input);
            Cipher(plainBlock, out output, key);
            return SquareToArray(output);
        }

        #endregion

        #region AES Counter Mode

        // i - номер сообщения и номер блока
        public static ulong AES_CRT(byte[] input, byte[] key, out byte[] output, ulong nonce, ulong i)
        {
            byte[] K_i;
            byte[,] out_array;
            uint numblock = (uint)(input.Length / 16);
            uint rest = (uint)(input.Length % 16);
            uint[] w = KeyExpansion(key);
            ulong temp_i = i;
            byte[] temp;
            output = new byte[input.Length];
            for (int s = 0; s < numblock; s++)
            {
                temp = ulongToByteArray(nonce, temp_i);
                Cipher(ArrayToSquare(temp),out out_array, w);
                K_i = SquareToArray(out_array);
                for (int k = 0; k < 16; k++)
                {
                    output[s * 16 + k] = (byte)(input[s * 16 + k] ^ K_i[k]);
                }
                temp_i++;
            }

            if (rest != 0)
            {
                temp = ulongToByteArray(nonce, temp_i);
                Cipher(ArrayToSquare(temp), out out_array, w);
                K_i = SquareToArray(out_array);
                for (int k = 0; k < rest; k++)
                {
                    output[numblock * 16 + k] = (byte)(input[numblock * 16 + k] ^ K_i[k]);
                }
                temp_i++;
            }

            Array.Clear(w, 0, w.Length);

            return temp_i;
        }

        #endregion

        #region AES CCM Encryption Mode

        public static bool AES_CCM_Encrypt(byte[] input, byte[] key, out byte[] output, ulong nonce, uint messageNumber)
        {
            if(input.Length < 16) throw new ArgumentOutOfRangeException();
            if (input.Length > ((1 << 16) - 1)) throw new ArgumentOutOfRangeException();
            //заполняем блок B_0
            byte[] B_0 = new byte[16];
            B_0[0] = 0x09;
            B_0[1] = (byte)(nonce & 0xff);
            B_0[2] = (byte)((nonce >> 8) & 0xff);
            B_0[3] = (byte)((nonce >> 16) & 0xff);
            B_0[4] = (byte)((nonce >> 24) & 0xff);
            B_0[5] = (byte)((nonce >> 32) & 0xff);
            B_0[6] = (byte)((nonce >> 40) & 0xff);
            B_0[7] = (byte)((nonce >> 48) & 0xff);
            B_0[8] = (byte)((nonce >> 56) & 0xff);
            B_0[9] = (byte)((messageNumber & 0xff));
            B_0[10] = (byte)((messageNumber >> 8) & 0xff);
            B_0[11] = (byte)((messageNumber >> 16) & 0xff);
            B_0[12] = (byte)((messageNumber >> 24) & 0xff);
            B_0[13] = 0x00;
            B_0[14] = (byte)(input.Length & 0xff);
            B_0[15] = (byte)((input.Length >> 8) & 0xff);
            //-----------------------
            byte[] temp;
            uint[] w = KeyExpansion(key);
            uint len = (uint)(input.Length / 16);
            uint rest = (uint)(input.Length % 16);

            temp = AES_Block_Encrypt(B_0, w);

            for (int i = 0; i < len; i++)
            {
                for (int k = 0; k < 16; k++)
                {
                    temp[k] = (byte)(temp[k] ^ input[16 * i + k]);
                }
                temp = AES_Block_Encrypt(temp, w);
            }

            if (rest != 0)
            {
                for (int i = 0; i < rest; i++)
                {
                    temp[i] = (byte)(temp[i] ^ input[16 * len + i]);
                }
                temp = AES_Block_Encrypt(temp, w);
            }

            byte[] A_temp = new byte[16];

            A_temp[0] = 0x01;
            A_temp[1] = (byte)(nonce & 0xff);
            A_temp[2] = (byte)((nonce >> 8) & 0xff);
            A_temp[3] = (byte)((nonce >> 16) & 0xff);
            A_temp[4] = (byte)((nonce >> 24) & 0xff);
            A_temp[5] = (byte)((nonce >> 32) & 0xff);
            A_temp[6] = (byte)((nonce >> 40) & 0xff);
            A_temp[7] = (byte)((nonce >> 48) & 0xff);
            A_temp[8] = (byte)((nonce >> 56) & 0xff);
            A_temp[9] = (byte)((messageNumber & 0xff));
            A_temp[10] = (byte)((messageNumber >> 8) & 0xff);
            A_temp[11] = (byte)((messageNumber >> 16) & 0xff);
            A_temp[12] = (byte)((messageNumber >> 24) & 0xff);
            A_temp[13] = 0x00;
            A_temp[14] = 0x00;
            A_temp[15] = 0x00;

            byte[] S_0 = AES_Block_Encrypt(A_temp, w);

            output = new byte[8 + input.Length];
            output[0] = (byte)(messageNumber & 0xff);
            output[1] = (byte)((messageNumber >> 8) & 0xff);
            output[2] = (byte)((messageNumber >> 16) & 0xff);
            output[3] = (byte)((messageNumber >> 24) & 0xff);

            output[4] = (byte)(S_0[0] ^ temp[0]);
            output[5] = (byte)(S_0[1] ^ temp[1]);
            output[6] = (byte)(S_0[2] ^ temp[2]);
            output[7] = (byte)(S_0[3] ^ temp[3]);

            for (uint i = 1; i <= len; i++)
            {
                A_temp[14] = (byte)(i & 0xff);
                A_temp[15] = (byte)((i >> 8) & 0xff);
                S_0 = AES_Block_Encrypt(A_temp, w);
                for (int k = 0; k < 16; k++)
                {
                    output[8 + (i-1)*16 + k] = (byte)(input[(i - 1) * 16 + k] ^ S_0[k]);
                }
            }

            if (rest != 0)
            {
                A_temp[14] = (byte)((len + 1) & 0xff);
                A_temp[15] = (byte)(((len + 1) >> 8) & 0xff);
                S_0 = AES_Block_Encrypt(A_temp, w);
                for (int k = 0; k < rest; k++)
                {
                    output[8 + len * 16 + k] = (byte)(input[len * 16 + k] ^ S_0[k]);
                }
            }
            Array.Clear(w, 0, w.Length);

            return true;
        }

        public static bool AES_CCM_Decrypt(byte[] input, byte[] key, out byte[] output, ulong nonce, out uint messageNumber)
        {
            if (input.Length < 8) throw new ArgumentOutOfRangeException();

            uint[] w = KeyExpansion(key);

            byte[] temp_output = new byte[input.Length - 8];

            for (int i = 0; i < temp_output.Length; i++)
            {
                temp_output[i] = input[i + 8];
            }

            byte[] A_temp = new byte[16];
            A_temp[0] = 0x01;
            A_temp[1] = (byte)(nonce & 0xff);
            A_temp[2] = (byte)((nonce >> 8) & 0xff);
            A_temp[3] = (byte)((nonce >> 16) & 0xff);
            A_temp[4] = (byte)((nonce >> 24) & 0xff);
            A_temp[5] = (byte)((nonce >> 32) & 0xff);
            A_temp[6] = (byte)((nonce >> 40) & 0xff);
            A_temp[7] = (byte)((nonce >> 48) & 0xff);
            A_temp[8] = (byte)((nonce >> 56) & 0xff);
            A_temp[9] = input[0];
            A_temp[10] = input[1];
            A_temp[11] = input[2];
            A_temp[12] = input[3];
            A_temp[13] = 0x00;
            A_temp[14] = 0x00;
            A_temp[15] = 0x00;

            byte[] S_0 = AES_Block_Encrypt(A_temp, w);

            byte[] U = new byte[4];

            U[0] = (byte)(input[4] ^ S_0[0]);
            U[1] = (byte)(input[5] ^ S_0[1]);
            U[2] = (byte)(input[6] ^ S_0[2]);
            U[3] = (byte)(input[7] ^ S_0[3]);

            //расшифруем сообщение

            uint len = (uint)((input.Length - 8) / 16);
            uint res = (uint)((input.Length - 8) % 16);

            for (int i = 1; i <= len; i++)
            {
                A_temp[14] = (byte)(i & 0xff);
                A_temp[15] = (byte)((i >> 8) & 0xff);

                S_0 = AES_Block_Encrypt(A_temp, w);

                for (int k = 0; k < 16; k++)
                {
                    temp_output[(i - 1) * 16 + k] = (byte)(S_0[k] ^ input[(i - 1) * 16 + k + 8]);
                }
            }

            if (res != 0)
            {
                A_temp[14] = (byte)((len+1) & 0xff);
                A_temp[15] = (byte)(((len+1) >> 8) & 0xff);

                S_0 = AES_Block_Encrypt(A_temp, w);

                for (int k = 0; k < res; k++)
                {
                    temp_output[len * 16 + k] = (byte)(input[len * 16 + k + 8] ^ S_0[k]);
                }
            }
            //расшифровали сообщение (оно в temp_output), нужно аутентифицировать его

            byte[] B_0 = new byte[16];
            B_0[0] = 0x09;
            B_0[1] = (byte)(nonce & 0xff);
            B_0[2] = (byte)((nonce >> 8) & 0xff);
            B_0[3] = (byte)((nonce >> 16) & 0xff);
            B_0[4] = (byte)((nonce >> 24) & 0xff);
            B_0[5] = (byte)((nonce >> 32) & 0xff);
            B_0[6] = (byte)((nonce >> 40) & 0xff);
            B_0[7] = (byte)((nonce >> 48) & 0xff);
            B_0[8] = (byte)((nonce >> 56) & 0xff);
            B_0[9] = input[0];
            B_0[10] = input[1];
            B_0[11] = input[2];
            B_0[12] = input[3];
            B_0[13] = 0x00;
            B_0[14] = (byte)((input.Length - 8) & 0xff);
            B_0[15] = (byte)(((input.Length - 8) >> 8) & 0xff);

            S_0 = AES_Block_Encrypt(B_0, w);

            for (uint i = 0; i < len; i++)
            {
                for (int k = 0; k < 16; k++)
                {
                    S_0[k] = (byte)(S_0[k] ^ temp_output[i * 16 + k]);
                }
                S_0 = AES_Block_Encrypt(S_0, w);
            }

            if (res != 0)
            {
                for (int k = 0; k < res; k++) S_0[k] = (byte)(S_0[k] ^ temp_output[len * 16 + k]);
                S_0 = AES_Block_Encrypt(S_0, w);
            }

            output = temp_output;
            
            messageNumber = (((uint)input[3]) << 24) ^ (((uint)input[2]) << 16) ^ (((uint)input[1]) << 8) ^ input[0];
            
            for (int i = 0; i < 4; i++)
            {
                if (U[i] == S_0[i]) continue;
                Array.Clear(w, 0, w.Length);
                return false;
            }

            Array.Clear(w, 0, w.Length);

            return true;

        }
        #endregion
    }
}

