using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using System.Numerics;

namespace protect_inf_LR1
{
    public partial class Form1 : Form
    {
        char[] characters = new char[] { '#', 'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И',
                                                        'Й', 'К', 'Л', 'М', 'Н', 'О', 'П', 'Р', 'С', 
                                                        'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ь', 'Ы', 'Ъ',
                                                        'Э', 'Ю', 'Я', ' ', '1', '2', '3', '4', '5', '6', '7',
                                                        '8', '9', '0' };


        public Form1()
        {
            InitializeComponent();
        }

        //зашифровать кнопка
        private void buttonEncrypt_Click(object sender, EventArgs e)
        {
            if ((textBox_p.Text.Length > 0) && (textBox_q.Text.Length > 0))
            {
                BigInteger p = Convert.ToInt64(textBox_p.Text);
                BigInteger q = Convert.ToInt64(textBox_q.Text);

                if (IsTheNumberSimple(p) && IsTheNumberSimple(q))
                {
                    string s = "";

                    StreamReader sr = new StreamReader("in.txt");

                    while (!sr.EndOfStream)
                    {
                        s += sr.ReadLine();
                    }

                    sr.Close();

                    s = s.ToUpper();

                    BigInteger n = p * q;
                    BigInteger m = (p - 1) * (q - 1);
                    BigInteger d = Calculate_d(m);
                    BigInteger e_ = Calculate_e(d, m);

                    List<string> result = RSA_Endoce(s, e_, n);

                    StreamWriter sw = new StreamWriter("out1.txt");
                    foreach (string item in result)
                        sw.WriteLine(item);
                    sw.Close();

                    textBox_d.Text = d.ToString();
                    textBox_n.Text = n.ToString();

                    Process.Start("out1.txt");
                }
                else
                    MessageBox.Show("p или q - не простые числа!");
            }
            else
                MessageBox.Show("Введите p и q!");
        }

        //расшифровать кнопка
        private void buttonDecipher_Click(object sender, EventArgs e)
        {
            if ((textBox_d.Text.Length > 0) && (textBox_n.Text.Length > 0))
            {
                BigInteger d = Convert.ToInt64(textBox_d.Text);
                BigInteger n = Convert.ToInt64(textBox_n.Text);
                BigInteger p = Convert.ToInt64(textBox_p.Text);
                BigInteger q = Convert.ToInt64(textBox_q.Text);

                List<string> input = new List<string>();

                StreamReader sr = new StreamReader("out1.txt");

                while (!sr.EndOfStream)
                {
                    input.Add(sr.ReadLine());
                }

                sr.Close();

                string result = RSA_Dedoce(input, d, n, p , q);

                StreamWriter sw = new StreamWriter("out2.txt");
                sw.WriteLine(result);
                sw.Close();

                Process.Start("out2.txt");
            }
            else
                MessageBox.Show("Введите секретный ключ!");
        }

        //проверка: простое ли число?
        private bool IsTheNumberSimple(BigInteger n)
        {
            if (n < 2)
                return false;

            if (n == 2)
                return true;

            for (BigInteger i = 2; i < n; i++)
                if (n % i == 0)
                    return false;

            return true;
        }

        //Тут шифруем:)
        private List<string> RSA_Endoce(string s, BigInteger e, BigInteger n)
        {
            List<string> result = new List<string>();

            BigInteger bi;
            int k = 0;
            for (int i = 0; i < s.Length; i++)
            {
                
                int index = Array.IndexOf(characters, s[i]);

                bi = new BigInteger(index);
                //bi = BigInteger.Pow(bi, (int)e);//стандартная
                bi = PowerStepen(bi, (int)e);//ускоренная
                BigInteger n_ = new BigInteger((int)n);
                k++;
                bi = bi % n_;
                for (int v = 0; v < k; v++) {
                    bi *= 2;
                }

                result.Add(bi.ToString());
            }

            return result;
        }

        //Тут расшифровываем:)
        private string RSA_Dedoce(List<string> input, BigInteger d, BigInteger n, BigInteger p, BigInteger q)
        {
            string result = "";

            BigInteger bi;
            int k = 0;
            foreach (string item in input)
            {
               
                bi = new BigInteger(Convert.ToDouble(item));
                k++;
                for (int i = 0; i < k; i++)
                {
                    bi /= 2;
                }
                //bi = BigInteger.Pow(bi, (int)d); //стандартная операция 
                bi = PowerStepen(bi, (BigInteger)d);//ускоренная
                BigInteger n_ = new BigInteger((int)n);
                bi = bi % n_;
                //bi = KTO(bi,d,p,q) ;
                int index = Convert.ToInt32(bi.ToString());

                result += characters[index].ToString();
            }

            return result;
        }



        


        //вычисление параметра d
        private BigInteger Calculate_d(BigInteger m)
        {
            BigInteger d = m - 1;

            for (BigInteger i = 2; i <= m; i++)
                if ((m % i == 0) && (d % i == 0)) //если имеют общие делители
                {
                    d--;
                    i = 1;
                }

            return d;
        }

        //вычисление параметра e
        private BigInteger Calculate_e(BigInteger d, BigInteger m)
        {
            BigInteger e = 10;

            while (true)
            {
                if ((e * d) % m == 1)
                    break;
                else
                    e++;
            }

            return e;
        }
        //Быстрое возведение в степень,сдвиг вправо = деление на 2,а у четного последний бит = 0
        static BigInteger PowerStepen(BigInteger bi, BigInteger e)
        {
            BigInteger result = 1;
            while (e > 0)
            {
                if ((e & 1) == 0)
                {
                    bi *= bi;
                    e >>= 1;
                }
                else
                {
                    result *= bi;
                    --e;
                }
            }

            return result;
        }

        //KTO

        static BigInteger KTO(BigInteger bi, BigInteger d, BigInteger p, BigInteger q)
        {
            BigInteger x = 0;
            BigInteger r1 = PowerStepen(bi, d) % p;
            BigInteger r2 = PowerStepen(bi, d) % q;
            x = (r1 * q * (ExtendedEvclid(1, q, p)) + r2 * p * (ExtendedEvclid(1, p, q))) % (p * q);


            return x;
        }




   



        //Обратное мультипликативное по модулю(Расширенный Евклид)
        static BigInteger ExtendedEvclid(BigInteger a, BigInteger b, BigInteger n)
        {
            BigInteger x = (BigInteger)b;
            int i = 0;
            do
            {
                if (x % 2 == 1) x--;
                x = x / 2;
                i++;
            }
            while (x > 0);
            x = (BigInteger)b;
            BigInteger[] ar = new BigInteger[i];
            for (i = 0; i < ar.Length; i++)
            {
                ar[i] = x % 2;
                if (x % 2 == 1) x--;
                x = x / 2;
            }
            x = (BigInteger)a;
            for (i = ar.Length - 2; i >= 0; i--)
            {
                x = (x * x) % (BigInteger)n;
                x = (x * PowerStepen((BigInteger)a, (BigInteger)ar[i])) % (BigInteger)n;
            }
            return (BigInteger)x;
        }











    }
}
