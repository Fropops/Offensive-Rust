using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Test
{
    public class Program
    {
        static int HostingMain(String args)
        {
            Main(new string[] { args });
            return 0;
        }
        public static void Main(string[] args)
        {
            Console.WriteLine("Hello");
            //Environment.Exit(10);
        }
    }
}
