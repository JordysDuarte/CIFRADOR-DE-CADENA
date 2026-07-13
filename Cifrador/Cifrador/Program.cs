using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cifrador
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== CIFRADO SIMÉTRICO (AES) ===\n");

            // 1. Configuración inicial
            string miClaveSecreta = "MiClaveSuperSecreta123!";
            string cadenaOriginal = "Server=myServerAddress;Database=myDataBase;Uid=myUsername;Pwd=myPassword;";

            //Console.WriteLine($"[1] Texto Original:\n    {cadenaOriginal}\n");

            try
            {
                // 2. Probar el Cifrado
                Console.ForegroundColor = ConsoleColor.Cyan;
                string resultadoEncriptado = CryptoHelper.Cifrar(cadenaOriginal, miClaveSecreta);
                Console.WriteLine($"CADENA ENCRIPTADA:");
                Console.ResetColor();
                Console.WriteLine($"\t{resultadoEncriptado}");
                Console.WriteLine();

                // 3. Probar el Descifrado
                Console.ForegroundColor = ConsoleColor.Cyan;
                string resultadoDescifrado = CryptoHelper.Desencriptar(resultadoEncriptado, miClaveSecreta);
                Console.WriteLine("CADENA DESENCRIPTADA:");
                Console.ResetColor();
                Console.WriteLine($"\t{resultadoDescifrado}");
                

                // 4. Prueba de Seguridad (¿Qué pasa si la clave es incorrecta?)
                //Console.WriteLine("[4] Ejecutando prueba de seguridad con clave incorrecta...");
                //string resultadoFallido = CryptoHelper.Desencriptar(resultadoEncriptado, "ClaveErronea");
            }
            catch (Exception ex)
            {
                // Aquí atrapará el error provocado intencionalmente en el paso 4
                Console.WriteLine($"\n[Resultado Esperado] Error detectado con éxito: {ex.Message}");
            }

            Console.WriteLine("\nPresiona cualquier tecla para salir...");
            Console.ReadKey();
        }


        public static class CryptoHelper
        {
            // IV fijo de 16 bytes (ceros) para simplificar el proceso y evitar fallos de padding
            private static readonly byte[] IvFijo = new byte[16];

            public static string Cifrar(string textoPlano, string claveSecreta)
            {
                byte[] claveBytes = Encoding.UTF8.GetBytes(claveSecreta.PadRight(32).Substring(0, 32));
                using (Aes aes = Aes.Create())
                {
                    aes.Key = claveBytes;
                    aes.IV = IvFijo;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            byte[] textoPlanoBytes = Encoding.UTF8.GetBytes(textoPlano);
                            cs.Write(textoPlanoBytes, 0, textoPlanoBytes.Length);
                            cs.FlushFinalBlock();
                        }
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            public static string Desencriptar(string textoCifrado, string claveSecreta)
            {
                try
                {
                    byte[] bytesCifrados = Convert.FromBase64String(textoCifrado.Trim());
                    byte[] claveBytes = Encoding.UTF8.GetBytes(claveSecreta.PadRight(32).Substring(0, 32));

                    using (Aes aes = Aes.Create())
                    {
                        aes.Key = claveBytes;
                        aes.IV = IvFijo;

                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                cs.Write(bytesCifrados, 0, bytesCifrados.Length);
                                cs.FlushFinalBlock();
                            }
                            return Encoding.UTF8.GetString(ms.ToArray());
                        }
                    }
                }
                catch (CryptographicException)
                {
                    throw new Exception("La clave de desencriptación es incorrecta o los datos se corrompieron.");
                }
                catch (FormatException)
                {
                    throw new Exception("El texto cifrado no tiene un formato Base64 válido.");
                }
            }
        }
    }
}

