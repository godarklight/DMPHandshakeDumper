using System;
using System.Net;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using DarkMultiPlayerCommon;
using DarkNetwork;
using MessageStream;

namespace DMPHandshakeDumper
{
    public class MainClass
    {
        private const string NETWORK_SCRAPER = "DMPModScraper";
        private static DarkNetworkConnection dnc = new DarkNetworkConnection();

        private static string rootPath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
        private static string dataPath = Path.Combine(new string[] { rootPath, "GameData", "DarkMultiPlayer", "Plugins", "Data" });
        private static string settingsPath = Path.Combine(dataPath, "servers.xml");
        private static string publicKeyPath = Path.Combine(dataPath, "publickey.txt");
        private static string privateKeyPath = Path.Combine(dataPath, "privatekey.txt");

        private static string playerName;
        private static string publicKey;
        private static string privateKey;

        public static void Main()
        {

            if (!File.Exists(settingsPath) || !File.Exists(publicKeyPath) || !File.Exists(privateKeyPath))
            {
                Console.WriteLine("Must be placed next to KSP's executable!");
                Console.ReadKey();
                return;
            }

            LoadSettings();

            dnc.callbackHandler.RegisterCallback((int)ServerMessageType.HANDSHAKE_CHALLANGE, HandleChallange);
            dnc.callbackHandler.RegisterCallback((int)ServerMessageType.HANDSHAKE_REPLY, HandleHandshake);
            dnc.Connect(new IPEndPoint(IPAddress.Loopback, 6702));
            while (true)
            {
                System.Threading.Thread.Sleep(500);
            }
        }

        private static void LoadSettings()
        {
            publicKey = File.ReadAllText(publicKeyPath);
            privateKey = File.ReadAllText(privateKeyPath);
            XmlDocument document = new XmlDocument();
            document.Load(settingsPath);
            playerName = document.SelectSingleNode("settings/global/@username").Value;
            Console.WriteLine("Name: " + playerName + ", pubkey length: " + publicKey.Length + ", prikey length: " + privateKey.Length);
        }

        private static void HandleChallange(byte[] messageData)
        {
            try
            {
                using (MessageReader mr = new MessageReader(messageData, false))
                {
                    //Remove byte[] payload length
                    mr.Read<int>();
                    //Read challange
                    byte[] challange = mr.Read<byte[]>();
                    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024))
                    {
                        rsa.PersistKeyInCsp = false;
                        rsa.FromXmlString(privateKey);
                        byte[] signature = rsa.SignData(challange, CryptoConfig.CreateFromName("SHA256"));
                        SendHandshakeResponse(signature);
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error handling HANDSHAKE_CHALLANGE message, exception: " + e);
            }
        }

        private static void SendHandshakeResponse(byte[] signature)
        {
            NetworkMessage newMessage = new NetworkMessage();
            newMessage.messageType = (int)ClientMessageType.HANDSHAKE_RESPONSE;
            using (MessageWriter mw = new MessageWriter())
            {
                mw.Write<int>(Common.PROTOCOL_VERSION);
                mw.Write<string>(playerName);
                mw.Write<string>(publicKey);
                mw.Write<byte[]>(signature);
                mw.Write<string>(NETWORK_SCRAPER);
                newMessage.messageData = AddLengthPayloadHeader(mw.GetMessageBytes());
            }
            dnc.QueueNetworkMessage(newMessage);
        }

        private static void HandleHandshake(byte[] messageData)
        {

            int reply = 0;
            string reason = "";
            string modFileData = "";
            int serverProtocolVersion = -1;
            int modControl = -1;
            string serverVersion = "Unknown";
            using (MessageReader mr = new MessageReader(messageData, false))
            {
                //Lameness..
                mr.Read<int>();
                reply = mr.Read<int>();
                reason = mr.Read<string>();
                serverProtocolVersion = mr.Read<int>();
                serverVersion = mr.Read<string>();
                if (reply == 0)
                {
                    modControl = mr.Read<int>();
                    if (modControl != (int)ModControlMode.DISABLED)
                    {
                        modFileData = mr.Read<string>();
                    }
                }
            }
            Console.WriteLine("Reply: " + reply);
            Console.WriteLine("Reason: " + reason);
            Console.WriteLine("Protocol version: " + serverProtocolVersion);
            Console.WriteLine("Mod control: " + modControl);
            Console.WriteLine("Mod file data: " + modFileData);
            Console.WriteLine("Server version: " + serverVersion);
        }

        //My lameness...
        //DMP incorrectly reads a second byte[] header around messages due to the read with messagewriter. I'll fix it one day...
        private static byte[] AddLengthPayloadHeader(byte[] payload)
        {
            byte[] newPayload = new byte[payload.Length + 4];
            BitConverter.GetBytes(payload.Length).CopyTo(newPayload, 0);
            payload.CopyTo(newPayload, 4);
            return newPayload;
        }
    }
}

