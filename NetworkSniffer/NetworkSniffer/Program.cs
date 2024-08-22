using System.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using PacketDotNet;
using SharpPcap;
using System.Net.Sockets;
using System.Data.SQLite;
using System.Text;

namespace PlatformInfo.Networks
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            await Host.CreateDefaultBuilder(args)
            .ConfigureServices((_, services) =>
            services.AddHostedService<SharpPCapNetwork>())
            .RunConsoleAsync();
        }
    }
    public class SharpPCapNetwork : IHostedService
    {
        private static List<ILiveDevice> deviceList = new List<ILiveDevice>();
        private TcpListener _listener;
        private CancellationTokenSource _cts = new CancellationTokenSource();

        public static void GetDeviceList()
        {
            var ver = Pcap.SharpPcapVersion;
            StringBuilder sb = new StringBuilder();
            if (CaptureDeviceList.Instance.Count < 1)
            {
                sb.AppendLine("No devices were found on this machine");
                return;
            }

            int i = 1;
            foreach (var dev in CaptureDeviceList.Instance)
            {
                sb.AppendLine($"{i}) {dev.Name} {dev.Description}   {dev.MacAddress}");
                deviceList.Add(dev);
                i++;
            }
            Console.WriteLine(sb);
            string FullPath = Path.Combine(Directory.GetCurrentDirectory(), "Temps");
            Directory.CreateDirectory(FullPath);
            string FileName = Path.Combine(FullPath, $"NetworkDevices_{DateTime.Now:yyyyMMddHHmmss}.txt");

            File.WriteAllText(FileName, $"Datetime:#{DateTime.Now}#\n{sb}");
        }

        private static void CaptureDevice(int i)
        {
            deviceList[i].OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
            int readTimeoutMilliseconds = 1000;
            try
            {
                deviceList[i].Open(DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, readTimeoutMilliseconds);
                deviceList[i].StartCapture();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Device Error {deviceList[i].Name} {deviceList[i].Description} {deviceList[i].MacAddress} {ex.Message}");
            }
        }

        private static int packetIndex = 0;


        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var ipPacket = packet.Extract<IPPacket>();
            if (ipPacket != null)
            {
                string sourceIP = ipPacket.SourceAddress.ToString();
                string destinationIP = ipPacket.DestinationAddress.ToString();


                //string restrictedIP = "192.168.1.62";  
                //if (sourceIP == restrictedIP || destinationIP == restrictedIP)
                //{
                //    Console.WriteLine($"Packet from/to restricted IP {restrictedIP} dropped.");
                //    return;  
                //}

                string protocolType = ipPacket.Protocol.ToString();
                string protocolPacket = ipPacket.PayloadPacket?.ToString() ?? "N/A";
                string timestamp = rawPacket.Timeval.Date.ToString();
                int millisecond = rawPacket.Timeval.Date.Millisecond;

                InsertPacketIntoDatabase(packetIndex, timestamp, millisecond, sourceIP, destinationIP, protocolType, protocolPacket);

                packetIndex++;
            }
        }

        private static void InsertPacketIntoDatabase(int packetIndex, string timestamp, int millisecond, string sourceIP, string destinationIP, string protocolType, string payloadPacket)
        {
            try
            {
                string databasePath = Path.Combine(Directory.GetCurrentDirectory(), "Temps", "packets.db");
                using (var connection = new SQLiteConnection($"Data Source={databasePath};Version=3;"))
                {
                    connection.Open();
                    string insertQuery = @"
                    INSERT INTO Packets (PacketIndex, Timestamp, Millisecond, SourceIP, DestinationIP, ProtocolType, PayloadPacket)
                    VALUES (@PacketIndex, @Timestamp, @Millisecond, @SourceIP, @DestinationIP, @ProtocolType, @PayloadPacket)";
                    using (var command = new SQLiteCommand(insertQuery, connection))
                    {
                        command.Parameters.AddWithValue("@PacketIndex", packetIndex);
                        command.Parameters.AddWithValue("@Timestamp", timestamp);
                        command.Parameters.AddWithValue("@Millisecond", millisecond);
                        command.Parameters.AddWithValue("@SourceIP", sourceIP);
                        command.Parameters.AddWithValue("@DestinationIP", destinationIP);
                        command.Parameters.AddWithValue("@ProtocolType", protocolType);
                        command.Parameters.AddWithValue("@PayloadPacket", payloadPacket);
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database Insert Error: {ex.Message}");
            }
        }

        public static void InitializeDatabase()
        {
            try
            {
                string databasePath = Path.Combine(Directory.GetCurrentDirectory(), "Temps", "packets.db");
                using (var connection = new SQLiteConnection($"Data Source={databasePath};Version=3;"))
                {
                    connection.Open();
                    string createTableQuery = @"
                    CREATE TABLE IF NOT EXISTS Packets (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        PacketIndex INTEGER,
                        Timestamp TEXT,
                        Millisecond INTEGER,
                        SourceIP TEXT,
                        DestinationIP TEXT,
                        ProtocolType TEXT,
                        PayloadPacket TEXT
                    )";
                    using (var command = new SqliteCommand(createTableQuery, connection))
                    {
                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Database Initialization Error: {ex.Message}");
            }
        }

        public static void Dispose()
        {
            try
            {
                foreach (var item in deviceList)
                {
                    item.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Device Disposal Error: {ex.Message}");
            }
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            InitializeDatabase();
            GetDeviceList();
            //changes
            CaptureDevice(5);

        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            Dispose();

            return Task.CompletedTask;
        }
    }
}