# openvpn-status-sharp
**openvpn-status-sharp** is a library for parsing OpenVPN server status logs into a .NET data structure.


Getting Started
---------------
You will need the path that your OpenVPN server instance is configured to write the status log to. See the [**--status** option in the OpenVPN documentation](https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage) for more information.


At present only **--status-version 1** is supported.


```csharp
    using OpenVpnStatusSharp;

    if (OpenVpnStatusLog.TryParse("my_status.log", out OpenVpnStatusLog log))
    {
        Console.WriteLine(log.Updated); // 18/6/15 8:12:15 am

        foreach (Client client in log.Clients)
        {
            Console.WriteLine(client.CommonName); // foo@bar.com
        }

        foreach (Route route in log.Routes)
        {
            if (route.VirtualAddress.TryGetIPAddress(out System.Net.IPAddress ip))
            {
                Console.WriteLine(ip); // 192.168.255.24
            }
        }
    }
```
