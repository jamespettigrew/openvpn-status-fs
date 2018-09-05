namespace OpenVPNStatus

open System
open System.Collections.Generic
open System.Net
open System.Text.RegularExpressions

open NetTools
open System.Globalization

module Models =
    type MACAddress = private MACAddress of string

    module MACAddress =
        let create str = 
            match Regex.IsMatch(
                str, 
                "(([0-9a-f]{2})[:]){5}([0-9a-f]{2})",
                RegexOptions.IgnoreCase) with
            | true -> Some(MACAddress str)
            | _ -> None

        let value (MACAddress str) = str

    let (|MACAddress|_|) str =
        match MACAddress.create str with
        | Some(macaddr) -> Some(macaddr)
        | _ -> None

    let (|IPAddress|_|) str =
        match IPAddress.TryParse str with
        | (true, ipAddr) -> Some(ipAddr)
        | _ -> None

    let (|IPAddressRange|_|) str =
        match IPAddressRange.TryParse str with
        | (true, ipRange) -> Some(ipRange)
        | _ -> None

    let (|Port|_|) str =
        match Int32.TryParse str with
        | (true, p) when (p > IPEndPoint.MinPort) && (p < IPEndPoint.MaxPort) -> Some p
        | _ -> None

    type VirtualAddress = 
        | IP of IPAddress
        | IPRange of IPAddressRange
        | MAC of MACAddress

    let parseVirtualAddress str =
        match str with
        | IPAddress i -> Some(VirtualAddress.IP i)
        | MACAddress m -> Some(VirtualAddress.MAC m)
        | IPAddressRange r -> Some(VirtualAddress.IPRange r)
        | _ -> None

    let (|IsVirtualAddress|_|) str =
        parseVirtualAddress str

    let parseRealAddress (addrStr : string) =
        match addrStr.LastIndexOf(":") with
        | index when index >= 0 ->

            let hostStr = addrStr.Substring(0, index)
            let portStr = addrStr.Substring(index + 1, addrStr.Length - index - 1)

            match hostStr, portStr with
            | IPAddress i, Port p -> Some(new IPEndPoint(i, p))
            | _ -> None
        | _ -> None

    let (|RealAddress|_|) str =
        parseRealAddress str

    let (|Int|_|) str =
        match Int32.TryParse str with
        | (true, x) -> Some(x)
        | _ -> None
    
    let (|LogDateTime|_|) str =
        let format = "ddd MMM dd HH:mm:ss yyyy" 
        let provider = CultureInfo.InvariantCulture;
        let style = DateTimeStyles.None

        match DateTime.TryParseExact(str, format, provider, style) with
        | (true, datetime) -> Some(datetime)
        | _ -> None

    type Client = {
        CommonName: String;
        RealAddress: IPEndPoint;
        BytesReceived: int;
        BytesSent: int;
        ConnectedSince: DateTime;
    }

    type Route = {
        VirtualAddress: VirtualAddress
        CommonName: String;
        RealAddress: IPEndPoint;
        LastRef: DateTime;
    }

    type GlobalStats = {
        MaxBcastMcastQueueLength: int
    }


    let parseClientRow (row : string) =
        match row.Split ',' with
        | [| commonName; RealAddress r; Int bytesRx; Int bytesTx; LogDateTime t|] ->
            Some { 
                CommonName = commonName
                RealAddress = r
                BytesReceived = bytesRx
                BytesSent = bytesTx
                ConnectedSince = t
            }
        | _ -> None

    let parseRouteRow (row : string) =
        match row.Split ',' with
        | [| IsVirtualAddress v; commonName; RealAddress r; LogDateTime t|] ->
            Some { 
                VirtualAddress = v
                CommonName = commonName
                RealAddress = r
                LastRef = t
            }
        | _ -> None
