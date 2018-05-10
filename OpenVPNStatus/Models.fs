namespace OpenVPNStatus

open System
open System.Net
open System.Text.RegularExpressions

open NetTools

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

    let parseRealAddress (addrStr : string) =
        match addrStr.LastIndexOf(":") with
        | index when index >= 0 ->

            let hostStr = addrStr.Substring(0, index)
            let portStr = addrStr.Substring(index + 1, addrStr.Length - index - 1)

            match hostStr, portStr with
            | IPAddress i, Port p -> Some(new IPEndPoint(i, p))
            | _ -> None
        | _ -> None