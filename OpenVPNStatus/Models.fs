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

    type VirtualAddress = 
        | IP of IPAddress
        | IPRange of IPAddressRange
        | MAC of MACAddress

    let parseVirtualAddress (vAddrStr : string) =
        match IPAddress.TryParse vAddrStr with
        | (true, ipAddr) -> Some(VirtualAddress.IP ipAddr)
        | _ -> 
            match MACAddress.create vAddrStr with
            | Some macAddr -> Some(VirtualAddress.MAC macAddr)
            | _ ->
                match IPAddressRange.TryParse vAddrStr with
                | (true, ipRange) -> Some(VirtualAddress.IPRange ipRange)
                | _ -> None