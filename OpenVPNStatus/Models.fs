namespace OpenVPNStatus

open System
open System.Net
open System.Runtime.InteropServices
open System.Text.RegularExpressions

open NetTools

type MACAddress private(str) =
    static member Create str = 
        match Regex.IsMatch(
            str, 
            "(([0-9a-f]{2})[:]){5}([0-9a-f]{2})",
            RegexOptions.IgnoreCase) with
        | true -> Some(MACAddress str)
        | _ -> None

    member this.Value = str

type VirtualAddress = 
    | IP of IPAddress
    | IPRange of IPAddressRange
    | MAC of MACAddress
with
    member this.TryGetIPAddress( [<Out>] result : IPAddress byref ) =
        match this with
        | IP ip ->
            result <- ip
            true
        | _ -> false

    member this.TryGetIPAddressRange( [<Out>] result : IPAddressRange byref ) =
        match this with
        | IPRange range ->
            result <- range
            true
        | _ -> false

    member this.TryGetMACAddress( [<Out>] result : MACAddress byref ) =
        match this with
        | MAC mac ->
            result <- mac
            true
        | _ -> false

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