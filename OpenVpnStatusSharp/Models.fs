namespace OpenVpnStatusSharp

open System
open System.Net
open System.Runtime.InteropServices
open System.Text.RegularExpressions

open NetTools

type MacAddress private(str) =
    static member Create str = 
        match Regex.IsMatch(
            str, 
            "(([0-9a-f]{2})[:]){5}([0-9a-f]{2})",
            RegexOptions.IgnoreCase) with
        | true -> Some(MacAddress str)
        | _ -> None

    member this.Value = str

type VirtualAddress = 
    | IP of IPAddress
    | IPRange of IPAddressRange
    | Mac of MacAddress
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

    member this.TryGetMacAddress( [<Out>] result : MacAddress byref ) =
        match this with
        | Mac mac ->
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