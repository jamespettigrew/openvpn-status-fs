module OpenVPNStatus.Tests

open System
open System.Net
open Xunit

open NetTools
open OpenVPNStatus.Models

let validMACAddresses = [|
    "00:1A:2B:3C:4D:5E"
    "00:1a:2b:3c:4d:5e"
    "AA:BB:CC:DD:EE:FF"
    "aa:bb:cc:dd:ee:ff"
    "11:11:11:11:11:11"
|]

let invalidMACAddresses = [|
    ""
    "lsfjldshfsl"
    "0A:1B:2C:3D:4E"
    "0A:1B:2C:3D:4E:5G"
|]

[<Fact>]
let ``Valid MAC addresses correctly parsed`` () = 
    validMACAddresses 
    |> Seq.ofArray 
    |> Seq.iter(fun address ->
        let mac = MACAddress.create address
        Assert.True(mac.IsSome)
        let mac = mac.Value
        Assert.Equal(MACAddress.value mac, address)
    )

[<Fact>]
let ``Invalid MAC addresses return None`` () = 
    invalidMACAddresses 
    |> Seq.ofArray 
    |> Seq.iter(fun address ->
        let mac = MACAddress.create address
        Assert.True(mac.IsNone)
    )

[<Fact>]
let ``MAC address parsed as VirtualAddress.MAC`` () = 
    match parseVirtualAddress validMACAddresses.[0] with
    | Some(VirtualAddress.MAC _) -> true
    | _ -> false
    |> Assert.True

[<Fact>]
let ``IP address parsed as VirtualAddress.IP`` () = 
    match parseVirtualAddress "192.168.0.1" with
    | Some(VirtualAddress.IP _) -> true
    | _ -> false
    |> Assert.True

[<Fact>]
let ``IP range parsed as VirtualAddress.IPRange`` () = 
    match parseVirtualAddress "192.168.0.1/31" with
    | Some(VirtualAddress.IPRange _) -> true
    | _ -> false
    |> Assert.True

[<Fact>]
let ``Invalid virtual address parsed as None`` () = 
    let invalid = "asfhjsjf"
    let virtualAddr = parseVirtualAddress invalid
    Assert.True(virtualAddr.IsNone)
