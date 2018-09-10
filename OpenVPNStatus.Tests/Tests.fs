module OpenVPNStatus.Tests

open Xunit

open OpenVPNStatus.Models
open OpenVPNStatus.Parser
let validMACAddresses = [|
    "00:1A:2B:3C:4D:5E"
    "00:1a:2b:3c:4d:5e"
    "AA:BB:CC:DD:EE:FF"
    "aa:bb:cc:dd:ee:ff"
    "11:11:11:11:11:11"
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

let invalidMACAddresses = [|
    ""
    "lsfjldshfsl"
    "0A:1B:2C:3D:4E"
    "0A:1B:2C:3D:4E:5G"
|]

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
    let success = 
        match invalid with
        | IsVirtualAddress _ -> false
        | _ -> true
    Assert.True(success)

let validRealAddresses = [|
    "10.10.10.10:49502"
    "2001:db8::1000:30000"
|]


[<Fact>]
let ``Valid real address strings parsed as IPEndPoint`` () = 
    validRealAddresses 
    |> Seq.ofArray 
    |> Seq.iter(fun address ->
        let success = 
            match address with
            | RealAddress _ -> true
            | _ -> false
        Assert.True(success)
    )

let invalidRealAddresses = [|
    ""
    "lsfjldshfsl"
    "10.10.10.10:70000"
    "10.10.10.10:"
    ":"
    "1:"
    "10.10.10.10"
    "2001:db8::1000"
    "2001:db8::1000:"
    "2001:db8::1000:70000"
|]

[<Fact>]
let ``Invalid real address strings parsed as None`` () = 
    invalidRealAddresses 
    |> Seq.ofArray 
    |> Seq.iter(fun address ->
        let success = 
            match address with
            | RealAddress _ -> false
            | _ -> true
        Assert.True(success)
    )

let validDateTimes = [|
    "Thu Jun 18 04:23:03 2015"
    "Thu Oct 19 20:14:19 2017"
    "Sun Aug 05 03:54:21 2012"
|]


[<Fact>]
let ``Valid DateTimes parsed`` () = 
    validDateTimes 
    |> Seq.ofArray 
    |> Seq.iter(fun dateTime ->
        let success = 
            match dateTime with
            | LogDateTime _ -> true
            | _ -> false
        Assert.True(success)
    )

let invalidDateTimes = [|
    ""
    "asdfsadf"
    "Sin Oct 19 20:14:21 2013"
    "Thu Jun 18 04:23:03"
|]

[<Fact>]
let ``Invalid DateTimes parsed as None`` () = 
    invalidDateTimes 
    |> Seq.ofArray 
    |> Seq.iter(fun dateTime ->
        let success = 
            match dateTime with
            | LogDateTime _ -> false
            | _ -> true
        Assert.True(success)
    )

[<Fact>]
let ``Valid client row parsed as Client`` () = 
    let clientString = "foo@example.com,10.10.10.10:49502,334948,1973012,Thu Jun 18 04:23:03 2015"
    let clientOption = parseClientRow clientString
    Assert.True(clientOption.IsSome)

let invalidClientRows = [|
    ""
    ",,,,"
    "foo@example.com,,334948,1973012,Thu Jun 18 04:23:03 2015"
    "foo@example.com,10.10.10.10:49502,,1973012,Thu Jun 18 04:23:03 2015"
    "foo@example.com,10.10.10.10:49502,334948,,Thu Jun 18 04:23:03 2015"
    "foo@example.com,10.10.10.10:49502,334948,1973012,"
|]

[<Fact>]
let ``Invalid client rows parsed as None`` () = 
    invalidClientRows 
    |> Seq.ofArray 
    |> Seq.iter(fun row ->
        let clientOption = parseClientRow row
        Assert.True(clientOption.IsNone)
    )

[<Fact>]
let ``Valid route row parsed as Route`` () = 
    let routeRow = "192.168.255.118,baz@example.com,10.10.10.10:63414,Thu Jun 18 08:12:09 2015"
    let routeOption = parseRouteRow routeRow
    Assert.True(routeOption.IsSome)

let invalidRouteRows = [|
    ""
    ",,,,"
    ",baz@example.com,10.10.10.10:63414,Thu Jun 18 08:12:09 2015"
    "192.168.255.118,baz@example.com,,Thu Jun 18 08:12:09 2015"
    "192.168.255.118,baz@example.com,10.10.10.10:63414,"
|]

[<Fact>]
let ``Invalid route rows parsed as None`` () = 
    invalidRouteRows 
    |> Seq.ofArray 
    |> Seq.iter(fun row ->
        let routeOption = parseRouteRow row
        Assert.True(routeOption.IsNone)
    )

let validLogFilePaths = [|
    "./data/valid/1.log"
    "./data/valid/2.log"
    "./data/valid/3.log"
    "./data/valid/4.log"
|]

let isOk = function
| Ok _ -> (true, "")
| Error msg -> (false, msg)

[<Fact>]
let ``Valid logs parsed without error`` () =
    validLogFilePaths 
    |> Seq.ofArray 
    |> Seq.iter(fun filePath ->
        let logResult = parse filePath
        let (ok, msg) = isOk logResult
        Assert.True(ok, msg)
    )

let invalidLogFilePaths = [|
    "./data/invalid/1.log"
    "./data/invalid/2.log"
    "./data/invalid/3.log"
    "./data/invalid/4.log"
    "./data/invalid/5.log"
    "./data/invalid/6.log"
    "./data/invalid/7.log"
    "./data/invalid/8.log"
    "./data/invalid/9.log"
    "./data/invalid/10.log"
    "./data/invalid/11.log"
|]

[<Fact>]
let ``Invalid logs parsed with error`` () = 
    invalidLogFilePaths 
    |> Seq.ofArray 
    |> Seq.iter(fun filePath ->
        let logResult = parse filePath
        let (ok, msg) = isOk logResult
        Assert.False(ok, msg)
    )