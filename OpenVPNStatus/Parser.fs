namespace OpenVPNStatus

module internal Parser =
    open System
    open System.Globalization
    open System.Net
    open System.Runtime.CompilerServices

    open NetTools

    open OpenVPNStatus

    [<assembly: InternalsVisibleTo("OpenVPNStatus.Tests")>]
    do()

    type LogContents = {
        Updated: DateTime
        Clients: Client list
        Routes: Route list
        GlobalStats: GlobalStats
    }

    let (|MACAddress|_|) str =
        match MACAddress.Create str with
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

    let parseVirtualAddress str =
        match str with
        | IPAddress i -> Some(VirtualAddress.IP i)
        | MACAddress m -> Some(VirtualAddress.MAC m)
        | IPAddressRange r -> Some(VirtualAddress.IPRange r)
        | _ -> None

    let (|VirtualAddress|_|) str =
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
        let format = "ddd MMM d HH:mm:ss yyyy" 
        let provider = CultureInfo.InvariantCulture;
        let style = DateTimeStyles.AllowWhiteSpaces

        match DateTime.TryParseExact(str, format, provider, style) with
        | (true, datetime) -> Some(datetime)
        | _ -> None

    let parseClientListHeader (log, rows) =
        match rows with
        | "OpenVPN CLIENT LIST" :: rest -> Ok (log, rest)
        | _ -> Error "Invalid client list header"

    let parseUpdated (log, rows) =
        match rows with
        | (h : string) :: rest ->
            match h.Split ',' with
            | [|"Updated"; LogDateTime time; |] -> Ok ({ log with Updated = time }, rest)
            | _ -> Error (sprintf "Invalid Updated line: %s" h)
        | _ -> Error "Invalid Updated line"

    let parseClientColumnHeaders (log, rows) =
        match rows with
        | "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since" :: rest -> 
            Ok (log, rest)
        | _ -> Error "Invalid client list columns headers"

    let parseRoutingTableHeader line =
        match line with
        | "ROUTING TABLE" -> Some ()
        | _ -> None

    let parseRouteColumnHeaders (log, rows) =
        match rows with
        | "Virtual Address,Common Name,Real Address,Last Ref" :: rest -> Ok (log, rest)
        | _ -> Error "Invalid route list column headers"

    let parseGlobalStatsHeader line =
        match line with
        | "GLOBAL STATS" -> Some ()
        | _ -> None

    let parseGlobalStatsRow (line: string) =
        match line.Split ',' with
        | [|"Max bcast/mcast queue length"; Int length; |] -> 
            Some { MaxBcastMcastQueueLength = length }
        | _ -> None

    let parseGlobalStats (log, rows) =
        match rows with
        | h :: rest ->
            match parseGlobalStatsRow h with
            | Some globalStats -> Ok ({ log with GlobalStats = globalStats }, rest)
            | None -> Error (sprintf "Invalid Global Stats line: %s" h)
        | _ -> Error "Invalid Global Stats line"

    let parseEnd (log, rows) =
        match rows with
        | "END" :: _ -> Ok log
        | _ -> Error "Invalid END line"

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
        | [| VirtualAddress v; commonName; RealAddress r; LogDateTime t|] ->
            Some { 
                VirtualAddress = v
                CommonName = commonName
                RealAddress = r
                LastRef = t
            }
        | _ -> None

    let rec parseClients (log, rows) =
        match rows with
        | h :: rest ->
            match (parseRoutingTableHeader h) with
            | Some _ -> Ok (log, rest)
            | None ->
                match parseClientRow h  with
                | Some client ->
                    let updatedClients = List.append log.Clients [client]
                    let logWithClientAdded = { log with Clients = updatedClients }
                    parseClients (logWithClientAdded, rest)
                | _ -> Error (sprintf "Invalid client line: %s" h)
        | _ -> Error "Invalid clients list"

    let rec parseRoutes (log, rows) =
        match rows with
        | h :: rest ->
            match (parseGlobalStatsHeader h) with
            | Some _ -> Ok (log, rest)
            | None ->
                match parseRouteRow h with
                | Some route ->
                    let updatedRoutes = List.append log.Routes [route]
                    let logWithRouteAdded = { log with Routes = updatedRoutes }
                    parseRoutes (logWithRouteAdded, rest)
                | _ -> Error (sprintf "Invalid route line: %s" h)
        | _ -> Error "Invalid routes list"

    let bind switchFunction twoTrackInput = 
        match twoTrackInput with
        | Ok s -> switchFunction s
        | Error f -> Error f

    let ( >>= ) m f =
        bind f m

    let parseRows rows =
        let log : LogContents = { 
            Updated = DateTime.Now
            Clients = List.empty<Client>
            Routes = List.empty<Route>
            GlobalStats = { MaxBcastMcastQueueLength = 0 }
        } 

        parseClientListHeader (log, rows)
        >>= parseUpdated
        >>= parseClientColumnHeaders
        >>= parseClients
        >>= parseRouteColumnHeaders
        >>= parseRoutes
        >>= parseGlobalStats
        >>= parseEnd

    let parse filePath =
        let readLines = System.IO.File.ReadAllLines(filePath)
        parseRows (readLines |> Array.toList)