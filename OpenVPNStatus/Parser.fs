namespace OpenVPNStatus

module internal Parser =
    open System
    open System.Collections.Generic
    open System.Globalization
    open System.Net
    open System.Runtime.CompilerServices

    open NetTools

    open OpenVPNStatus

    [<assembly: InternalsVisibleTo("OpenVPNStatus.Tests")>]
    do()

    type LogContents = {
        Updated: DateTime
        Clients: IReadOnlyCollection<Client>
        Routes: IReadOnlyCollection<Route>
        GlobalStats: GlobalStats
    }

    let tryGetIndex (s : Memory<'T>) i =
        match i with
        | x when x <= (s.Length - 1) -> 
            Some(s.Span.[i])
        | _ -> None

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

    let parseClientListHeader (log : LogContents, rows : Memory<string>) =
        match tryGetIndex rows 0 with
        | Some("OpenVPN CLIENT LIST") -> Ok (log, rows.Slice(1))
        | Some(row) -> Error (sprintf "Invalid client list header: %s" row)
        | _ -> Error "Unexpected EOF"

    let parseUpdated (log, rows : Memory<string>) =
        match tryGetIndex rows 0 with
        | Some(row) ->
            match row.Split ',' with
            | [|"Updated"; LogDateTime time; |] -> 
                Ok ({ log with Updated = time }, rows.Slice(1))
            | _ -> Error (sprintf "Invalid Updated line: %s" row)
        | _ -> Error "Unexpected EOF"

    let parseClientColumnHeaders (log, rows : Memory<string>) =
        match tryGetIndex rows 0 with
        | Some("Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since") -> 
            Ok (log, rows.Slice(1))
        | Some(row) -> Error (sprintf "Invalid client list columns header: %s" row)
        | _ -> Error "Unexpected EOF"

    let parseRoutingTableHeader line =
        match line with
        | "ROUTING TABLE" -> Some ()
        | _ -> None

    let parseRouteColumnHeaders (log, rows : Memory<string>) =
        match tryGetIndex rows 0 with
        | Some("Virtual Address,Common Name,Real Address,Last Ref") -> 
            Ok (log, rows.Slice(1))
        | Some(row) -> Error (sprintf "Invalid route list column header: %s" row)
        | _ -> Error "Unexpected EOF" 

    let parseGlobalStatsHeader line =
        match line with
        | "GLOBAL STATS" -> Some ()
        | _ -> None

    let parseGlobalStatsRow (row: string) =
        match row.Split ',' with
        | [|"Max bcast/mcast queue length"; Int length; |] -> 
            Some { MaxBcastMcastQueueLength = length }
        | _ -> None

    let parseGlobalStats (log, rows : Memory<string>) =
        match tryGetIndex rows 0 with
        | Some(row) ->
            match parseGlobalStatsRow row with
            | Some globalStats ->
                Ok ({ log with GlobalStats = globalStats }, rows.Slice(1))
            | None -> Error (sprintf "Invalid Global Stats line: %s" row)
        | _ -> Error "Unexpected EOF"

    let parseEnd (log, rows : Memory<string>) =
        match tryGetIndex rows 0 with
        | Some("END") -> Ok (log : LogContents)
        | Some(row) -> Error (sprintf "Invalid END line: %s" row)
        | _ -> Error "Unexpected EOF"

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

    let parseClients (log, rows) =
        let rec loop (clients : List<Client>, rows) = 
            match tryGetIndex rows 0 with
            | Some(row) ->
                match parseClientRow row  with
                | Some client ->
                    clients.Add(client)
                    loop (clients, rows.Slice(1))
                | _ -> 
                    match (parseRoutingTableHeader row) with
                    | Some _ -> 
                        let clients = clients.AsReadOnly()
                        Ok ({ log with Clients = clients }, rows.Slice(1))
                    | None -> Error (sprintf "Invalid client line: %s" row)
            | _ -> Error "Unexpected EOF"
        loop (new List<Client>(), rows)

    let parseRoutes (log, rows) =
        let rec loop (routes : List<Route>, rows) =
            match tryGetIndex rows 0 with
            | Some(row) ->
                match parseRouteRow row with
                | Some route ->
                    routes.Add(route)
                    loop (routes, rows.Slice(1))
                | _ -> 
                    match (parseGlobalStatsHeader row) with
                    | Some _ ->
                        let routes = routes.AsReadOnly() 
                        Ok ({ log with Routes = routes }, rows.Slice(1))
                    | None -> Error (sprintf "Invalid route line: %s" row)
            | _ -> Error "Unexpected EOF"
        loop (new List<Route>(), rows)

    let bind switchFunction twoTrackInput = 
        match twoTrackInput with
        | Ok s -> switchFunction s
        | Error f -> Error f

    let ( >>= ) m f =
        bind f m

    let parseRows (rows : Memory<string>) =
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
        parseRows (Memory readLines)