namespace OpenVPNStatus

module Parser =
    open System
    open Models

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
        | [| IsVirtualAddress v; commonName; RealAddress r; LogDateTime t|] ->
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
        let emptyLog = { 
            Updated = DateTime.Now
            Clients = List.empty<Client>
            Routes = List.empty<Route>
            GlobalStats = { MaxBcastMcastQueueLength = 0 }
        }

        parseClientListHeader (emptyLog, rows)
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