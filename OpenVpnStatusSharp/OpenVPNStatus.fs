
namespace OpenVPNStatus

open System
open System.Collections.Generic
open System.Runtime.InteropServices

open OpenVPNStatus
open OpenVPNStatus.Parser

type ParseException (msg:string) = inherit Exception(msg)

type StatusLog = {
        Updated: DateTime
        Clients: IReadOnlyCollection<Client>
        Routes: IReadOnlyCollection<Route>
        GlobalStats: GlobalStats
    }
with
    static member Parse(filePath : string) =
        match (parse filePath) with
        |  Ok log ->
            { 
                Updated = log.Updated
                Clients = log.Clients
                Routes = log.Routes
                GlobalStats = log.GlobalStats
            }
        | Error msg -> raise (ParseException(msg))

    static member TryParse(filePath : string, [<Out>] result : StatusLog byref ) =
        try
            result <- StatusLog.Parse filePath
            true
        with
        | _ -> false