
namespace OpenVpnStatusSharp

open System
open System.Collections.Generic
open System.Runtime.InteropServices

open OpenVpnStatusSharp
open OpenVpnStatusSharp.Parser

type ParseException (msg:string) = inherit Exception(msg)

type OpenVpnStatusLog = {
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

    static member TryParse(filePath : string, [<Out>] result : OpenVpnStatusLog byref ) =
        try
            result <- OpenVpnStatusLog.Parse filePath
            true
        with
        | _ -> false