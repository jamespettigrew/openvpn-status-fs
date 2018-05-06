namespace OpenVPNStatus

open System
open System.Text.RegularExpressions

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