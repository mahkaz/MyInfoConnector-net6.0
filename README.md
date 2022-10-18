# MyInfoConnector-net6.0
MyInfoConnector target framework upgraded from v4.8 to net6.0 using upgrade assistant<br>
MSDN Tutorial: https://learn.microsoft.com/en-us/dotnet/core/porting/upgrade-assistant-aspnetmvc

## Manual Changes
refactor ["obsolete"](https://learn.microsoft.com/en-us/dotnet/core/compatibility/networking/6.0/webrequest-deprecated) code from v4.8
- token and auth api requests
- Cryptographically secure RNG
- added bc-auth (unstable)

## Original Connector by SingPass
https://github.com/singpass/myinfo-connector-dotnet

## Notes
1. backchannel authentication is currently unavailable (last checked 2022-10-18)
