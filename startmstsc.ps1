param([string]$username = "username", [string]$password = "password", [string]$server = "server")
Write-Host "Arg: $username"
Write-Host "Arg: $password"
cmdkey /generic:DOMAIN/$server /user:$username /pass:$password
mstsc.exe Default.rdp /v $server;
