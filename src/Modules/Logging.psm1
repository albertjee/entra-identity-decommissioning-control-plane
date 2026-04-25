$script:DecomLogPath=$null
function Initialize-DecomLog { param([Parameter(Mandatory)][string]$Path) $script:DecomLogPath=$Path; New-Item -ItemType File -Path $Path -Force | Out-Null }
function Write-DecomLog { param([string]$Level,[string]$Message) $line='[{0}] [{1}] {2}' -f (Get-Date).ToUniversalTime().ToString('o'),$Level.ToUpper(),$Message; if($script:DecomLogPath){Add-Content -Path $script:DecomLogPath -Value $line} }
function Write-DecomConsole { param([string]$Level,[string]$Message) Write-DecomLog -Level $Level -Message $Message; switch($Level.ToUpper()){'ERROR'{Write-Host $Message -ForegroundColor Red}'WARN'{Write-Host $Message -ForegroundColor Yellow}'INFO'{Write-Host $Message -ForegroundColor Cyan} default{Write-Host $Message}} }
Export-ModuleMember -Function Initialize-DecomLog,Write-DecomLog,Write-DecomConsole
