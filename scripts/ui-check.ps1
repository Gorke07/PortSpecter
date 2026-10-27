param([ValidateSet('Start','Review','Pause','Stop','Capture','Close','SelectFirst')][string]$Action = 'Capture', [int]$X=420, [int]$Y=700)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PortSpecterWindow {
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr window, uint message, IntPtr wParam, IntPtr lParam);
}
'@
$process = Get-Process portspecter -ErrorAction Stop | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $process) { throw 'No PortSpecter window found' }
if ($Action -eq 'Close') {
    [PortSpecterWindow]::PostMessage($process.MainWindowHandle,0x0010,[IntPtr]::Zero,[IntPtr]::Zero) | Out-Null
} elseif ($Action -eq 'SelectFirst') {
    # Logical client coordinates at the default size. Used only by the developer smoke check.
    $point = [IntPtr](($Y -shl 16) -bor $X)
    [PortSpecterWindow]::PostMessage($process.MainWindowHandle,0x0200,[IntPtr]0,$point) | Out-Null
    [PortSpecterWindow]::PostMessage($process.MainWindowHandle,0x0201,[IntPtr]1,$point) | Out-Null
    [PortSpecterWindow]::PostMessage($process.MainWindowHandle,0x0202,[IntPtr]0,$point) | Out-Null
} else {
    $key = @{Start=0x74;Review=0x74;Pause=0x77;Stop=0x78;Capture=0x7B}[$Action]
    [PortSpecterWindow]::PostMessage($process.MainWindowHandle,0x0100,[IntPtr]$key,[IntPtr]1) | Out-Null
    [PortSpecterWindow]::PostMessage($process.MainWindowHandle,0x0101,[IntPtr]$key,[IntPtr]0xC0000001L) | Out-Null
}
