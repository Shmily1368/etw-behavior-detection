# SPDX-License-Identifier: AGPL-3.0-only
# Run during an explicitly started short collector session.
$ErrorActionPreference = "Stop"
$workloadDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("etw-behavior-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $workloadDirectory | Out-Null
try {
    1..10 | ForEach-Object {
        $workloadFile = Join-Path $workloadDirectory ("example-" + $_ + ".txt")
        [System.IO.File]::WriteAllText($workloadFile, "Benign ETW workload")
        [System.IO.File]::ReadAllText($workloadFile) | Out-Null
    }
    $workloadProcess = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
        -ArgumentList "/c", "exit", "0" -Wait -PassThru
    Write-Output ("Child process exited: " + $workloadProcess.ExitCode)
} finally {
    Remove-Item -LiteralPath $workloadDirectory -Recurse -Force
}
