<#
.SYNOPSIS
    Scans a directory and prints/saves an indented file tree.

.PARAMETER Path
    Root folder to scan. Defaults to current directory.

.PARAMETER OutFile
    Optional path to save the tree as a text file. If omitted, prints to console.

.PARAMETER Exclude
    Folder names to skip entirely (case-insensitive). Defaults to common build/VCS noise.

.EXAMPLE
    .\Get-FileTree.ps1 -Path D:\project\zig\keepasshttp2 -OutFile tree.txt
#>

param(
    [string]$Path = ".",
    [string]$OutFile,
    [string[]]$Exclude = @("bin", "obj", ".git", ".vs", "node_modules", "TestResults")
)

function Write-Tree {
    param(
        [string]$CurrentPath,
        [string]$Indent = ""
    )

    $items = Get-ChildItem -LiteralPath $CurrentPath -Force |
        Where-Object { $Exclude -notcontains $_.Name } |
        Sort-Object @{Expression = { -not $_.PSIsContainer }}, Name

    $count = $items.Count
    for ($i = 0; $i -lt $count; $i++) {
        $item = $items[$i]
        $isLast = ($i -eq $count - 1)
        $connector = if ($isLast) { "\-- " } else { "+-- " }
        $line = "$Indent$connector$($item.Name)"
        $lines.Add($line)

        if ($item.PSIsContainer) {
            $nextIndent = $Indent + $(if ($isLast) { "    " } else { "|   " })
            Write-Tree -CurrentPath $item.FullName -Indent $nextIndent
        }
    }
}

$resolvedPath = Resolve-Path -LiteralPath $Path
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add($resolvedPath.Path)
Write-Tree -CurrentPath $resolvedPath.Path

if ($OutFile) {
    $lines | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "Tree saved to $OutFile"
} else {
    $lines | ForEach-Object { Write-Host $_ }
}