Set-StrictMode -Version Latest

function Assert-ExactSdk {
    param([Parameter(Mandatory)][string]$Version)

    $actual = (& dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $actual -ne $Version) {
        throw "The verification requires .NET SDK $Version exactly; found '$actual'."
    }
}

function Invoke-DotNet {
    & dotnet @args
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet failed with exit code $LASTEXITCODE."
    }
}

function Assert-CleanWorktree {
    param([Parameter(Mandatory)][string]$RepositoryRoot)

    $status = @(& git -C $RepositoryRoot status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to inspect the repository worktree.'
    }
    if ($status.Count -ne 0) {
        throw 'Repository worktree must be clean before isolated verification.'
    }
}

function Assert-SafeWorkRootAncestors {
    param([Parameter(Mandatory)][string]$WorkRoot)

    $discoveryFiles = @(
        'Directory.Build.props',
        'Directory.Build.targets',
        'Directory.Build.rsp',
        'Directory.Solution.props',
        'Directory.Solution.targets',
        'Directory.Packages.props',
        'NuGet.Config'
    )
    $current = Split-Path -Parent ([IO.Path]::GetFullPath($WorkRoot))
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        foreach ($fileName in $discoveryFiles) {
            $candidate = Join-Path $current $fileName
            if (Test-Path -LiteralPath $candidate) {
                throw "Unsafe build customization file found above the verification work root. '$candidate'."
            }
        }

        $parent = Split-Path -Parent $current
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $current) {
            break
        }
        $current = $parent
    }
}

function Get-PinnedBuildArguments {
    param([Parameter(Mandatory)][string]$SourceRoot)

    $sourceRoot = [IO.Path]::GetFullPath($SourceRoot)
    return @(
        '-noAutoResponse',
        "-p:DirectoryBuildPropsPath=$(Join-Path $sourceRoot 'Directory.Build.props')",
        "-p:DirectoryBuildTargetsPath=$(Join-Path $sourceRoot 'Directory.Build.targets')",
        "-p:DirectorySolutionPropsPath=$(Join-Path $sourceRoot 'Directory.Solution.props')",
        "-p:DirectorySolutionTargetsPath=$(Join-Path $sourceRoot 'Directory.Solution.targets')",
        "-p:DirectoryPackagesPropsPath=$(Join-Path $sourceRoot 'Directory.Packages.props')"
    )
}

function Copy-TrackedSource {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string]$DestinationRoot
    )

    New-Item -ItemType Directory -Path $DestinationRoot | Out-Null
    $paths = & git -C $RepositoryRoot ls-files --cached
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to enumerate the repository source.'
    }

    foreach ($relativePath in $paths) {
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            $relativePath.Replace('\', '/').StartsWith(
                'vendor/p14a2/packages/',
                [StringComparison]::OrdinalIgnoreCase)) {
            continue
        }

        $source = Join-Path $RepositoryRoot $relativePath
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            continue
        }
        $destination = Join-Path $DestinationRoot $relativePath
        $parent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Force -Path $parent | Out-Null
        }
        Copy-Item -LiteralPath $source -Destination $destination
    }

    $vendorParent = Join-Path $DestinationRoot 'vendor\p14a2'
    New-Item -ItemType Directory -Force -Path $vendorParent | Out-Null
    $vendorLink = Join-Path $vendorParent 'packages'
    $vendorTarget = Join-Path $RepositoryRoot 'vendor\p14a2\packages'
    New-Item -ItemType Junction -Path $vendorLink -Target $vendorTarget | Out-Null
}

function Get-RepositoryBuildSnapshot {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string[]]$ProjectRoots
    )

    $snapshot = @{}
    foreach ($projectRoot in $ProjectRoots) {
        foreach ($directoryName in @('bin', 'obj')) {
            $directory = Join-Path (Join-Path $RepositoryRoot $projectRoot) $directoryName
            if (-not (Test-Path -LiteralPath $directory)) {
                continue
            }
            foreach ($file in Get-ChildItem -LiteralPath $directory -File -Recurse) {
                $rootPrefix = $RepositoryRoot.TrimEnd(
                    [IO.Path]::DirectorySeparatorChar,
                    [IO.Path]::AltDirectorySeparatorChar) +
                    [IO.Path]::DirectorySeparatorChar
                $relative = $file.FullName.Substring($rootPrefix.Length)
                $snapshot[$relative] = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            }
        }
    }
    return ,$snapshot
}

function Assert-SnapshotEqual {
    param(
        [Parameter(Mandatory)][hashtable]$Expected,
        [Parameter(Mandatory)][hashtable]$Actual
    )

    if ($Expected.Count -ne $Actual.Count) {
        throw "Repository build state changed: expected $($Expected.Count) files, found $($Actual.Count)."
    }
    foreach ($key in $Expected.Keys) {
        if (-not $Actual.ContainsKey($key) -or $Actual[$key] -ne $Expected[$key]) {
            throw "Repository build state changed at '$key'."
        }
    }
}

function Get-NormalizedPath {
    param([Parameter(Mandatory)][string]$Path)
    return [IO.Path]::GetFullPath($Path).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar)
}

function Assert-AssetsPackageFolder {
    param(
        [Parameter(Mandatory)][string]$AssetsPath,
        [Parameter(Mandatory)][string]$ExpectedPackages
    )

    $assets = Get-Content -LiteralPath $AssetsPath -Raw | ConvertFrom-Json
    $folders = @($assets.packageFolders.PSObject.Properties.Name)
    if ($folders.Count -ne 1 -or
        (Get-NormalizedPath $folders[0]) -ne (Get-NormalizedPath $ExpectedPackages)) {
        throw "Unexpected packageFolders in '$AssetsPath': $($folders -join ', ')."
    }
}

function Assert-AssetsPackageFoldersUnderRoot {
    param(
        [Parameter(Mandatory)][string]$AssetsPath,
        [Parameter(Mandatory)][string]$ExpectedPackages,
        [Parameter(Mandatory)][string]$WorkRoot
    )

    $assets = Get-Content -LiteralPath $AssetsPath -Raw | ConvertFrom-Json
    $folders = @($assets.packageFolders.PSObject.Properties.Name)
    $expected = Get-NormalizedPath $ExpectedPackages
    $prefix = (Get-NormalizedPath $WorkRoot) + [IO.Path]::DirectorySeparatorChar
    if ($folders.Count -eq 0 -or
        -not ($folders | Where-Object { (Get-NormalizedPath $_) -eq $expected })) {
        throw "The isolated packages folder is absent from '$AssetsPath'."
    }
    foreach ($folder in $folders) {
        if (-not (Get-NormalizedPath $folder).StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase)) {
            throw "packageFolders escaped the work root in '$AssetsPath': '$folder'."
        }
    }
}

function Assert-MetadataSources {
    param(
        [Parameter(Mandatory)][string]$PackagesRoot,
        [Parameter(Mandatory)][string]$ExpectedSource,
        [Parameter(Mandatory)][int]$ExpectedCount
    )

    $metadataFiles = @(Get-ChildItem -LiteralPath $PackagesRoot -Recurse -File -Filter '.nupkg.metadata')
    if ($metadataFiles.Count -ne $ExpectedCount) {
        throw "Expected $ExpectedCount package metadata files, found $($metadataFiles.Count)."
    }
    foreach ($metadataFile in $metadataFiles) {
        $metadata = Get-Content -LiteralPath $metadataFile.FullName -Raw | ConvertFrom-Json
        if ((Get-NormalizedPath $metadata.source) -ne (Get-NormalizedPath $ExpectedSource)) {
            throw "Package '$($metadataFile.FullName)' came from '$($metadata.source)', not the vendor source."
        }
    }
}

function Assert-NoHttpCacheFiles {
    param([Parameter(Mandatory)][string]$HttpCache)
    if (@(Get-ChildItem -LiteralPath $HttpCache -Recurse -File).Count -ne 0) {
        throw 'The HTTP cache is not empty.'
    }
}

function Assert-DownloadDependencies {
    param(
        [Parameter(Mandatory)][string]$AssetsPath,
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$RuntimePackVersion
    )

    $assets = Get-Content -LiteralPath $AssetsPath -Raw | ConvertFrom-Json
    $dependencies = @($assets.project.frameworks.'net10.0'.downloadDependencies)
    $actual = @($dependencies | ForEach-Object { "$($_.name)/$($_.version)" } | Sort-Object)

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $expected = @(
        $manifest.packages |
            Where-Object role -eq 'win-arm64-sdk-runtime-pack' |
            ForEach-Object {
                if ($_.version -ne $RuntimePackVersion) {
                    throw "Runtime pack '$($_.id)' is not pinned to $RuntimePackVersion."
                }
                "$($_.id)/[$($_.version), $($_.version)]"
            } |
            Sort-Object
    )
    if (($actual -join "`n") -ne ($expected -join "`n")) {
        throw "downloadDependencies do not match the manifest.`nExpected:`n$($expected -join "`n")`nActual:`n$($actual -join "`n")"
    }
}

function Assert-ArtifactsUnderRoot {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$WorkRoot
    )

    $prefix = (Get-NormalizedPath $WorkRoot) + [IO.Path]::DirectorySeparatorChar
    foreach ($directory in Get-ChildItem -LiteralPath $SourceRoot -Directory -Recurse |
        Where-Object Name -in @('bin', 'obj')) {
        if (-not $directory.FullName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Build artifact escaped the work root: '$($directory.FullName)'."
        }
    }
}

function Assert-RepositoryAssetsUsable {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][string[]]$ProjectRoots
    )

    foreach ($projectRoot in $ProjectRoots) {
        $assetsPath = Join-Path (Join-Path $RepositoryRoot $projectRoot) 'obj\project.assets.json'
        if (-not (Test-Path -LiteralPath $assetsPath)) {
            continue
        }
        $assets = Get-Content -LiteralPath $assetsPath -Raw | ConvertFrom-Json
        foreach ($folder in $assets.packageFolders.PSObject.Properties.Name) {
            if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                throw "Repository assets reference a deleted package folder: '$folder'."
            }
        }
    }
}

function Remove-OwnedWorkRoot {
    param(
        [Parameter(Mandatory)][string]$WorkRoot,
        [Parameter(Mandatory)][string]$ArtifactsRoot
    )

    $requiredPrefix = (Get-NormalizedPath $ArtifactsRoot) + [IO.Path]::DirectorySeparatorChar
    if (-not (Get-NormalizedPath $WorkRoot).StartsWith(
        $requiredPrefix,
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove a work root outside the owned verification directory.'
    }
    Remove-Item -LiteralPath $WorkRoot -Recurse -Force
}
