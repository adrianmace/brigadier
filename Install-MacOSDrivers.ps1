function Install-MacOSDrivers { 
    [CmdletBinding()]
    Param(
        [string]$Model = (Get-WmiObject -Class Win32_ComputerSystem).Model,
        [switch]$Install,
        [string]$OutputDir = "C:\macOS",
        [switch]$KeepFiles,
        [array]$ProductId,
        [string]$SUCATALOG_URL = 'https://swscan.apple.com/content/catalogs/others/index-10.13seed-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz',
        [string]$SEVENZIP_URL = 'https://www.7-zip.org/a/7z1805-x64.msi'
    )

    # Disable Invoke-WebRequest progress bar to speed up download due to bug
    $ProgressPreference = "SilentlyContinue"

    # Create Output Directory if it does not exist
    if (!(Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force }

    # Check if at least 7zip 15.14 is installed. If not, download and install it.
    $7z = "$env:ProgramFiles\7-Zip\7z.exe"
    if ((Test-Path $7z) -And ([decimal](Get-ItemProperty $7z).VersionInfo.FileVersion -gt 15.14)) {
        $7zInstalled = $true
    } else { 
        Invoke-WebRequest -Uri $SEVENZIP_URL -OutFile "$OutputDir\$($SEVENZIP_URL.Split('/')[-1])" -ErrorAction Stop
        Start-Process -FilePath $env:SystemRoot\System32\msiexec.exe -ArgumentList "/i $OutputDir\$($SEVENZIP_URL.Split('/')[-1]) /qb- /norestart" -Wait -Verbose
    }

    # Read data from sucatalog and find all Bootcamp ESD's
    [xml]$sucatalog = Invoke-WebRequest -Uri $SUCATALOG_URL -Method Get -UseBasicParsing -ErrorAction Stop
    $sucatalog.plist.dict.dict.dict | Where-Object { $_.String -match "Bootcamp" } | ForEach-Object {
        # Search dist files to find supported models, using regex match to find models in dist files - stolen regex from brigadier's source
        $SupportedModels = [regex]::Matches((Invoke-RestMethod -Uri ($_.dict | Where-Object { $_.Key -match "English" }).String).InnerXml,"([a-zA-Z]{4,12}[0-9]{1,2}\,[1-6])").Value
        if ($SupportedModels -contains $Model) { 
            $version = [regex]::Match(($_.dict | Where-Object { $_.Key -match "English" }).String,"(\d{3}-\d{5})").Value
            Write-Output "Found supported ESD: $Version"
            [array]$bootcamplist += $_ 
        }
    }
    if ($bootcamplist.Length -gt 1) { 
        Write-warning "Found more than 1 supported Bootcamp ESD. Selecting newest based on posted date which may not always be correct"
        $bootcamplist | ForEach-Object { 
            if ($_.date -gt $latestdate) { 
                $latestdate = $_.date
                $download = $_.array.dict.string | Where-Object { $_ -match '.pkg' }
            }
        }
    } else { $download = $bootcamplist.array.dict.string | Where-Object { $_ -match '.pkg' }}

    # Download the BootCamp ESD
    Invoke-WebRequest -Uri $download -Method Get -OutFile "$OutputDir\BootCampESD.pkg" -UseBasicParsing -ErrorAction Stop
    if (Test-Path -Path "$OutputDir\BootCampESD.pkg") {
        # Extract the bootcamp installer
        Invoke-Command -ScriptBlock { 
            & $7z -o"$OutputDir" -y e "$OutputDir\BootCampESD.pkg"
            & $7z -o"$OutputDir" -y e "$OutputDir\Payload~"
		    & $7z -o"$OutputDir" -y x "$OutputDir\WindowsSupport.dmg"
        }
    } else { Write-Warning "BootCampESD.pkg could not be found"; exit 1000 } 

    # Uninstall 7zip if we installed it
    if ($7zInstalled -ne $true) { Start-Process -FilePath $env:SystemRoot\System32\msiexec.exe -ArgumentList "/x $OutputDir\$($SEVENZIP_URL.Split('/')[-1]) /qb- /norestart" -Wait }

    # Install Bootcamp using Task Scheduler to install as SYSTEM
    if ($Install) { 
	    # Add Sysinternals Acceptance
	    New-Item -Path "HKCU:\Software\Sysinternals" -Force | Out-Null
	    New-ItemProperty -Path "HKCU:\Software\Sysinternals" -Name "EulaAccepted" -Value "1" -PropertyType DWORD -Force | Out-Null
	    New-Item -Path "HKCU:\.DEFAULT\Software\Sysinternals" -Force | Out-Null
	    New-ItemProperty -Path "HKCU:\.DEFAULT\Software\Sysinternals" -Name "EulaAccepted" -Value "1" -PropertyType DWORD -Force | Out-Null

	    # Install Bootcamp	
        Start-Process -FilePath $PsScriptRoot\psexec64.exe -ArgumentList "-i -s $env:SystemRoot\System32\msiexec.exe /i $OutputDir\Bootcamp\Drivers\Apple\BootCamp.msi NOCHECK=1 /qn /norestart" -Wait 
    } else { exit 2000 }
}

Install-MacOSDrivers -Install