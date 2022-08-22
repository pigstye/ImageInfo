<#
.SYNOPSIS
    This script will discover and download all available programs used by get-imageinfo.ps1 and download them to the appropriate location.
.DESCRIPTION
    This script will discover and download all available programs used by get-imageinfo.ps1 and download them to the appropriate location.
    Rerunning the script will download the latest versions. It reads process-lib.ps1 to get the configured location of the files and places them there if you have changed the location.
.EXAMPLE
    C:\PS> Setup-ImageInfo.ps1
    Downloads/extracts and saves required programs the get-imaginfo directory.
.NOTES
    Author: Tom Willett
    Date:   8/12/2022    
#>

#load locations of tools incase they have been changed
. .\Process-lib.ps1

write-host "Downloading Eric Zimmerman's Tools" -ForegroundColor Yellow
write-host "This only gets the bare minimum - you should really get his entire suite of tools - they are great." -ForegroundColor Green
# Get Eric Zimmerman Tools - this gets the .NET4 versions by default for maximum compatibility 
# set the $net variable below to 6 to get .NET6 versions
$net = 4
$URL = "https://raw.githubusercontent.com/EricZimmerman/ericzimmerman.github.io/master/index.md"
$Page = (Invoke-WebRequest -Uri $URL -UseBasicParsing).Content
if ($net -eq 6) {
    $EZamcache = ($page | Select-String '(https://.*?/net6/AmcacheParser\.zip)').matches.value
    $EZappcompat = ($page | Select-String '(https://.*?/net6/AppCompatCacheParser\.zip)').matches.value
    $EZjlecmd = ($page | Select-String '(https://.*?/net6/JLECmd\.zip)').matches.value
    $EZlecmd = ($page | Select-String '(https://.*?/net6/LECmd\.zip)').matches.value
    $EZmftcmd = ($page | Select-String '(https://.*?/net6/MFTECmd\.zip)').matches.value
    $EZpemcd = ($page | Select-String '(https://.*?/net6/PECmd\.zip)').matches.value
    $EZrbcmd = ($page | Select-String '(https://.*?/net6//RBCmd\.zip)').matches.value
    $EZrfc = ($page | Select-String '(https://.*?/net6/RecentFileCacheParser\.zip)').matches.value
    $EZsbe = ($page | Select-String '(https://.*?/net6/SBECmd\.zip)').matches.value
    $EZwxt = ($page | Select-String '(https://.*?/net6/WxTCmd\.zip)').matches.value
    $EZrecmd = ($page | Select-String '(https://.*?/net6/RECmd\.zip)').matches.value
} else {
    $EZamcache = ($page | Select-String '(https://.*?AmcacheParser\.zip)').matches.value
    $EZappcompat = ($page | Select-String '(https://.*?AppCompatCacheParser\.zip)').matches.value
    $EZjlecmd = ($page | Select-String '(https://.*?JLECmd\.zip)').matches.value
    $EZlecmd = ($page | Select-String '(https://.*?/LECmd\.zip)').matches.value
    $EZmftcmd = ($page | Select-String '(https://.*?MFTECmd\.zip)').matches.value
    $EZpemcd = ($page | Select-String '(https://.*?PECmd\.zip)').matches.value
    $EZrbcmd = ($page | Select-String '(https://.*?/RBCmd\.zip)').matches.value
    $EZrfc = ($page | Select-String '(https://.*?RecentFileCacheParser\.zip)').matches.value
    $EZsbe = ($page | Select-String '(https://.*?SBECmd\.zip)').matches.value
    $EZwxt = ($page | Select-String '(https://.*?WxTCmd\.zip)').matches.value
    $EZrecmd = ($page | Select-String '(https://.*?RECmd\.zip)').matches.value
}
$tools = $EZamcache,$EZappcompat,$EZjlecmd,$EZlecmd,$EZmftcmd,$EZpemcd,$EZrbcmd,$EZrecmd,$EZrfc,$EZsbe,$EZwxt
$dest = $appCacheCmd,$appCompCmd,$jleCmd,$leCmd,$mft,$peCmd,$rbcmd,$recmd,$rfc,$sb,$wtxcmd
for($i=0;$i -lt 11;$i++) {
    $uri = $tools[$i]
    $outfile = ($dest[$i] -replace '.exe','.zip')
    Invoke-WebRequest -uri $uri -outfile $outfile -UseBasicParsing
    $destpath = $dest[$i].substring(0,$dest[$i].lastindexof('\')+1)
    Expand-Archive $outfile -DestinationPath $destpath -force
    Remove-Item $outfile
}
move-item ($recmddir + 'RECmd\*') $recmddir

#Get Nirsofer's Tools
write-host "Downloading Nirsofer's Tools" -ForegroundColor Yellow
write-host "This only gets the bare minimum - you should really get his entire suite of tools." -ForegroundColor Green

$nirsoftdir = $bhv.substring(0,$bhv.lastindexof('\')+1)
invoke-webrequest -Headers @{'Referer' = 'https://www.nirsoft.net/web_browser_tools.html'} -uri https://www.nirsoft.net/packages/brtools.zip -OutFile ($nirsoftdir + 'brtools.zip')
Expand-Archive -path ($nirsoftdir + 'brtools.zip') -DestinationPath $nirsoftdir -Force
invoke-webrequest -Headers @{'Referer' = 'https://www.nirsoft.net/utils/app_crash_view.html'} -uri https://www.nirsoft.net/utils/appcrashview.zip -OutFile ($nirsoftdir + 'appcrashview.zip')
Expand-Archive -path ($nirsoftdir + 'appcrashview.zip') -DestinationPath $nirsoftdir -Force
invoke-webrequest -Headers @{'Referer' = 'https://www.nirsoft.net/utils/chrome_cookies_view.html'} -uri https://www.nirsoft.net/utils/chromecookiesview.zip -OutFile ($nirsoftdir + 'chromecookiesview.zip')
Expand-Archive -path ($nirsoftdir + 'chromecookiesview.zip') -DestinationPath $nirsoftdir -Force
invoke-webrequest -Headers @{'Referer' = 'https://www.nirsoft.net/utils/edge_cookies_view.html'} -uri https://www.nirsoft.net/utils/edgecookiesview.zip -OutFile ($nirsoftdir + 'edgecookiesview.zip')
Expand-Archive -path ($nirsoftdir + 'edgecookiesview.zip') -DestinationPath $nirsoftdir -Force
Invoke-WebRequest -headers @{'Referer' = 'https://www.nirsoft.net/utils/ese_database_view.html'} -uri https://www.nirsoft.net/utils/esedatabaseview.zip -OutFile ($nirsoftdir + 'esedatabaseview.zip')
Expand-Archive -path ($nirsoftdir + 'esedatabaseview.zip') -DestinationPath $nirsoftdir -Force
Remove-Item ($nirsoftdir + '*.zip')

write-host "Downloading ese2csv.exe from https://github.com/MarkBaggett/ese-analyst" -ForegroundColor Yellow
invoke-webrequest -uri https://github.com/MarkBaggett/ese-analyst/raw/master/ese2csv.exe -OutFile $srum
invoke-webrequest -uri https://raw.githubusercontent.com/MarkBaggett/ese-analyst/master/srudb_plugin.py -OutFile ($srum + 'srudb_plugin.py')
invoke-webrequest -uri https://raw.githubusercontent.com/MarkBaggett/ese-analyst/master/spartan_plugin.py -OutFile ($srum + 'spartan_plugin.py')

write-host 'Finished. Run get-imageinfo.ps1 by mounting a forensic image. In PowerShell run as Administrator cd to directory where you want the information and' -ForegroundColor Cyan
write-host "PS> \imageinfo\get-imageinfo.ps1 <drive>" -ForegroundColor Gray
Write-Host "It will create a directory named after the host and start populating information." -ForegroundColor Cyan