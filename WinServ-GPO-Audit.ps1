########################################################################################
# Script: GetMsProductKeys.ps1
# Objective: Get Windows and Office Product Keys from all domain computers
# created from: Ruggiero Lauria
# on : 25/03/2014
#
# http://ruggierolauria.blogspot.com
#
# Thanks to:
# http://poshcode.org/4488
# http://gallery.technet.microsoft.com/scriptcenter/Backup-Windows-product-key-b41468c2
########################################################################################

# Start Functions definition

# Get Windows Product Key
function Get-WindowsProductKey
 {
   Param (
          [string[]]$Computername = $Env:Computername,
           $version
          )
         $hklm = 2147483650
        # Invoke the WMI RemoteRegistry access provider
        $wmi = [WMIClass] ("\\" + $Computername + "\root\default:StdRegProv")
        # Load DigitalProductId value
        $values = [byte[]]($wmi.getbinaryvalue($hklm,"SOFTWARE\Microsoft\Windows NT\CurrentVersion","DigitalProductId").uvalue)
        # Select the correct decode function based on Windows Version
        if ($version -lt "6.2")
         {
             $keyproductid = Get-Windows7ProductKey($values)
         }
        else
        {
              $keyproductid = Get-Windows8ProductKey($values)
        }
    $keyproductid

   }

#Decode Pre-Windows 8 Product Key
Function Get-Windows7ProductKey($Key)
 {
$lookup = [char[]]("B","C","D","F","G","H","J","K","M","P","Q","R","T","V","W","X","Y","2","3","4","6","7","8","9")
        $keyStartIndex = 0x34;
        $keyEndIndex = [int]($keyStartIndex + 15);
        $decodeLength = [int]29
        $decodeStringLength = [int]15
        $decodedChars = new-object char[] $decodeLength
        $hexPid = new-object System.Collections.ArrayList
       
       for ($i = $keyStartIndex; $i -le $keyEndIndex; $i++){ [void]$hexPid.Add($values[$i]) }
        for ( $i = $decodeLength - 1; $i -ge 0; $i--)
            {
             if (($i + 1) % 6 -eq 0){$decodedChars[$i] = '-'}
             else
               {
                $digitMapIndex = [int]0
                for ($j = $decodeStringLength - 1; $j -ge 0; $j--)
                {
                    $byteValue = [int](($digitMapIndex * [int]256) -bor [byte]$hexPid[$j]);
                    $hexPid[$j] = [byte] ([math]::Floor($byteValue / 24));
                    $digitMapIndex = $byteValue % 24;
                    $decodedChars[$i] = $lookup[$digitMapIndex];
                 }
                }
             }
  $keyproduct = ''
  $decodedChars | % { $keyproduct+=$_}
  $keyproduct
   }
# Decode Windows 8 Product Key
Function Get-Windows8ProductKey($Key)
{
    $Keyoffset = 52
    $isWin8 = [int]($Key[66]/6) -band 1
    $HF7 = 0xF7
    $Key[66] = ($Key[66] -band $HF7) -bOr (($isWin8 -band 2) * 4)
    $i = 24
    [String]$Chars = "BCDFGHJKMPQRTVWXY2346789"   
    do
    {
        $Cur = 0
        $X = 14
        Do
        {
            $Cur = $Cur * 256   
            $Cur = $Key[$X + $Keyoffset] + $Cur
            $Key[$X + $Keyoffset] = [math]::Floor([double]($Cur/24))
            $Cur = $Cur % 24
            $X = $X - 1
        }while($X -ge 0)
        $i = $i- 1
        $KeyOutput = $Chars.SubString($Cur,1) + $KeyOutput
        $last = $Cur
    }while($i -ge 0)
   
    $Keypart1 = $KeyOutput.SubString(1,$last)
    $Keypart2 = $KeyOutput.Substring(1,$KeyOutput.length-1)
    if($last -eq 0 )
    {
        $KeyOutput = "N" + $Keypart2
    }
    else
    {
        $KeyOutput = $Keypart2.Insert($Keypart2.IndexOf($Keypart1)+$Keypart1.length,"N")
    }
    $a = $KeyOutput.Substring(0,5)
    $b = $KeyOutput.substring(5,5)
    $c = $KeyOutput.substring(10,5)
    $d = $KeyOutput.substring(15,5)
    $e = $KeyOutput.substring(20,5)
    $keyproduct = $a + "-" + $b + "-"+ $c + "-"+ $d + "-"+ $e
    $keyproduct
}

   # Get Microsoft Office Product Key
    function Get-MSOfficeProductKey {
    Param(
          [string[]]$Computername = $Env:Computername
          )

    $product = @()
    $hklm = 2147483650
     
   # If DigitalProductId not found in hklm\SOFTWARE\Microsoft\Office\..
   # may be we have Office 32 Bit on 64 bit OS so the registry path becomes: SOFTWARE\Wow6432node\Microsoft\Office\..
 
    $path = @("SOFTWARE\Wow6432node\Microsoft\Office","SOFTWARE\Microsoft\Office")

    for ($p = 1; $p -ge 0; $p--) {
       # Invoke the WMI RemoteRegistry access provider
        $wmi = [WMIClass] ("\\" + $Computername + "\root\default:StdRegProv")
       #Navigate 3 levels down the registry tree  starting from actual $ path to find DigitalProductID
       # i.e.  HKLM\SOFTWARE\Microsoft\Office\11.0\Registration\{90120410-6000-11D3-8CFE-0150048383C9}
        $subkeys1 = $wmi.EnumKey($hklm,$path[$p])
        foreach ($subkey1 in $subkeys1.snames) {
            $subkeys2 = $wmi.EnumKey($hklm,$path[$p]+"\$subkey1")
            foreach ($subkey2 in $subkeys2.snames) {
                $subkeys3 = $wmi.EnumKey($hklm,$path[$p]+"\$subkey1\$subkey2")
                foreach ($subkey3 in $subkeys3.snames) {
                    $subkeys4 = $wmi.EnumValues($hklm,$path[$p]+"\$subkey1\$subkey2\$subkey3")
                    foreach ($subkey4 in $subkeys4.snames) {
                        #Looking for DigitalProductID key
                        if ($subkey4 -eq "DigitalProductId") {
                      
                           # Load DigitalProductId value         
                           $values = [byte[]]($wmi.getbinaryvalue($hklm,$path[$p]+"\$subkey1\$subkey2\$subkey3","DigitalProductId").uvalue)
                        
                           $p = -1 # Key found: exit from path loop
                            #Decode DigitalProductId
                           $keyproductid = Get-Windows7ProductKey($values)
                           $keyproductid
                        }
                    }
                }
            }
        }
    }
  }

# End Functions definition

# Start of Script body

# Define variables
$FilePath = "C:\scripts\ProductKey" # Change with your own path (must be created!) to store CSV output
$NewCSVObject = @()

# Write Columns headers: first output line

$NewCSVObject | Select  "ClientName","OSArchitecture", "Username" , "Manufacturer", "Model", "Dev SerialNumber" ,"Office Version","Office SN", "Caption", "Version", "RegisteredUser", "OS SerialNumber", "WindowsPK" | Format-Table -AutoSize

# Get the list of active computer in AD.

Import-Module ActiveDirectory
$arrComputers = Get-ADComputer -Filter {enabled -eq $true} -properties *|select name | sort name

#$arrComputers = Get-ADComputer -Filter {enabled -eq $true} -properties *|Where {$_.name -like "nb-ac*"} |select name | sort name

# Computers Loop
foreach ($strComputer in $arrComputers)
{
 Write-Host $strComputer.name
 #Try to connect to the computer
 If (Test-Connection -ComputerName $strComputer.name -Count 1 -Quiet) {

  try {
    #Inizialize a new row
    $objInfo = New-Object PSObject | Select  "ClientName", "OSArchitecture", "Username" ,"Manufacturer", "Model", "DevSerialNumber" ,"OfficeVersion", "OfficeSN", "Caption", "Version","RegisteredUser", "OSSerialNumber", "WindowsPK"

    # Get currently logged in username, client name, manufacturer and model from Win32_ComputerSystem class.
    $colItems = Get-WmiObject Win32_ComputerSystem -Namespace "root\CIMV2" -ErrorAction stop -ComputerName $strComputer.name

    foreach($objItem in $colItems) {
     $objInfo.Username= $objItem.UserName
     $objInfo.ClientName = $objItem.Name
     $objInfo.Manufacturer = $objItem.Manufacturer
     $objInfo.Model = $objItem.Model
     }


    # Get workstation serial number from Win32_BIOS class.
    $colItems = Get-WmiObject Win32_BIOS -Namespace "root\CIMV2" -ErrorAction stop -ComputerName $strComputer.name

    foreach($objItem in $colItems) {
    $objInfo.DevSerialNumber = $objItem.SerialNumber
     }

    #Get OS Info from Win32_OperatingSystem
    $colItems = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop  -ComputerName $strComputer.name
    foreach($objItem in $colItems) {
    if ($objItem.OSArchitecture) {$objInfo.OSArchitecture = $objItem.OSArchitecture} else { $objInfo.OSArchitecture ="32 bit" }
    $objInfo.Caption  = $objItem.Caption
    $objInfo.Version = $objItem.Version
    $objInfo.RegisteredUser= $objItem.RegisteredUser
    $objInfo.OsSerialNumber= $objItem.SerialNumber
      }  
   
    #Get MS Windows Serial Number
    #write-host $objInfo.Version
    $objInfo.WindowsPK = Get-WindowsProductKey -Computername $strComputer.name -Version $objInfo.Version

    #Get Office Version from WIn32_Product
    $colItems = Get-WmiObject WIn32_Product -Computername $strComputer.name -Filter "Name like '%Office%'"| Where {($_.ProductID) }
    foreach($objItem in $colItems) {
    $objInfo.OfficeVersion = $objItem.Name
     }
    if ($objInfo.OfficeVersion) {
   
    #Get Office Serial Number
    $objInfo.OfficeSN = Get-MSOfficeProductKey  -Computername $strComputer.name
     }
    else {
    $objInfo.OfficeVersion = "Office not installed"
    }
  }
  catch # If we get any error Reading computer data let's say it is Unreadable
  {
    $objInfo = New-Object PSObject | Select  "ClientName", "OSArchitecture", "Username" ,"Manufacturer", "Model", "DevSerialNumber" ,"OfficeVersion", "OfficeSN", "Caption", "Version","RegisteredUser", "OSSerialNumber", "WindowsPK" 
    $objInfo.ClientName = $strComputer.name
    $objInfo.OSArchitecture = 'Unreadable'
   }
 }
# If we are unable to connect let's say the computer is Unreachable
else
    {
    $objInfo = New-Object PSObject | Select  "ClientName", "OSArchitecture", "Username" ,"Manufacturer", "Model", "DevSerialNumber" ,"OfficeVersion", "OfficeSN", "Caption", "Version","RegisteredUser", "OSSerialNumber", "WindowsPK"
        $objInfo.ClientName = $strComputer.name
        $objInfo.OSArchitecture = 'Unreachable'
     }
# Add a new Row with current computer data
$NewCSVObject += $objInfo
$objInfo=""

}

# OutPut to CSV file
# If you want a video output too uncomment line below
$NewCSVObject |Out-GridView
$NewCSVObject | export-csv "$FilePath\ListPK_$(Get-Date -f yyyy-MM-dd).csv" -noType

# End of Script body
###################################################################
