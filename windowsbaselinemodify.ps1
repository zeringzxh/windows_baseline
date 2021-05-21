Function Parse-SecPol($CfgFile){ 
    secedit /export /cfg "$CfgFile" | out-null
    $obj = New-Object psobject
    $index = 0
    $contents = Get-Content $CfgFile -raw
    [regex]::Matches($contents,"(?<=\[)(.*)(?=\])") | %{
        $title = $_
        [regex]::Matches($contents,"(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{
            $section = new-object psobject
            $_.value -split "\r\n" | ?{$_.length -gt 0} | %{
                $value = [regex]::Match($_,"(?<=\=).*").value
                $name = [regex]::Match($_,".*(?=\=)").value
                $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
            }
            $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
        }
        $index += 1
    }
    return $obj
}
Function Set-SecPol($Object, $CfgFile){
   $SecPool.psobject.Properties.GetEnumerator() | %{
        "[$($_.Name)]"
        $_.Value | %{
            $_.psobject.Properties.GetEnumerator() | %{
                "$($_.Name)=$($_.Value)"
            }
        }
    } | out-file $CfgFile -ErrorAction Stop
    secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile"
}
$SecPool = Parse-SecPol -CfgFile C:\Test.cgf
#组策略
$SecPool.'System Access'.NewAdministratorName = "admlntest"
$SecPool.'System Access'.EnableGuestAccount = 0
$SecPool.'System Access'.NewGuestName = -join((48..57 + 65..90 + 97..122) | get-random -count 6 | %{[char]$_}) + "guest"
$SecPool.'System Access'.PasswordComplexity = 1
$SecPool.'System Access'.MinimumPasswordLength = 8
$SecPool.'System Access'.MaximumPasswordAge = 90
$SecPool.'System Access'.PasswordHistorySize = 5
$SecPool.'System Access'.LockoutBadCount = 5
$SecPool.'System Access'.ResetLockoutCount = 30
$SecPool.'System Access'.LockoutDuration = 30
#审核策略
$SecPool.'Event Audit'.AuditSystemEvents = 3
$SecPool.'Event Audit'.AuditLogonEvents = 3
$SecPool.'Event Audit'.AuditObjectAccess = 3
$SecPool.'Event Audit'.AuditProcessTracking = 2
$SecPool.'Event Audit'.AuditDSAccess = 3
$SecPool.'Event Audit'.AuditPrivilegeUse = 3
$SecPool.'Event Audit'.AuditSystemEvents = 3
$SecPool.'Event Audit'.AuditAccountLogon = 3
$SecPool.'Event Audit'.AuditAccountManage = 3
#操作系统本地关机策略
$SecPool.'Privilege Rights'.SeShutdownPrivilege = "*S-1-5-32-544"
#操作系统远程关机策略安全
$SecPool.'Privilege Rights'.SeRemoteShutdownPrivilege = "*S-1-5-32-544"
#取得文件或其他对象的所有权限策略
$SecPool.'Privilege Rights'.SeProfileSingleProcessPrivilege = "*S-1-5-32-544"
#从本地登录此计算机策略
$SecPool.'Privilege Rights'.SeInteractiveLogonRight = "*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551"
#从网络访问次计算机
#$SecPool.'Privilege Rights'.SeNetworkLogonRight = "*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551"
#暂停会话前所需的空闲时间
$SecPool.'Registry Values'.'MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\AutoDisconnect' = "4,15" 
Set-SecPol -Object $SecPool -CfgFile C:\Test.cfg
rm -force C:\Test.cgf -confirm:$false
rm -force C:\Test.cfg -confirm:$false

#日志大小
#Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application" -name "MaxSize" -value 20971520
#Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System" -name "MaxSize" -value 20971520
#Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -name "MaxSize" -value 20971520
#关闭默认共享
#Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" -name "AutoShareServer" -value 0
#禁止全部驱动器自动播放
Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -name "NoDriveTypeAutoRun" -value 255
#屏幕保护程序
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Desktop" -name "ScreenSaveTimeOut" -value 300
Set-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Control Panel\Desktop" -name "ScreenSaverIsSecure" -value 1