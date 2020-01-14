#The is almost the same like '07 Standalone Root CA, Sub Ca domain joined.ps1' but this adds a web server and requests
#a web sever certificate for SSL. This certificate is then used for the SSL binding.
#This intro script is extending '03 Single domain-joined server.ps1'. Two additional ISOs are added to the lab which are required to install
#Visual Studio 2015 and SQL Server 2014. After the lab is installed, AutomatedLab installs Redgate Relector on the LDT-DEV-Cli01.
[void](Get-Module -Name *Lab* <#| Where-Object { $_.Name -NotMatch '^(AutomatedLab.*)$'; } #>|Remove-Module -Force);
Import-Module -Name AutomatedLab -Force;

if (!([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Verbose -Message ('Must execute using elevated permissions') -Verbose;
    exit
}

$vmDrive = 'E:' #this is the drive where to create the VMs
$labName = 'EvolveLab' #the name of the lab, VM folder and network Switch

#create the folder path for the lab using Join-Path
$labPath = Join-Path -Path (Join-Path -Path $vmDrive -ChildPath '__REMOVE_LAB__') -ChildPath $labName;

$BaseVHDPath="E:\__Lab__\_HyperV\Virtual Hard Disks\";

# (Get-ChildItem -Path E:\LabSources\ISOs).Where({ $_.Fullname -notin ((Get-LabIsoImageDefinition).Path)  +((Get-ChildItem -Path E:\LabSources\ISOs -Include *.zip,*.exe,*.md,*.checksum -Recurse).FullName)  }).ForEach({ $_.FullName  })

#create the target directory if it does not exist
if (-not (Test-Path $labPath)) { New-Item $labPath -ItemType Directory | Out-Null }

$labDefinition=@{
    Name="$($labName)";
    DefaultVirtualizationEngine="HyperV";
    Path="$($labPath)";
    VMPath="$($labPath)";
};
New-LabDefinition @labDefinition;

$Secure = ConvertTo-SecureString -String 'P@$$w0rd' -AsPlainText -Force
$credential = New-Object -typename Pscredential -ArgumentList Administrator, $secure
Set-LabInstallationCredential -Username $credential.UserName -Password $credential.GetNetworkCredential().Password -Verbose;

# Add-LabIsoImageDefinition -Name SQLServer2014 -Path $labSources\ISOs\en_sql_server_2014_standard_edition_with_service_pack_2_x64_dvd_8961564.iso
# Add-LabIsoImageDefinition -Name VisualStudio2015 -Path $labSources\ISOs\en_visual_studio_enterprise_2015_with_update_3_x86_x64_dvd_8923288.iso

Add-LabVirtualNetworkDefinition -Name $labDefinition.Name;
Add-LabVirtualNetworkDefinition -Name 'Default Switch' -HyperVProperties @{ SwitchType = 'External'; AdapterName = 'Wi-Fi' }

#defining default parameter values, as these ones are the same for all the machines
$PSDefaultParameterValues = @{
    'Add-LabMachineDefinition:DomainName' = 'contoso.com'
    'Add-LabMachineDefinition:Memory' = 1GB
    'Add-LabMachineDefinition:OperatingSystem' = 'Windows Server 2016 Datacenter Evaluation (Desktop Experience)'
    'Add-LabMachineDefinition:Network' = "$($labDefinition.Name)"
}

$netAdapter = @()
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch $labDefinition.Name
$netAdapter += New-LabNetworkAdapterDefinition -VirtualSwitch 'Default Switch' -UseDhcp

Add-LabMachineDefinition -Name LDT-EVL-AD001 -Roles RootDC -NetworkAdapter $netAdapter
Add-LabMachineDefinition -Name LDT-EVL-CA001 -Roles CaRoot
Add-LabMachineDefinition -Name LDT-EVL-Web01 -Roles WebServer
#Add-LabMachineDefinition -Name LDT-EVL-Cli01 -OperatingSystem 'Windows 10 Pro'

#([adsi]'LDAP://RootDSE').ConfigurationNamingContext

# $roles = @(
#     Get-LabMachineRoleDefinition -Role SQLServer2014 -Properties @{InstallSampleDatabase = 'true'}
#     Get-LabMachineRoleDefinition -Role Routing
# )
# Add-LabMachineDefinition -Name LDT-EVL-SQL01 -Roles $roles
# Add-LabMachineDefinition -Name LDT-DEV-Cli01 -OperatingSystem 'Windows 10 Enterprise Evaluation' -Roles VisualStudio2015

# Add BaseImages to the environment
<#
Get-ChildItem -path E:\ -file -recurse -force |  foreach-object {
    if ((fsutil hardlink list $_.fullname).count -ge 2) {
        $_.PSChildname + ":Hardlinked:" + $_.Length
    } else {
        $_.PSChildname + ":RegularFile:" + $_.Length
    }
}
#>
if ((Test-Path -Path (Get-Content -Raw -Path ((Get-LabDefinition).MachineDefinitionFiles).Path))) {
    [xml]$def=(Get-Content -Raw -Path ((Get-LabDefinition).MachineDefinitionFiles).Path);
    $oses=$def.ListXmlStoreOfMachine.Machine.OperatingSystem;
    $oses|Select-Object OperatingSystemName,Version -Unique|ForEach-Object {
        $_ | Add-Member -MemberType ScriptProperty -Name VHDName -Value {
            "BASE_$($this.OperatingSystemName.Replace(' ',''))_$([Version]::new($this.Version.Major,$this.Version.Minor,$this.Version.Build,$this.Version.Revision)).vhdx";
        } -PassThru | Add-Member -MemberType ScriptProperty -Name SourceVHDName -Value {
            Join-Path -Path $BaseVHDPath -ChildPath "BASE_$($this.OperatingSystemName.Replace(' ',''))_$([Version]::new($this.Version.Major,$this.Version.Minor,$this.Version.Build,$this.Version.Revision)).vhdx";
        } -PassThru;

        $ShouldAddSympolicLink=&{
            $vhdPath=(Join-Path -Path "$($labDefinition.Path)" -ChildPath "$($_.VHDName)");
            if ((Test-Path -Path "$($vhdPath)") -and !(Get-Item -Path "$($vhdPath)" -ErrorAction SilentlyContinue).LinkType) {
                Move-Item -Path "$($vhdPath)" -Destination (Split-Path -Path "$($_.SourceVHDName)" -Parent);
            };

            return !(Test-Path -Path "$($vhdPath)") -and (Test-Path -Path "$($_.SourceVHDName)");
        };

        <#
        +-----------------------+-----------------------------------------------------------+
        | mklink syntax         | Powershell equivalent                                     |
        +-----------------------+-----------------------------------------------------------+
        | mklink Link Target    | New-Item -ItemType SymbolicLink -Name Link -Target Target |
        | mklink /D Link Target | New-Item -ItemType SymbolicLink -Name Link -Target Target |
        | mklink /H Link Target | New-Item -ItemType HardLink -Name Link -Target Target     |
        | mklink /J Link Target | New-Item -ItemType Junction -Name Link -Target Target     |
        +-----------------------+-----------------------------------------------------------+
        #>
        if ($ShouldAddSympolicLink) {
            [void](New-Item -ItemType symboliclink -Path $labDefinition.Path -Name "$($_.VHDName)" -Value "$($_.SourceVHDName)" -ErrorAction SilentlyContinue);
        }
    }
};

Install-Lab

Enable-LabCertificateAutoenrollment -Computer -User -CodeSigning

$cert = Request-LabCertificate -Subject CN=LDT-EVL-Web01.contoso.com -TemplateName WebServer -ComputerName LDT-EVL-Web01 -PassThru

Invoke-LabCommand -ActivityName 'Setup SSL Binding' -ComputerName LDT-EVL-Web01 -ScriptBlock {
    New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https
    Import-Module -Name WebAdministration
    Get-Item -Path "Cert:\LocalMachine\My\$($args[0].Thumbprint)" | New-Item -Path IIS:\SslBindings\0.0.0.0!443
} -ArgumentList $cert

# Install-LabSoftwarePackage -Path $labSources\SoftwarePackages\ReflectorInstaller.exe -CommandLine '/qn /IAgreeToTheEula' -ComputerName LDT-DEV-Cli01

Show-LabDeploymentSummary -Detailed

<#
$vmDrive = 'E:' #this is the drive where to create the VMs
$labName = 'EvolveLab' #the name of the lab, VM folder and network Switch

#create the folder path for the lab using Join-Path
$labPath = Join-Path -Path (Join-Path -Path $vmDrive -ChildPath '__REMOVE_LAB__') -ChildPath $labName;

if ((Test-Path -Path (Join-Path -Path $labPath -ChildPath 'Lab.xml'))) {
    # AutomatedLab\Remove-Lab -Name 'LabDev2'
    # AutomatedLab\Import-Lab -Name $labName;
    AutomatedLab\Remove-Lab -Path "$($labPath)" -Confirm:$false
}
#>
