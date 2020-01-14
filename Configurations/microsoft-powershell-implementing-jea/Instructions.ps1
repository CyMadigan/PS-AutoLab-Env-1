[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $Unattend

   ,[Parameter()]
    [switch]
    $Wipe
)
[void](Get-Module -Name *Lab* <#| Where-Object { $_.Name -NotMatch '^(AutomatedLab.*)$'; } #>|Remove-Module -Force);
Import-Module -Name PSAutoLab -Force;

$originalLocation=(Get-Location).Path;
try {
    Set-Location -Path "$($PSScriptRoot)";

    # To run the full lab setup, which includes Setup-Lab, Run-Lab, Enable-Internet, and Validate-Lab:
    if (!$Wipe -and ($Unattend -or ($PSBoundParameters["Unattend"] -and $Unattend))) {
        Unattend-Lab
    } elseif (!$Wipe) {
        # To run the commands individually to setup the lab environment:

        # Run the following for initial setup:
        Setup-Lab

        <#
        # When this task is complete, run:
        Run-Lab

        # To enable Internet access for the VM's, run:
        Enable-Internet

        # Run the following to validate when configurations have converged:
        Validate-Lab

        # To stop the lab VM's:
        Shutdown-lab

        # When the configurations have finished, you can checkpoint the VM's with:
        Snapshot-Lab

        # To quickly rebuild the labs from the checkpoint, run:
        Refresh-Lab
        #>
    }

    # To destroy the lab to build again:
    if ($Wipe -or ($PSBoundParameters["Wipe"] -and $Wipe)) {
        Wipe-Lab
    }
} finally {
    Set-Location -Path "$($originalLocation)";
}
