# active directory
Required files:
1. .\modules\vm-deployment.psm1 # as it contains some functions used in the script
2. create-gpo-ntp.ps1 # creates a GPO for time servers to PDC and non-PDC
3. install-first-addc.ps1 # deploys the first DC including DNS and DHCP