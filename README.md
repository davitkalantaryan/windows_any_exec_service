# windows any exec as service
Service that willl run any executable from config file. Config file signature will be provided.   
One can provide service name, initialization procedure as well uninstall cleanup.  
Some variables also can be used during config creation


Any executable can be used to run as a service.   
You have to copy this executable to your windows machine to desired directory .  
Then you can install the service with the simple double click of the executable.  
To uninstall again double click and executable will check that service is installedand exe will uninstall it.  
  
    
# Config file example  
  
  
```config.conf  
# 
# those are examples of single line comment
# command below will be executed by script

// this is another example of single line comment
// ssh -i C:\FocusT\ssh_port_redirect_service\id_rsa_dev001 -R *:11389:localhost:3389 kalantar@dev001.focust.io -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -N -o "ExitOnForwardFailure yes" -o "ServerAliveInterval 60"

/*
    Below is example of multiline comment
    
    Current implementation provides following arguments
    1. ${serviceDir}  -> directory where this file and service executable located
    2. ${serviceFilePath} -> Path to the service executable
    3. ${serviceFileName} -> name of the executable of the service with extension (example 'windows_any_exec_service.exe')

    Service needs following parameters to execute 
    1. name -> name of the service
    2. exec -> command to execute
    3. init -> will be executed before first start of Service
    4. clean will be executed after service uninstalled

    The variables can be embedded to "". In between one can have multiple double quotes, so the last one in the line will terminate the string.
*/

name="ssh_port_redirect_service08"
exec="plink.exe -i "${serviceDir}\id_rsa_dev001.ppk" -R *:11389:localhost:3389 kalantar@dev001.focust.io -N -batch -no-antispoof -ssh"
#exec="ssh -i "${serviceDir}\id_rsa_dev001" -R *:11389:localhost:3389 kalantar@dev001.focust.io -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -N -o "ExitOnForwardFailure yes" -o "ServerAliveInterval 60""
#init="cmd.exe /C "cd /D "${serviceDir}" && icacls id_rsa_dev001 /inheritance:r && icacls id_rsa_dev001 /reset && icacls id_rsa_dev001 /grant:r SYSTEM:F""
#clean="cmd.exe /C "cd /D "${serviceDir}" && echo "Service is going to be deleted"""
```