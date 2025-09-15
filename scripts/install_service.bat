::
:: File:	install_service.bat
:: Created on:	2025 Sep 15
:: Autor:	Davit Kalantaryan (davit.kalantaryan@desy.de)
:: Notice:	Example how to create service
::

@echo off

setlocal EnableDelayedExpansion enableextensions

set  scriptDirectory=%~dp0
set  currentDirectory=%cd%
cd /D "%scriptDirectory%.."

sc create ssh_port_redirect_service binPath= "C:\FocusT\ssh_port_redirect_service\windows_ssh_service.exe" start= auto

:: create config.conf file in the executable directory


endlocal