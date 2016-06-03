Param($rango="172.17.1.11")
Clear-Host

Function validar-ip ($ip){
    Write-Output $ip
    $ipObj=[System.net.IPAddress]::parse($ip)
    return($isvalid=[System.Net.IPAddress]::TryParse([string]$ip,[ref]$ipObj))
    
}

############################################################################
############# Recibe las consultas WMI y escribe los vales en BD ###########
############################################################################
Function gestiona_datos ($sysinfoItems, $procesadores, $perfmem, $operatingsystem, $discosio, $fichero_log){


 Write-Output "Gestionando los datos..."
 Write-Output "Gestionando Datos" >> $fichero_log

#write-host 1
#write-host $sysinfoItems
#write-host 2
#write-host $procesadores
#write-host 3
#write-host $perfmem
#write-host 4
#write-host $operatingsystem
#write-host 5


 $ServicePoint=[System.Net.ServicePointManager]::FindServicePoint("http://172.17.100.180:8086/write?db=EFE")
 $ServicePoint.ConnectionLimit=10
 $ServicePoint.CloseConnectionGroup("")

$influxdbserver = "D:\PWSH\serverstoinflux\influxdbserver.txt"
$dbserver=Get-Content $influxdbserver

$influxdbBD = "D:\PWSH\serverstoinflux\influxdbBD.txt"
$BD=Get-Content $influxdbBD

#write-host $dbserver
#write-host $BD
 
     

$memoriatotal=0
$memoriatotal=$sysinfoItems.TotalPhysicalMemory/1024/1024
$memoriatotal=[math]::Round($memoriatotal,2)


#$operatingsystem = Get-WmiObject Win32_OperatingSystem -Namespace root\CIMV2 -ComputerName $fip # -ErrorAction SilentlyContinue
#$memorialibre=$operatingsystem.FreePhysicalMemory
#$memoriatotal=$operatingsystem.TotalVisibleMemorySize

$memorialibre=0
write-host " INICIO"
write-host  $perfmem
write-host " FIN"
if ($perfmem -ne $null){

$memorialibre=$perfmem.AvailableBytes/1024/1024
$memorialibre=[math]::Round($memorialibre,2)
}
else{
write-host "es null"
$memorialibre=$operatingsystem.FreePhysicalMemory/1024#/1024
$memorialibre=[math]::Round($memorialibre,2)
}

#$procesos = Get-WmiObject Win32_Process -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue

#$totalworkingsetsize=0
#foreach ($proceso in $procesos){
#$totalworkingsetsize=$totalworkingsetsize+$proceso.workingsetsize
#write-host $proceso.caption $proceso.workingsetsize
#}
#Write-Host "workingsetsize" $totalworkingsetsize
#$memoriaconsumida=$totalworkingsetsize


#$memorialibre=$memoriatotal-$memoriaconsumida

$memoriaconsumida=$memoriatotal-$memorialibre


write-host  "memoria total" $memoriatotal
Write-Host "memoria consumida" $memoriaconsumida
Write-Host "memoria libre" $memorialibre
		
$authheader = "Basic " + ([Convert]::ToBase64String([System.Text.encoding]::ASCII.GetBytes("root:root")))
$uri = 'http://172.17.100.180:8086/write?db=EFE'
#$uri = 'http://'+$dbserver+':8086/write?db='+$BD

#$Metricsmem = "Uso_Memoria,maquina=$fip"+",TotalMem=$memoriatotal"+",FreeMem=$memorialibre"+" value=$memoriaconsumida" #la "i" le indica que es un entero
$Metricsmem = "Uso_Memoria,maquina=$fip"+" value=$memoriaconsumida" #la "i" le indica que es un entero
   
  Write-host "invoke memoria"
  Invoke-RestMethod -Headers @{Authorization=$authheader} -Uri $uri -Method POST -Body $Metricsmem
  $ServicePoint.CloseConnectionGroup("")
  Write-host "Fin invoke memoria"

foreach ($procesador in $procesadores){
    #Write-Host $procesadores
    #Write-Host $procesador.description
    $proc=$procesador.LoadPercentage
    #if ($proc -eq $null){
    #Write-Host "proc null"
    
    #}
   
    
   # write-host $procesador |fl *

    $id=$procesador.DeviceID
    Write-Host "el valor del procesador es: " $proc      
    $Metricscpu = "Uso_CPU,maquina=$fip"+",CPU=$id"+" value=$proc" #la "i" le indica que es un entero
    if ($proc -eq "null"){
    write-host "valor nulo" $proc    
    }
     Write-host "invoke CPU"
     Invoke-RestMethod -Headers @{Authorization=$authheader} -Uri $uri -Method POST -Body $Metricscpu
     $ServicePoint.CloseConnectionGroup("")
     Write-host "Fin invoke CPU"
}



<#
Write-host "empiezo discos"

foreach ($discoio in $discosio){
    write-host $discoio
    $averageio=$discoio.AvgDiskQueueLength
    if ($averageio -ne 0){  
        Write-Host "no es 0"      
        $nombreio=$discoio.name
        write-host $nombreio
        write-host $averageio
        $Metricsdiscoio = "Uso_Disco,maquina=$fip"+",disco=$nombreio"+" value=$averageio"
         Write-host "invoke DISCO"
       # Invoke-RestMethod -Headers @{Authorization=$authheader} -Uri $uri -Method POST -Body $Metricsdiscoio
       #$ServicePoint.CloseConnectionGroup("")
       Write-host "Fin invoke DISCO"
    }
    else{
    write-host "ES 0"
    }


}

Write-host "acabo discos"
#>


}

############################################################################
##### Recibe la ip de la maquina y realiza las consultas sin credencial ####
############################################################################

Function recojo_datos_sin_credencial ($fip,$fichero_log){
            
            Write-Output "Recogiendo datos..."
            Write-Output "Recogiendo Datos..." >>$fichero_log
           
 <#          
                        $sysinfoItems = Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue		
		                $sysoperativoItems = Get-WmiObject Win32_OperatingSystem -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue				
		                $systemenclosures= Get-WmiObject Win32_SystemEnclosure -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue
                        Write-Output "Recogiendo datos 1"	
		                #$PhysicalMemorys= Get-WmiObject Win32_PhysicalMemory -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue            
                        $configuracionred= Get-WmiObject Win32_networkadapterconfiguration -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue
                        $configred= Get-WmiObject Win32_networkadapter -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue
                        $rutas=Get-WmiObject Win32_IP4PersistedRouteTable -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue
                        Write-Output "Recogiendo datos 2"	
                        #$antivir=Get-WmiObject -Namespace "root\SecurityCenter" -ComputerName  $fip -Query "SELECT * FROM AntiVirusProduct" -ErrorAction SilentlyContinue            	
		                $licencias=Get-WmiObject softwarelicensingproduct -Namespace root\CIMV2 -ComputerName $fip  -ErrorAction SilentlyContinue                        
                        $vm=Get-WmiObject msvm_computersystem -Namespace root\virtualization -ComputerName $fip -ErrorAction SilentlyContinue                        
                        $vm2=Get-WmiObject msvm_computersystem -Namespace root\virtualization\v2 -ComputerName $fip -ErrorAction SilentlyContinue
                        Write-Output "Recogiendo datos 3"	
                        $reg = Get-WmiObject -List -Namespace root\default -ComputerName $fip | Where-Object {$_.Name -eq "StdRegProv"}
                        $licenc=Get-WmiObject Win32_WindowsProductActivation -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue
                       # $remoteReg = Get-WmiObject -List -Namespace root\default -ComputerName $fip | Where-Object {$_.Name -eq "StdRegProv"}
                       Write-Output "Recogiendo datos 4"	

 #>

    $procesadores = Get-WmiObject Win32_Processor -Namespace root\CIMV2 -ComputerName $fip # -ErrorAction SilentlyContinue

    $sysinfoItems = Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip # -ErrorAction SilentlyContinue

    #$operatingsystem = Get-WmiObject Win32_OperatingSystem -Namespace root\CIMV2 -ComputerName $fip # -ErrorAction SilentlyContinue
    try{
    $perfmem = Get-WmiObject Win32_PerfFormattedData_PerfOS_Memory -ComputerName $fip -AsJob |Wait-Job -Timeout 5 |Receive-Job # -ErrorAction SilentlyContinue
      
    $operatingsystem = Get-WmiObject Win32_OperatingSystem -Namespace root\CIMV2 -ComputerName $fip # -ErrorAction SilentlyContinue    

    $discosio=Get-WmiObject Win32_Perfformatteddata_perfdisk_physicaldisk -Namespace root\CIMV2 -ComputerName $fip  -AsJob |Wait-Job -Timeout 5 |Receive-Job# -ErrorAction SilentlyContinue            

    #Win32_PerfFormattedData_Tcpip_NetworkInterface
    }
    catch{
     write-host "fallo con el fer"
    }
    #$procesos = Get-WmiObject Win32_Process -Namespace root\CIMV2 -ComputerName $fip -ErrorAction SilentlyContinue


gestiona_datos $sysinfoItems $procesadores $perfmem $discosio $fichero_log


}

############################################################################
##### Recibe la ip de la maquina y realiza las consultas con credencial ####
############################################################################
Function recojo_datos_con_credencial ($fip, $cred,$fichero_log){

            #$sesionDCOM=New-CimSessionOption -Protocol DCOM
            #$sesion=New-CimSession -SessionOption $sesionDCOM -ComputerName $fip -Credential $cred


            Write-Output "Recogiendo datos..."
            Write-Output "Recogiendo Datos..." >> $fichero_log 
         
                               
                                #$sysinfoItems=Get-CimInstance Win32_ComputerSystem -CimSession $sesion
                                #$sysoperativoItems = Get-CimInstance Win32_OperatingSystem -CimSession $sesion
                                #$systemenclosures= Get-CimInstance Win32_SystemEnclosure -CimSession $sesion
                                #$configuracionred= Get-CimInstance Win32_networkadapterconfiguration -CimSession $sesion
                                #$configred= Get-CimInstance Win32_networkadapter -CimSession $sesion
                                #$rutas=Get-CimInstance Win32_IP4PersistedRouteTable -CimSession $sesion
                                #$licencias=Get-CimInstance softwarelicensingproduct -CimSession $sesion
                                #$licenc=Get-CimInstance Win32_WindowsProductActivation -CimSession $sesion
                                #$vm=Get-CimInstance msvm_computersystem -Namespace root\virtualization -CimSession $sesion
                                #$vm2=Get-CimAssociatedInstance msvm_computersystem -Namespace root\virtualization\v2 -CimSession $sesion
   <#
                                $sysinfoItems = Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue		                                
		                        $sysoperativoItems = Get-WmiObject Win32_OperatingSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue				
		                        $systemenclosures= Get-WmiObject Win32_SystemEnclosure -Namespace root\CIMV2 -ComputerName $fip -Credential $cred	-ErrorAction SilentlyContinue			                                           
                                Write-Output "Recogiendo datos...1"
                                $configuracionred= Get-WmiObject Win32_networkadapterconfiguration -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue
                                $configred= Get-WmiObject Win32_networkadapter -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue
                                $rutas=Get-WmiObject Win32_IP4PersistedRouteTable -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue                                        
                                Write-Output "Recogiendo datos...2"                                
                                if ($fip -ne "172.28.108.13"){
                                    $licenc=Get-WmiObject Win32_WindowsProductActivation -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue
                                }                                
                                $licencias=Get-WmiObject softwarelicensingproduct -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue                                
		                        $vm=Get-WmiObject msvm_computersystem -Namespace root\virtualization -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue
                                Write-Output "Recogiendo datos...3"
                                $vm2=Get-WmiObject msvm_computersystem -Namespace root\virtualization\v2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue                                
                                $reg = Get-WmiObject -List -Namespace root\default -ComputerName $fip -Credential $cred| Where-Object {$_.Name -eq "StdRegProv"}                                
                                 Write-Output "Recogiendo datos...4"

                                #####$PhysicalMemorys= Get-WmiObject Win32_PhysicalMemory -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue            
                                #####$antivir=Get-WmiObject -Namespace "root\SecurityCenter" -ComputerName  $fip -Query "SELECT * FROM AntiVirusProduct" -Credential $cred -ErrorAction SilentlyContinue
   #>
   write-host "processor"
    $procesadores = Get-WmiObject Win32_Processor -Namespace root\CIMV2 -ComputerName $fip -Credential $cred # -ErrorAction SilentlyContinue

    write-host "computersystem"
    $sysinfoItems = Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $cred # -ErrorAction SilentlyContinue

    #$operatingsystem = Get-WmiObject Win32_OperatingSystem -Namespace root\CIMV2 -ComputerName $fip # -ErrorAction SilentlyContinue
    write-host "memory"

    try{
    
    $perfmem = Get-WmiObject Win32_PerfFormattedData_PerfOS_Memory -ComputerName $fip -Credential $cred -AsJob |Wait-Job -Timeout 5 |Receive-Job # -ErrorAction SilentlyContinue
    #$perfCPU = Get-WmiObject Win32_PerfFormattedData_PerfProc_Process -ComputerName $fip -Credential $cred -AsJob |Wait-Job -Timeout 10 |Receive-Job # -ErrorAction SilentlyContinue
    #Write-Host $perfCPU
      #  if ($perfCPU -eq $null){
       #     Write-Host NULO
       #     Write-Host $perfmem
       #     write-host $perfCPU
        
        #}
      #Write-Host Get-Job
      
    $operatingsystem = Get-WmiObject Win32_OperatingSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $cred # -ErrorAction SilentlyContinue    
    
    $discosio=Get-WmiObject Win32_Perfformatteddata_perfdisk_physicaldisk -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -AsJob |Wait-Job -Timeout 5 |Receive-Job # -ErrorAction SilentlyContinue            
   

    }
    catch{
     write-host "fallo con el fer"
    }
    #$procesos = Get-WmiObject Win32_Process -Namespace root\CIMV2 -ComputerName $fip -Credential $cred -ErrorAction SilentlyContinue


gestiona_datos $sysinfoItems $procesadores $perfmem $operatingsystem $discosio $fichero_log
                             
                                     

}

Function SysInfo ($fip, $fcredencialwmi1, $fcredencialwmi2, $fcredencialwmi3, $fcredencialwmi5, $fcredencialwmi6, $fcredencialWMI7, $fcredencialWMI8, $fcredencialWMI9, $fcredencialilo, $fnumero, $fichero_log) {    
    
    $opera=$null
	$error=$false	
	$respuestawmi=@()
    $respuestavmware=@()
    $ping="KO"
    $dns="KO"



#### PRUEBO SI CONTESTA AL PING APROVECHANDO EL RESULTADO PARA SABER EL TIPO DE OPERATIVO #########
Write-Output "Probando ping" >>$fichero_log
         if (Test-Connection $fip -count 1){
         $ping="OK"         
	         $respuesta_al_ping=Test-Connection $fip  -Count 1 
             if ($respuesta_al_ping -ne $null){  # solo lo que responda al ping QUITAR!!!!
                                   
                    Switch($respuesta_al_ping.ResponseTimeToLive){
                        {$_ -le 64} {$opera="Linux"; break}
                        {$_ -le 128} {$opera="Windows"; break}
                        {$_ -le 255} {$opera="UNIX"; break}
                    }
             }
             else{
                Write-Output "Contesta al ping pero no me da el objeto del ping"
                Write-Output "Contesta al ping pero no me da el objeto del ping" >>$fichero_log
                 
             }
        }
        else{
            Write-Output "No contesta al ping"
            Write-Output "No contesta al ping" >>$fichero_log                               
            $ping="KO"
            
        }		

	#$ipnumber=[System.Net.Dns]::GetHostAddresses("$fip")

#### PRUEBO SI ESTA DADO DE ALTA EN EL DNS  #######

#$nombredeip="empiezo"
#try{
#    write-host "pregunto al dns"
#    $nombredeip=[System.Net.Dns]::GetHostEntry("$fip")
#    write-host "DNS contesta"
#    $dns="OK"        
#}
#catch{
#   write-host "DNS no sabe"
#   $dns="KO"
#   $nombredeip="sinnombre"   
#}

 #Write-Output $nombredeip

#$resultado="Ping=$ping"+" DNS=$dns"


	####### CONSIGUIENDO DATOS ######

#if (	$nombredeip=[System.Net.Dns]::GetHostEntry("$fip")	  ){
#if (($dns -eq "OK") -or($ping -eq "OK") ){	
if ($ping -eq "OK"){	
    
    #Write-Host $fip $nombredeip.HostName   
	
    #if ($nombredeip -ne "sinnombre"){

	    #$miSheet.Cells.Item($fnumero,1)=$nombredeip.HostName     #NOMBRE 1    
	    #$miSheet.Cells.Item($fnumero,2)=$fip					 #IP 2    
     #   $nombrecompleto=$nombredeip.HostName    
     #   if ($nombrecompleto.Contains(".")){
     #       $nombre=$nombrecompleto.Split(".")[0]   #quito los puntos del nombre
     #   }
     #   else{
     #   $nombre=$nombrecompleto
     #   }
     #}
     #else{
     #$nombre=$nombredeip
     #}
    #$t=[string]$fip


############ Pruebo si la máquina ya tiene entrada en la BD ###############

 # $fecha=get-date -Format u
 # $fecha=$fecha.Replace("Z","")     
    
    $netItems=0	
   
    $encuentrocredencialwmi=$false			


#######
# WMI #    
#######

        $respuestawmi=@()
        
       # Write-Host $netItems


############ Le pregunto sin credenciales para que me responda con error acceso denegado o fallo del servidor RPC  ########################3       
        Write-Output "Comprobando respuesta a WMI">>$fichero_log       
        Write-Host "Comprobando respuesta a WMI"       
        $netItems =Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace root\CIMV2 -ComputerName $fip -ErrorVariable respuestawmi -ErrorAction SilentlyContinue         
        if  ($netItems -eq $null){
          #  Write-Host $netItems
            Write-Host "ITEMS WMI NULL"
        }
        
        if( ( ($respuestawmi -match "denegado") -or ($respuestawmi -match "denied") -or ($netItems -ne 0) ) -and ($netItems -ne $null) ){  #Es WMI pero no tengo sus credenciales
                Write-Output "`tEs WMI">>$fichero_log       
                Write-Host "es WMI"
                #Write-Host $netItems

                $eswmi=$true

                    if ($netItems -ne 0){   #ya tengo credenciales
                        Write-Output "Ya tengo credenciales WMI" >>$fichero_log
                        write-host "ya tengo credenciales WMI"
                        $operat=Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip          
                        $nombre=$operat.name
                        $nombrecompleto=$operat.name+"."+$operat.domain                        
                       
                        #$netItems1 =Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace root\CIMV2 -ComputerName $fip  -ErrorAction SilentlyContinue	
                        #$netItems2 =Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace root\CIMV2 -ComputerName $fip  -ErrorAction SilentlyContinue	
                        #$netItems3 =Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace root\CIMV2 -ComputerName $fip  -ErrorAction SilentlyContinue
                        #$netItems4 =Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace root\CIMV2 -ComputerName $fip  -ErrorAction SilentlyContinue
        	            

                        recojo_datos_sin_credencial $fip $fichero_log
                        

                   }
                    else  #no tengo credenciales, voy a buscarlas
                    {    





                    $operat1 =Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $fcredencialwmi1 -ErrorAction SilentlyContinue	                   
	                if ($operat1.count -ne 0){
                                        $fcredencialwmi=$fcredencialwmi1
                                        $encuentrocredencialwmi=$true
                                        write-host "credencial1"
                                        $nombre=$operat1.name
                                        $nombrecompleto=$operat1.name+"."+$operat1.domain                                        
                                        }
                    else{
                        $operat2 =Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $fcredencialwmi2 -ErrorAction SilentlyContinue	
                        if ($operat2.count -ne 0){
                                        $fcredencialwmi=$fcredencialwmi2
                                        $encuentrocredencialwmi=$true
                                        write-host "credencial2"
                                        $nombre=$operat2.name
                                        $nombrecompleto=$operat2.name+"."+$operat2.domain                                        
                                        }
                        else{
                            $operat3 =Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $fcredencialwmi3 -ErrorAction SilentlyContinue
                            if ($operat3.count -ne 0){
                                        $fcredencialwmi=$fcredencialwmi3
                                        $encuentrocredencialwmi=$true
                                        write-host "credencial3"
                                        $nombre=$operat3.name
                                        $nombrecompleto=$operat3.name+"."+$operat3.domain                                        
                                        }
                            else{
                                $operat5 =Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $fcredencialwmi5 -ErrorAction SilentlyContinue
                                if ($operat5.count -ne 0){
                                        $fcredencialwmi=$fcredencialwmi5
                                        $encuentrocredencialwmi=$true
                                        write-host "credencial5"
                                        $nombre=$operat5.name
                                        $nombrecompleto=$operat5.name+"."+$operat5.domain                                        
                                        }
                                else{
                                    $operat6 =Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $fcredencialwmi6 -ErrorAction SilentlyContinue
                                    if ($operat6.count -ne 0){
                                        $fcredencialwmi=$fcredencialwmi6
                                        $encuentrocredencialwmi=$true
                                        write-host "credencial6"
                                        $nombre=$operat6.name
                                        $nombrecompleto=$operat6.name+"."+$operat6.domain                                        
                                        }
                                    else{
                                        $operat7 =Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $fcredencialwmi7 -ErrorAction SilentlyContinue
                                        if ($operat7.count -ne 0){
                                            $fcredencialwmi=$fcredencialwmi7
                                            $encuentrocredencialwmi=$true
                                            write-host "credencial7"
                                            $nombre=$operat7.name
                                            $nombrecompleto=$operat7.name+"."+$operat7.domain                                        
                                        }
                                        else{
                                            $operat8 =Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $fcredencialwmi8 -ErrorAction SilentlyContinue
                                            if ($operat8.count -ne 0){
                                                $fcredencialwmi=$fcredencialwmi8
                                                $encuentrocredencialwmi=$true
                                                write-host "credencial8"
                                                $nombre=$operat8.name
                                                $nombrecompleto=$operat8.name+"."+$operat8.domain                                       
                                            }
                                            else{
                                                $operat9 =Get-WmiObject Win32_ComputerSystem -Namespace root\CIMV2 -ComputerName $fip -Credential $fcredencialwmi9 -ErrorAction SilentlyContinue
                                                if ($operat9.count -ne 0){
                                                    $fcredencialwmi=$fcredencialwmi9
                                                    $encuentrocredencialwmi=$true
                                                    write-host "credencial9"
                                                    $nombre=$operat9.name
                                                    $nombrecompleto=$operat9.name+"."+$operat9.domain                                       
                                                }
                                            }#else del 8                                        
                                        }#else del 7

                                    }#else del 6
                                
                                }#else del 5
                            
                            }#else del 3
                        
                        }#else del 2
                    
                    }#else del 1                  
          
         
          
                    





                        Write-Output( $fcredencialwmi.username)

                        if ($encuentrocredencialwmi -eq $true){
                                Write-Output $nombre
                                Write-Output $nombrecompleto
                                Write-Output $nombredeip
                                write-host "He averiguado credenciales WMI"                                                                        
                                Write-Output "He averiguado Credencial Valida">>$fichero_log

                                recojo_datos_con_credencial $fip $fcredencialwmi $fichero_log
                                		                        


                        } #encuentro credencial WMI

                    
                        else #no he encontrado credencial
                        {                                     
                            Write-Host "Es WMI pero no me vale ninguna credencial"
                            Write-Output "Es WMI pero no me vale ninguna credencial" >> $fichero_log
                           
                        }
             

                 }#Else de voy a buscar credenciales

        }     #Es WMI            
        else
        {
           $eswmi=$false
           Write-Host "No es WMI"
        }       


###########
# FIN WMI #    
###########

##########
# LINUX  #
##########
        if ($eswmi -eq $false){ # no es WMI, Intento con LINUX   
            
               
            $session=New-SSHSession -ComputerName $fip -Credential $credencialWMI1 -ErrorVariable respuestalinux
            Write-Host $session
            if ($session -notmatch "SSH.SshSession"){

                Remove-SSHSession -index 0
                write-host "No puedo establecer conexion SSH"
            }
            else{ 
                
                $stream=$session.Session.CreateShellStream("mistream", 0, 0, 0, 0, 1000)      #SIN USAR STREAM (SOLO PARA SWITCHES)
                

                $stream.Writeline("uname") #Lanzo consulta
                Start-Sleep 1
                $resultado=$stream.Read() #Recupero consulta

                if ($resultado -ne $null ){ $eslinux=$true}else{$eslinux =$false}




                #MEMORIA TOTAL
                $meminfo=Invoke-SSHCommand -Index 0 -Command "cat /proc/meminfo |grep `"MemTotal`""
                #Write-Host $meminfo.Output
                $mel=$meminfo.Output
                #$stream.writeline("cat /proc/meminfo |grep `"MemTotal`"")
                #Start-Sleep 4
                #$mel1=$stream.read()
                #write-host memoria: $mel
                #write-host memoria1: $mel1[0]
              #  Write-Host $mel.gettype()
                $t=$mel.split(" ")
                
               # Write-Host $t[-2]
                $memo=[decimal]$t[-2]
               # Write-Host $memo
                $resultadomem=$memo/1024


                #MEMORIA LIBRE
                $memfreeinfo=Invoke-SSHCommand -Index 0 -Command "cat /proc/meminfo |grep `"MemFree`""
                
                #Write-Host $meminfo.Output
                $melfree=$memfreeinfo.Output
              #  Write-Host $mel.gettype()
                $tfree=$melfree.split(" ")
                
               # Write-Host $t[-2]
                $memofree=[decimal]$tfree[-2]
               # Write-Host $memo
                $resultadomemfree=$memofree/1024
             
                
                $memoriatotal=$resultadomem
                $memorialibre=$resultadomemfree
                $memoriaconsumida=$resultadomem-$resultadomemfree

                $ServicePoint=[System.Net.ServicePointManager]::FindServicePoint("http://172.17.100.180:8086/write?db=EFE")
                $ServicePoint.ConnectionLimit=10
                $ServicePoint.CloseConnectionGroup("")

                $authheader = "Basic " + ([Convert]::ToBase64String([System.Text.encoding]::ASCII.GetBytes("root:root")))
                $uri = 'http://172.17.100.180:8086/write?db=EFE'
                #$uri = 'http://'+$dbserver+':8086/write?db='+$BD
                
                #$Metricsmem = "Uso_Memoria,maquina=$fip"+",TotalMem=$memoriatotal"+",FreeMem=$memorialibre"+" value=$memoriaconsumida" #la "i" le indica que es un entero
                $Metricsmem = "Uso_Memoria,maquina=$fip"+" value=$memoriaconsumida" #la "i" le indica que es un entero
   
                Write-host "invoke memoria"
                Invoke-RestMethod -Headers @{Authorization=$authheader} -Uri $uri -Method POST -Body $Metricsmem
                $ServicePoint.CloseConnectionGroup("")
                Write-host "Fin invoke memoria"

                
                #CPU
                $cpuinfo=Invoke-SSHCommand -Index 0 -Command "iostat |grep -A 2 avg-cpu "
                #Write-Host $cpuinfo
                #$r=Invoke-SSHCommand -Index 0 -Command "q"
                
                $cpu=$cpuinfo.Output
                #Write-Host $cpu
                $lineascpu=$cpu.split("`n")  #nueva linea   retorno  de carro es `r

                #write-host "AAAAA"
                #write-host $lineascpu[0]
                $lineacpu=$lineascpu[1]
                $palabrascpu=$lineacpu.split(" ")
                #Write-Host $palabrascpu[-1]
                $valor=$palabrascpu[-1].replace(',','.')
                $idlecpu=[decimal]$valor
                #Write-Host $idlecpu
                $usagecpu=100-$idlecpu
                write-host $usagecpu
                $id="CPU0"
                Write-Host $fip


                $Metricscpu = "Uso_CPU,maquina=$fip"+",CPU=$id"+" value=$usagecpu" #la "i" le indica que es un entero                   
                Invoke-RestMethod -Headers @{Authorization=$authheader} -Uri $uri -Method POST -Body $Metricscpu
                $ServicePoint.CloseConnectionGroup("")




              #  Write-Host $mel.gettype()
                 #$t=$mel.split(" ")
               # $stream.Writeline("top |grep 'Cpu(s)'") #Lanzo consulta
               # Start-Sleep 1
               # $stream.Writeline("q") #Lanzo consulta
               # $cpuinfo=$stream.Read() #Recupero consulta
               # write-host $cpuinfo

                Remove-SSHSession -index 0

            }#Else de notmatch SSH.Session

        }#Fin de Linux


#############
# FIN LINUX #     
#############


}
else{    #No dado de alta en el DNS $dns="KO" ni contesta al ping $ping="KO"
    
      


}




} #Fin de funcion

Function inventario_rango ($fmaquinas, $fcredencialWMI1, $fcredencialWMI2, $fcredencialWMI3, $fcredencialWMI5, $fcredencialWMI6, $fcredencialWMI7, $fcredencialWMI8, $fcredencialWMI9, $fcredencialILO){                    
   
        write-host $fmaquinas
        $ipsRecorrer=$fmaquinas -split "-"
        $ipnumbers=$ipsRecorrer[0].split("{.}")
        $numero=1 #Para mantener la linea en la salida del Excel
        $triada=$ipNumbers[0]+"."+$ipNumbers[1]+"."+$ipNumbers[2]
        $evito=0  #Evita consultar las maquinas de la lista "D:\PWSH\ExploraRedesBD\evita.txt"

        for ($i=[int]$ipnumbers[3] ; $i -le $ipsRecorrer[1];$i++){          #convierto la cadena en rango de ips
			           							
			        #write-host $ipsRecorrer[0]
			        $ipexplorar=$ipNumbers[0]+"."+$ipNumbers[1]+"."+$ipNumbers[2]+"."+$i
			         Write-Host $ipexplorar
                
			        #if (Test-Connection $rangoips  -Count 1  -Quiet){  # solo lo que responda al ping QUITAR!!!!
                                                     <#               $respuesta_al_ping=Test-Connection $rangoips  -Count 1 
                 if ($respuesta_al_ping -ne $null){  # solo lo que responda al ping QUITAR!!!!
                                    
                        Switch($respuesta_al_ping.ResponseTimeToLive){
                            {$_ -le 64} {$opera="Linux"; break}
                            {$_ -le 128} {$opera="Windows"; break}
                            {$_ -le 255} {$opera="UNIX"; break}
                        }
                 }
                 else{
               
                 }

        #>


            ####################### Creo el fichero de log de la máquina #############################
            $directorio_logs="D:\PWSH\serverstoinflux\logs\"+$fmaquinas       
            $fichero_log_ip=$directorio_logs+"\"+$ipexplorar+".txt"
        
            Write-Output $fichero_log_ip

            if (-not (test-path $directorio_logs)){        #Si no exite el directorio de logs, lo creo           
                 New-Item -path $directorio_logs -itemtype "directory"        
            }
            if (test-path $fichero_log_ip ){                 #Borro el log antiguo del equipo  y lo vuelvo a crear
                Remove-Item $fichero_log_ip                    
            }        
                New-Item $fichero_log_ip -ItemType "file"

            Write-Output $fichero_log_ip
            Get-Date > $fichero_log_ip

            ###########################################################################################

       
       

                            $evitar=Get-Content "D:\PWSH\serverstoinflux\evita.txt"
                            foreach ($evita in $evitar)
                            {                
                                if($evita -eq $ipexplorar)
                                {      
                                    $evito=1                                            				        
                                }
                   
                            }
                            if ($evito -ne 1){
                                $numero=$numero+1
                                                                 
    				                SysInfo $ipexplorar $fcredencialWMI1 $fcredencialWMI2 $fcredencialWMI3 $fcredencialWMI5 $fcredencialWMI6 $fcredencialWMI7 $fcredencialWMI8 $fcredencialWMI9 $fcredencialILO $numero $fichero_log_ip   #Llamo a sysInfo				                
                                   
                            }
                            else{
                                Write-Output ("Evito")
                                Write-Output "Evito" >> $fichero_log_ip
                            }
               
			        #}		

        $evito=0
        }



       # $fecha=Get-Date | foreach {$_ -replace "/", "_"}
       # $fecha=$fecha |foreach {$_ -replace ":","_"}
       # $fecha=$fecha |foreach {$_ -replace " ","_"}


        Write-Host "Fin de la ejecucion"
        Write-Output "Fin del analisis" >>$fichero_log_ip

}# Fin funcion inventario_rango

$passWMI1=Get-Content "D:\PWSH\serverstoinflux\pa\wmi1\wmi1.txt" |ConvertTo-SecureString
$credencialWMI1=New-Object System.Management.Automation.PSCredential "admin.alarmas", $passWMI1    
     #$usuarioWMI5="admin.alarmas"
	#$passwordWMI5="5f8.T!02"
    
$passWMI2=Get-Content "D:\PWSH\serverstoinflux\pa\wmi2\wmi2.txt" |ConvertTo-SecureString
$credencialWMI2=New-Object System.Management.Automation.PSCredential "administrator", $passWMI2
    #$usuarioWMI2="administrator"
	#$passwordWMI2="4L0NS0C4MPE0N"

$passWMI3=Get-Content "D:\PWSH\serverstoinflux\pa\wmi3\wmi3.txt" |ConvertTo-SecureString
$credencialWMI3=New-Object System.Management.Automation.PSCredential "administrator", $passWMI3
    #$usuarioWMI3="administrator"
	#$passwordWMI3="4TLETI4PRIMER4"
    
    #$passWMI4=Get-Content "D:\PWSH\ExploraRedesBD\pa\wmi4\wmi4.txt" |ConvertTo-SecureString     #solo para EPI y BLAS
    #$credencialWMI4=New-Object System.Management.Automation.PSCredential "administrator", $passWMI4
    #$usuarioWMI4="administrator"
	#$passwordWMI4="4l4rm4s"
    
$passWMI5=Get-Content "D:\PWSH\serverstoinflux\pa\wmi5\wmi5.txt" |ConvertTo-SecureString
$credencialWMI5=New-Object System.Management.Automation.PSCredential "rmonitor", $passWMI5    
    #$usuarioWMI1="rmonitor"
	#$passwordWMI1="k!z.35"
    
$passWMI6=Get-Content "D:\PWSH\serverstoinflux\pa\wmi6\wmi6.txt" |ConvertTo-SecureString
$credencialWMI6=New-Object System.Management.Automation.PSCredential "administrator", $passWMI6
    #$usuarioWMI6="administrator"
	#$passwordWMI6="QUE.TE.JODAN.01"

$passWMI7=Get-Content "D:\PWSH\serverstoinflux\pa\wmi7\wmi7.txt" |ConvertTo-SecureString
$credencialWMI7=New-Object System.Management.Automation.PSCredential "monitorizacion", $passWMI7
    #$usuarioWMI7="monitorizacion"
	#$passwordWMI6="monitor"

$passWMI8=Get-Content "D:\PWSH\serverstoinflux\pa\wmi8\wmi8.txt" |ConvertTo-SecureString
$credencialWMI8=New-Object System.Management.Automation.PSCredential "administrator", $passWMI8
    #$usuarioWMI7="monitorizacion"
	#$passwordWMI6="T3sl4.Tur1n."

$passWMI9=Get-Content "D:\PWSH\serverstoinflux\pa\wmi9\wmi9.txt" |ConvertTo-SecureString
$credencialWMI9=New-Object System.Management.Automation.PSCredential "administrador", $passWMI9
    #$usuarioWMI7="administrador"
	#$passwordWMI6="T3sl4.Tur1n."

if ($rango -match "-"){ #Es un rango

         Write-Host "Es un rango"

         Write-Output "Comenzando analisis del rango">>$fichero_log_principal
         inventario_rango $rango $credencialWMI1 $credencialWMI2 $credencialWMI3 $credencialWMI5 $credencialWMI6 $credencialWMI7 $credencialWMI8 $credencialWMI9 $credencialILO   #Llamo a inventario rango
         
		 Write-host "Informe finalizado"
         Write-Output "Fin del analisis" >>$fichero_log_principal			
         }
else{

 if (validar-ip "$rango"){
    
        ####################### Creo el fichero de log de la máquina #############################
        $directorio_logs="D:\PWSH\serverstoinflux\logs\"+$rango+"\"
        $fichero_log_ip=$directorio_logs+$rango+".txt"
        
        Write-Output $fichero_log_ip

        if (-not (test-path $directorio_logs)){        #Si no exite el directorio de logs, lo creo           
             New-Item -path $directorio_logs -itemtype "directory"        
        }
        if (test-path $fichero_log_ip ){                 #Borro el log antiguo del equipo  y lo vuelvo a crear
            Remove-Item $fichero_log_ip                    
        }        
            New-Item $fichero_log_ip -ItemType "file"

        Write-Output $fichero_log_ip
        Get-Date > $fichero_log_ip

###########################################################################################

SysInfo $rango $credencialWMI1 $credencialWMI2 $credencialWMI3 $credencialWMI5 $credencialWMI6 $credencialWMI7 $credencialWMI8 $credencialWMI9 $credencialILO $numero $fichero_log_ip   #Llamo a sysInfo


}
else{
Write-Host "IP no valida"
}






}