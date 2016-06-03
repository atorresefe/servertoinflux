function serverstoinflux(){
    Clear-Host        

    $redes=Content D:\PWSH\serverstoinflux\servers.txt
    write-host "Iniciando Procesos..."
    foreach ($red in $redes){       
        $nombre_tarea="$red"
        Start-Job -FilePath C:\Users\administrator\Documents\WindowsPowerShell\Modules\serverstoinflux\serverstoinflux.ps1 -Name $nombre_tarea -ArgumentList $red
        
        Start-Sleep 1
    }
    Start-Sleep 2
    Write-host ""
    while (1){       
        Start-Sleep 1 
        $trabajos=Get-Job
        #Start-Sleep 2
        foreach($trabajo in $trabajos){
            Start-Sleep 1 
            <#           
            if ($trabajo.state -eq "Running"){
                $horainicio=$trabajo.PSBeginTime
                $horaactual=get-date
                $tiempoarrancado=$horaactual-$horainicio
                if ($tiempoarrancado.TotalMinutes -gt 20){
                    
                    Write-Warning "Trabajo bloqueado!"
                    #Stop-Job $trabajo.id                    
                    Receive-Job
                }
            }
            #>
            #if (($trabajo.State -eq "Completed") -or ($trabajo.State -eq "Failed") -or ($trabajo.State -eq "Stopped")){
            if (($trabajo.State -eq "Completed") -or ($trabajo.State -eq "Failed")){                            
                Remove-Job $trabajo.id
                #Start-Sleep 1
                Start-Job -FilePath C:\Users\administrator\Documents\WindowsPowerShell\Modules\serverstoinflux\serverstoinflux.ps1 -Name $trabajo.name -ArgumentList $trabajo.name            
                Start-Sleep 2
                #Write-Host "acabo el start"
            }
            

               
        }

    } #While 1

}


<#
function serverstoinflux(){
    Clear-Host        
     
     $redes=Content D:\PWSH\serverstoinflux\servers.txt
while(1){
    foreach ($red in $redes){       
        $nombre_tarea="$red"
        Start-Job -FilePath C:\Users\administrator\Documents\WindowsPowerShell\Modules\serverstoinflux\serverstoinflux.ps1 -Name $nombre_tarea -ArgumentList $red
        #Start-Sleep 300
    }
    $jobs=get-job
    $cuentacompletados=0
    $enproceso=$true

    while($enproceso -eq $true){
        foreach ($job in $jobs){
           if ($job.state -eq "Completed"){
             $cuentacompletados++
           }
           else{
            $cuentacompletados=0
           }
           if ($cuentacompletados -eq $jobs.count){
             $enproceso=$false
           }
        }
  }#while
   #get-job
   remove-job *
   # Start-Sleep 5
   # }
   }
}

#>