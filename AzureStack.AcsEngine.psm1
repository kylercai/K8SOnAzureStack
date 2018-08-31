function Get-AcseRemoteSSLCertificate
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String] $Url
    )

    $WebRequest = [Net.WebRequest]::CreateHttp($Url)
    $WebRequest.AllowAutoRedirect = $true
    $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

    try 
    {
        $Response = $WebRequest.GetResponse()
    }
    catch 
	{
		# We don't care even if there is an exception, as we still get the certificate.
	}

    $certificate = $WebRequest.ServicePoint.Certificate.Handle
    
    # Build the certificate chain.
    $chain.Build($certificate) | Out-Null

    $count = $chain.ChainElements.Count

    Write-Verbose "Total elementes in the cert chain are $($chain.ChainElements.Count)" -Verbose
    Write-Verbose "Last element in cert chain is issued by: $($chain.ChainElements[$count-1].Certificate.IssuerName.Name)" -Verbose

    $certificateThumbprint = $chain.ChainElements[$count-1].Certificate.GetCertHashString()

    [Net.ServicePointManager]::ServerCertificateValidationCallback = $null | Out-Null

	$certificateThumbprint
}

function Set-AcseAzureStackEnvironment
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String] $ArmEndpoint,

		[Parameter(Mandatory=$false)]
        [String] $EnvironmentName = "AzureStackUser"
    )

    
	Write-Verbose "Creating/Retrieving tenant environment at endpoint: $ArmEndpoint" 
	$environment = Get-AzureRmEnvironment -Name $EnvironmentName 
	if ($environment -eq $null)
    {
		$environment = Add-AzureRmEnvironment -Name $EnvironmentName -ArmEndpoint $ArmEndpoint -Verbose -ErrorAction Stop
    }

    $result = @{'ActiveDirectoryServiceEndpointResourceId'=$environment.ActiveDirectoryServiceEndpointResourceId;
				'GalleryUrl'=$environment.GalleryUrl;
                'StorageEndpointSuffix'=$environment.StorageEndpointSuffix;
                'AzureKeyVaultDnsSuffix'=$environment.AzureKeyVaultDnsSuffix; 
                'AzureKeyVaultServiceEndpointResourceId'=$environment.AzureKeyVaultServiceEndpointResourceId}
    $result

	Write-Verbose "Tenant environment created at endpoint: $ArmEndpoint"
}

function New-AcseServicePrincipal
{
    param
    (
		[Parameter(Mandatory = $true)]
		[string]$AadTenantId,

        [Parameter(Mandatory = $true)]
		[PSCredential]$ServiceAdminCredential
    )
   
    $session = New-PSSession -ErrorAction Stop

    Invoke-Command -Session $session -ScriptBlock {

        # If we are logged in we want to ensure that we logout.
        $null = Logout-AzureRmAccount -ErrorAction Ignore | Out-Null

        Write-Verbose "Logging to AzureCloud with tenantId: $using:AadTenantId" -Verbose
        $publicCloud = Get-AzureRmEnvironment -Name AzureCloud
        $null = Login-AzureRmAccount -Environment $publicCloud -Credential $using:ServiceAdminCredential -TenantId $using:AadTenantId -ErrorAction Stop

        $applicationName = "Kubernetes-WLK-$(New-Guid)"
        $password = (New-Guid).ToString()
        $application = New-AzureRmADApplication -DisplayName $applicationName -IdentifierUris "http://$applicationName" -HomePage "http://localhost" -Password $password   
        $applicationId = $application.ApplicationId
        $null = New-AzureRmADServicePrincipal -ApplicationId $applicationId
       
        $result = @{'applicationId'=$applicationId;'password'=$password}
        $result
    }  
    
    Remove-PSSession -Session $session
}

function Assign-AcseServicePrincipal
{
    param
    (
		[Parameter(Mandatory = $true)]
		[string]$TenantArmEndpoint,

		[Parameter(Mandatory = $true)]
		[string]$AadTenantId,

		[Parameter(Mandatory = $true)]
		[PSCredential]$TenantAdminCredential,

		[Parameter(Mandatory = $true)]
		[string]$TenantSubscriptionId,
		
		[Parameter(Mandatory = $true)]
		[string]$ApplicationId
    )
   
    $session = New-PSSession -ErrorAction Stop

    Invoke-Command -Session $session -ScriptBlock {

		$environmentName = "AzureStackUser"
        $environment = Get-AzureRmEnvironment -Name $environmentName
		if ($environment -eq $null)
		{
			$environment = Add-AzureRmEnvironment -Name $environmentName -ArmEndpoint $using:TenantArmEndpoint -Verbose -ErrorAction Stop
		}
		Login-AzureRmAccount -EnvironmentName $environmentName -TenantId $using:AadTenantId -Credential $using:TenantAdminCredential -ErrorAction Stop | Out-Null
        
		$subscription = Select-AzureRmSubscription -SubscriptionId $using:TenantSubscriptionId

		Write-Verbose "Assigning SPN: $using:ApplicationId to subcription: $using:TenantSubscriptionId." -Verbose
		New-AzureRmRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $using:ApplicationId | Out-Null
    }  
    
    Remove-PSSession -Session $session
}

function New-AcseStorageAccount
{
    param
    (
		[Parameter(Mandatory = $true)]
        [String] $AadTenantId,

		[Parameter(Mandatory = $true)]
        [String] $Location,

        [Parameter(Mandatory = $true)]
        [PSCredential] $TenantAdminCredential,

        [Parameter(Mandatory = $true)]
        [string] $TenantArmEndpoint,

		[Parameter(Mandatory = $true)]
        [string] $TenantSubscriptionId,

		[Parameter(Mandatory = $true)]
        [string] $LocalFilePath,

		[Parameter(Mandatory = $false)]
        [string] $NamingSuffix
    )

	$environmentName = "AzureStackUser"
	$environment = Get-AzureRmEnvironment -Name $environmentName
    if ($environment -eq $null)
    {
        $environment = Add-AzureRmEnvironment -Name $environmentName -ArmEndpoint $TenantArmEndpoint -Verbose -ErrorAction Stop
    }
	Login-AzureRmAccount -EnvironmentName $environmentName -TenantId $AadTenantId -Credential $TenantAdminCredential  -ErrorAction Stop | Out-Null

	$subscription = Select-AzureRmSubscription -SubscriptionId $TenantSubscriptionId -ErrorAction Stop

	if (-not ($NamingSuffix)) 
	{
		$NamingSuffix = 10000..99999 | Get-Random
	}
	$resourceGroupName = "k8ssa-" + $NamingSuffix
	$storageAccountName = "k8ssa" + $NamingSuffix
	$containerName = "k8ssaci" + $NamingSuffix

	#Write-Verbose "Creating or retrieving resource group: $resourceGroupName." -Verbose
	#if (-not (Get-AzureRmResourceGroup -Name $resourceGroupName -Location $Location -ErrorAction SilentlyContinue)) 
	#{
	#	New-AzureRmResourceGroup -Name $resourceGroupName -Location $Location -ErrorAction Stop| Out-Null
	#}

	#Write-Verbose "Creating or retrieving storage account: $storageAccountName." -Verbose
	$storageAccount = Get-AzureRmStorageAccount -Name $storageAccountName -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue
	#if (-not ($storageAccount)) 
	#{
		#$storageAccount = New-AzureRmStorageAccount -AccountName $storageAccountName -Location $Location -ResourceGroupName $resourceGroupName -Type Standard_LRS -ErrorAction Stop
	#	$storageAccount = New-AzureRmStorageAccount -AccountName $storageAccountName -Location $Location -ResourceGroupName $resourceGroupName -SkuName Standard_LRS
	#}
	Write-Verbose "Storage account AbsoluteUri: $($storageAccount.PrimaryEndpoints.Blob.AbsoluteUri)"
	Set-AzureRmCurrentStorageAccount -StorageAccountName $storageAccountName -ResourceGroupName $resourceGroupName | Out-Null
    
	#Write-Verbose "Creating or retrieving container account: $containerName." -Verbose
	$container = Get-AzureStorageContainer -Name $containerName -ErrorAction SilentlyContinue
	#if (-not ($container)) 
	#{
	#	$container = New-AzureStorageContainer -Name $containerName -Permission Blob
	#}

	$fileName = Split-Path $LocalFilePath -Leaf
	Set-AzureStorageBlobContent -File $LocalFilePath -Container $containerName -Blob $fileName -Force | Out-Null

	[string]$apiModelBlobPath = '{0}{1}/{2}' -f $storageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $containerName, $fileName
	Write-Verbose "Uploaded the API model to: $apiModelBlobPath." -Verbose

	[string]$blobRootPath = '{0}{1}' -f $storageAccount.PrimaryEndpoints.Blob.AbsoluteUri, $containerName
	Write-Verbose "Blob root path: $blobRootPath." -Verbose

	$result = @{'apiModelBlobPath'=$apiModelBlobPath;'blobRootPath'=$blobRootPath;'storageAccountResourceGroup'=$resourceGroupName;'storageAccountName'=$storageAccountName;}
    $result
}

function Prepare-AcseApiModel
{
    param
    (
		[Parameter(Mandatory = $true)]
		[string]$ErcsComputerName,

		[Parameter(Mandatory = $true)]
		[PSCredential]$CloudAdminCredential,

        [Parameter(Mandatory = $true)]
		[PSCredential]$ServiceAdminCredential,

		[Parameter(Mandatory = $true)]
		[PSCredential]$TenantAdminCredential,

		[Parameter(Mandatory = $true)]
		[string]$TenantSubscriptionId,

		[Parameter(Mandatory = $true)]
		[string]$MasterDnsPrefix,

		[Parameter(Mandatory = $true)]
		[string]$LinuxVmSshKey,

		[Parameter(Mandatory = $false)]
		[string]$NamingSuffix,

		[Parameter(Mandatory = $false)]
		[string]$HyperCubeImage = "msazurestackdocker/kubernetes:20180321.1.1.7.14",

		[Parameter(Mandatory = $false)]
		[string]$HyperCubeImageVersion = "1.7"
    )

    # Retrieve Stamp information.
	Write-Verbose "Retrieving stamp information from ERCS: $ErcsComputerName." -Verbose
    winrm s winrm/config/client "@{TrustedHosts=`"$ErcsComputerName`"}" | Out-Null
    $stampInfo = Invoke-Command -ComputerName $ErcsComputerName -Credential $CloudAdminCredential -ConfigurationName PrivilegedEndpoint -ScriptBlock { Get-AzureStackStampInformation } 

    if ($stampInfo.IdentitySystem -ne "AzureAD")
    {
		Write-Verbose "Creating Kubernetes API model is only supported for AAD type AzureStack System." -Verbose
        throw "Creating Kubernetes API model is only supported for AAD type AzureStack System."
    }

    $aadTenantName = $stampInfo.AADTenantName
    $aadTenantId = $stampInfo.AADTenantID
    $regionName = $stampInfo.RegionName
    $tenantArmEndpoint = $stampInfo.TenantExternalEndpoints.TenantResourceManager.TrimEnd("/")
    $tenantMetadataEndpointUrl = "$tenantArmEndpoint/metadata/endpoints?api-version=1.0"
    
	$resourceManagerVMDNSSuffix = $stampInfo.ExternalDomainFQDN
	$array = $resourceManagerVMDNSSuffix.Split(".")
	$resourceManagerVMDNSSuffix = 'cloudapp.'+ ($array[1..($array.Length -1)] -join ".")

    Write-Verbose "Retrieving Root CA certificated from: $tenantMetadataEndpointUrl" -Verbose
    $certificateThumbprint = Get-AcseRemoteSSLCertificate -Url $tenantMetadataEndpointUrl
	Write-Verbose "Retrieved certificate thumbprint is: $certificateThumbprint" -Verbose

    Write-Verbose "TenantId: $aadTenantId, TenantArmEndpoint: $tenantArmEndpoint" -Verbose

	Write-Verbose "Adding Tenant AzureStack Environment." -Verbose
    $environment = Set-AcseAzureStackEnvironment -ArmEndpoint $tenantArmEndpoint -EnvironmentName "AzureStackUser"

    # Create service principal in AAD
    $spn = New-AcseServicePrincipal -AadTenantId $aadTenantId -ServiceAdminCredential $ServiceAdminCredential
    Write-Verbose "Created new SPN ClientID: $($spn.applicationId), Secret: $($spn.password)" -Verbose

    # Prepare the API model based on the current AzureStack environment.
	Write-Verbose "Preparing the API model" -Verbose
    $apiModel = ConvertFrom-Json (Get-Content -Path  "$PSScriptRoot\azurestack-default.json" -Raw -ErrorAction Stop)
	$apiModel.properties.orchestratorProfile.kubernetesConfig.CustomHyperkubeImage = $HyperCubeImage
	$apiModel.properties.orchestratorProfile.orchestratorRelease = $HyperCubeImageVersion

	$apiModel.properties.masterProfile.dnsPrefix = $MasterDnsPrefix
	
    $apiModel.properties.cloudProfile.serviceManagementEndpoint = $environment.ActiveDirectoryServiceEndpointResourceId
    $apiModel.properties.cloudProfile.resourceManagerEndpoint = $tenantArmEndpoint   
    $apiModel.properties.cloudProfile.galleryEndpoint = $environment.GalleryUrl
    $apiModel.properties.cloudProfile.keyVaultEndpoint = $environment.AzureKeyVaultServiceEndpointResourceId
    $apiModel.properties.cloudProfile.storageEndpointSuffix = $environment.StorageEndpointSuffix
    $apiModel.properties.cloudProfile.keyVaultDNSSuffix = $environment.AzureKeyVaultDnsSuffix
	$apiModel.properties.cloudProfile.resourceManagerVMDNSSuffix = $resourceManagerVMDNSSuffix
    $apiModel.properties.cloudProfile.resourceManagerRootCertificate = $certificateThumbprint
    $apiModel.properties.cloudProfile.location = $regionName

	$apiModel.properties.linuxProfile.ssh.publicKeys[0].keyData = $LinuxVmSshKey

    $apiModel.properties.servicePrincipalProfile.clientId = $spn.applicationId
    $apiModel.properties.servicePrincipalProfile.secret = $spn.password

	Write-Verbose "Placing the API model to local location." -Verbose
	$localFilePathForApiModel = "$PSScriptRoot\azurestack.json"
    Write-Verbose "azurestack.json: $($PSScriptRoot)" -Verbose
    $apiModel | ConvertTo-Json -Depth 100 | Out-File -FilePath $localFilePathForApiModel -Encoding ascii

	$saParameters = @{'AadTenantId' = $aadTenantId;
					'Location' = $regionName;
					'TenantAdminCredential' = $TenantAdminCredential;
					'TenantArmEndpoint' = $tenantArmEndpoint;
					'TenantSubscriptionId' = $TenantSubscriptionId;
					'LocalFilePath' = $localFilePathForApiModel;
					'NamingSuffix' = $NamingSuffix }

	Write-Verbose "Upload the locally created API model to a Storage Account." -Verbose
	$apiModel = New-AcseStorageAccount @saParameters
	$apiModel.Add('spnApplicationId', $spn.applicationId);

	$apiModel
}