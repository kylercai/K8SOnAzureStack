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
		[string]$HyperCubeImage = "msazurestackdocker/k8s1.9:latest",

		[Parameter(Mandatory = $false)]
		[string]$HyperCubeImageVersion = "1.9"
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

	####pre-set the spn.applicationId, spn.password, or modify the value in the generated apiModel file
    $apiModel.properties.servicePrincipalProfile.clientId = $spn.applicationId
    $apiModel.properties.servicePrincipalProfile.secret = $spn.password

	Write-Verbose "Placing the API model to local location." -Verbose
	$localFilePathForApiModel = "$PSScriptRoot\azurestack.json"
    Write-Verbose "azurestack.json: $($PSScriptRoot)" -Verbose
    $apiModel | ConvertTo-Json -Depth 100 | Out-File -FilePath $localFilePathForApiModel -Encoding ascii

	$apiModel
}