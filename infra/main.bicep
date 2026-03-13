// ════════════════════════════════════════════════════════════════════════════
// Azure Brute-Force Defense — Bicep Deployment Template
// Deploys: VM, Function App, Log Analytics, Sentinel, Azure OpenAI, NSG, DCRs
// Author: El Bakkali
// ════════════════════════════════════════════════════════════════════════════

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Admin username for the Defender VM')
param adminUsername string = 'azuredefender'

@description('Admin password for the Defender VM')
@secure()
param adminPassword string

@description('Azure OpenAI model deployment name')
param openAiDeployment string = 'gpt-4o-mini'

@description('Azure OpenAI model name')
param openAiModelName string = 'gpt-4o-mini'

@description('Azure OpenAI model version')
param openAiModelVersion string = '2024-07-18'

@description('Azure OpenAI SKU capacity (thousands of tokens per minute)')
param openAiCapacity int = 10

// ── Naming ──────────────────────────────────────────────────────────────────
var prefix = 'bfdef'
var uniqueSuffix = uniqueString(resourceGroup().id)
var vmName = '${prefix}-vm'
var vnetName = '${prefix}-vnet'
var subnetName = 'snet-defender'
var nsgName = '${prefix}-nsg'
var lawName = '${prefix}-law'
var funcAppName = '${prefix}-func-${substring(uniqueSuffix, 0, 4)}'
var storageName = '${prefix}stor${substring(uniqueSuffix, 0, 5)}'
var aspName = '${prefix}-asp'
var openAiName = '${prefix}-openai-${substring(uniqueSuffix, 0, 4)}'
var publicIpName = '${prefix}-pip'
var nicName = '${prefix}-nic'

// ── 1. Network Security Group ───────────────────────────────────────────────
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowSSH'
        properties: {
          priority: 1000
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]
  }
}

// ── 2. Virtual Network ─────────────────────────────────────────────────────
resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

// ── 3. Public IP ────────────────────────────────────────────────────────────
resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: publicIpName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// ── 4. NIC ──────────────────────────────────────────────────────────────────
resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: vnet.properties.subnets[0].id
          }
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

// ── 5. Defender VM (Ubuntu 22.04, B2s) ──────────────────────────────────────
resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: vmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2s'
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
      linuxConfiguration: {
        disablePasswordAuthentication: false
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-jammy'
        sku: '22_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
  identity: {
    type: 'SystemAssigned'
  }
}

// ── 6. Azure Monitor Agent extension ────────────────────────────────────────
resource amaExtension 'Microsoft.Compute/virtualMachines/extensions@2024-03-01' = {
  parent: vm
  name: 'AzureMonitorLinuxAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorLinuxAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

// ── 7. Log Analytics Workspace ──────────────────────────────────────────────
resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: lawName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

// ── 8. Microsoft Sentinel (SecurityInsights solution) ───────────────────────
resource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'SecurityInsights(${lawName})'
  location: location
  plan: {
    name: 'SecurityInsights(${lawName})'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
  properties: {
    workspaceResourceId: law.id
  }
}

// ── 9. Data Collection Rules ────────────────────────────────────────────────
resource dcrSyslog 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: '${prefix}-dcr-syslog'
  location: location
  properties: {
    dataSources: {
      syslog: [
        {
          name: 'syslogAuth'
          streams: ['Microsoft-Syslog']
          facilityNames: ['auth', 'authpriv']
          logLevels: ['Debug', 'Info', 'Notice', 'Warning', 'Error', 'Critical', 'Alert', 'Emergency']
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: law.id
          name: 'lawDest'
        }
      ]
    }
    dataFlows: [
      {
        streams: ['Microsoft-Syslog']
        destinations: ['lawDest']
      }
    ]
  }
}

resource dcrSyslogAssoc 'Microsoft.Insights/dataCollectionRuleAssociations@2022-06-01' = {
  name: '${prefix}-dcr-syslog-assoc'
  scope: vm
  properties: {
    dataCollectionRuleId: dcrSyslog.id
  }
  dependsOn: [amaExtension]
}

// ── 10. Storage Account ─────────────────────────────────────────────────────
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
}

// ── 11. App Service Plan (B1 Linux) ─────────────────────────────────────────
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: aspName
  location: location
  kind: 'linux'
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  properties: {
    reserved: true // Linux
  }
}

// ── 12. Function App ────────────────────────────────────────────────────────
resource funcApp 'Microsoft.Web/sites@2023-12-01' = {
  name: funcAppName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      pythonVersion: '3.11'
      appSettings: [
        { name: 'AzureWebJobsStorage__accountName'; value: storageName }
        { name: 'FUNCTIONS_EXTENSION_VERSION'; value: '~4' }
        { name: 'FUNCTIONS_WORKER_RUNTIME'; value: 'python' }
        { name: 'DEFENDER_VM_IP'; value: publicIp.properties.ipAddress }
        { name: 'DEFENDER_VM_USER'; value: adminUsername }
        { name: 'LAW_WORKSPACE_ID'; value: law.properties.customerId }
        { name: 'LAW_RESOURCE_ID'; value: law.id }
        { name: 'NSG_NAME'; value: nsgName }
        { name: 'RESOURCE_GROUP'; value: resourceGroup().name }
        { name: 'SUBSCRIPTION_ID'; value: subscription().subscriptionId }
        { name: 'AZURE_OPENAI_ENDPOINT'; value: openAi.properties.endpoint }
        { name: 'AZURE_OPENAI_DEPLOYMENT'; value: openAiDeployment }
      ]
      cors: {
        allowedOrigins: [
          'https://portal.azure.com'
          'https://ms.portal.azure.com'
        ]
      }
    }
  }
  dependsOn: [storageAccount]
}

// ── 13. Azure OpenAI ────────────────────────────────────────────────────────
resource openAi 'Microsoft.CognitiveServices/accounts@2024-04-01-preview' = {
  name: openAiName
  location: location
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: openAiName
    publicNetworkAccess: 'Enabled'
  }
}

resource openAiDeploymentRes 'Microsoft.CognitiveServices/accounts/deployments@2024-04-01-preview' = {
  parent: openAi
  name: openAiDeployment
  sku: {
    name: 'GlobalStandard'
    capacity: openAiCapacity
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: openAiModelName
      version: openAiModelVersion
    }
  }
}

// ── 14. RBAC Role Assignments ───────────────────────────────────────────────
// Storage Blob Data Owner for Function App
resource storageBlobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, funcApp.id, 'StorageBlobDataOwner')
  scope: storageAccount
  properties: {
    principalId: funcApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b')
  }
}

// Storage Account Contributor for Function App
resource storageContribRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, funcApp.id, 'StorageAccountContributor')
  scope: storageAccount
  properties: {
    principalId: funcApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '17d1049b-9a84-46fb-8f53-869881c3d3ab')
  }
}

// Log Analytics Reader for Function App
resource lawReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(law.id, funcApp.id, 'LogAnalyticsReader')
  scope: law
  properties: {
    principalId: funcApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '73c42c96-874c-492b-b04d-ab87d138a893')
  }
}

// Cognitive Services OpenAI User for Function App
resource openAiUserRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(openAi.id, funcApp.id, 'CognitiveServicesOpenAIUser')
  scope: openAi
  properties: {
    principalId: funcApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd')
  }
}

// ── 15. Static Website (Blob Storage) ───────────────────────────────────────
// Note: Static website hosting must be enabled after deployment via:
//   az storage blob service-properties update --account-name <storageName> --static-website --index-document index.html --auth-mode login

// ── Outputs ─────────────────────────────────────────────────────────────────
output resourceGroup string = resourceGroup().name
output vmName string = vm.name
output vmPublicIp string = publicIp.properties.ipAddress
output functionAppName string = funcApp.name
output functionAppUrl string = 'https://${funcApp.properties.defaultHostName}'
output lawWorkspaceId string = law.properties.customerId
output openAiEndpoint string = openAi.properties.endpoint
output storageAccountName string = storageAccount.name
output staticWebsiteUrl string = 'https://${storageName}.z33.web.core.windows.net'
output nsgName string = nsg.name
