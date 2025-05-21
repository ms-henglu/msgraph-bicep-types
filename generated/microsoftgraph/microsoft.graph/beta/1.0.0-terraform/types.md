# Microsoft.Graph @ beta

## Resource Microsoft.Graph/applications@beta
* **Valid Scope(s)**: Unknown
### Properties
* **addIns**: [MicrosoftGraphAddIn](#microsoftgraphaddin)[]: Defines custom behavior that a consuming service can use to call an app in specific contexts. For example, applications that can render file streams can set the addIns property for its 'FileHandler' functionality. This lets services like Microsoft 365 call the application in the context of a document the user is working on.
* **api**: [MicrosoftGraphApiApplication](#microsoftgraphapiapplication): Specifies settings for an application that implements a web API.
* **apiVersion**: 'beta' (ReadOnly, DeployTimeConstant): The resource api version
* **appId**: string: The unique identifier for the application that is assigned to an application by Microsoft Entra ID. Not nullable. Read-only. Alternate key.
* **applicationTemplateId**: string: Unique identifier of the applicationTemplate. Read-only. null if the app wasn't created from an application template.
* **appRoles**: [MicrosoftGraphAppRole](#microsoftgraphapprole)[]: The collection of roles defined for the application. With app role assignments, these roles can be assigned to users, groups, or service principals associated with other applications. Not nullable.
* **authenticationBehaviors**: [MicrosoftGraphAuthenticationBehaviors](#microsoftgraphauthenticationbehaviors)
* **certification**: [MicrosoftGraphCertification](#microsoftgraphcertification): Specifies the certification status of the application.
* **createdDateTime**: string: The date and time the application was registered. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only.
* **defaultRedirectUri**: string
* **deletedDateTime**: string: Date and time when this object was deleted. Always null when the object hasn't been deleted.
* **description**: string: Free text field to provide a description of the application object to end users. The maximum allowed size is 1,024 characters.
* **disabledByMicrosoftStatus**: string: Specifies whether Microsoft has disabled the registered application. Possible values are: null (default value), NotDisabled, and DisabledDueToViolationOfServicesAgreement (reasons include suspicious, abusive, or malicious activity, or a violation of the Microsoft Services Agreement).
* **displayName**: string: The display name for the application. Maximum length is 256 characters.
* **groupMembershipClaims**: string: Configures the groups claim issued in a user or OAuth 2.0 access token that the application expects. To set this attribute, use one of the following valid string values: None, SecurityGroup (for security groups and Microsoft Entra roles), All (this gets all of the security groups, distribution groups, and Microsoft Entra directory roles that the signed-in user is a member of).
* **id**: string: The unique identifier for an entity. Read-only.
* **identifierUris**: string[]: Also known as App ID URI, this value is set when an application is used as a resource app. The identifierUris acts as the prefix for the scopes you reference in your API's code, and it must be globally unique. For more information on valid identifierUris patterns and best practices, see Microsoft Entra application registration security best practices. Not nullable.
* **info**: [MicrosoftGraphInformationalUrl](#microsoftgraphinformationalurl): Basic profile information of the application such as  app's marketing, support, terms of service and privacy statement URLs. The terms of service and privacy statement are surfaced to users through the user consent experience. For more info, see How to: Add Terms of service and privacy statement for registered Microsoft Entra apps.
* **isDeviceOnlyAuthSupported**: bool: Specifies whether this application supports device authentication without a user. The default is false.
* **isFallbackPublicClient**: bool: Specifies the fallback application type as public client, such as an installed application running on a mobile device. The default value is false, which means the fallback application type is confidential client such as a web app. There are certain scenarios where Microsoft Entra ID can't determine the client application type. For example, the ROPC flow where it's configured without specifying a redirect URI. In those cases, Microsoft Entra ID interprets the application type based on the value of this property.
* **keyCredentials**: [MicrosoftGraphKeyCredential](#microsoftgraphkeycredential)[]: The collection of key credentials associated with the application. Not nullable.
* **logo**: string: The main logo for the application. Not nullable.
* **nativeAuthenticationApisEnabled**: 'all' | 'none' | string: Specifies whether the Native Authentication APIs are enabled for the application. The possible values are: none and all. Default is none. For more information, see Native Authentication.
* **notes**: string: Notes relevant for the management of the application.
* **oauth2RequirePostResponse**: bool
* **optionalClaims**: [MicrosoftGraphOptionalClaims](#microsoftgraphoptionalclaims): Application developers can configure optional claims in their Microsoft Entra applications to specify the claims that are sent to their application by the Microsoft security token service. For more information, see How to: Provide optional claims to your app.
* **parentalControlSettings**: [MicrosoftGraphParentalControlSettings](#microsoftgraphparentalcontrolsettings): Specifies parental control settings for an application.
* **passwordCredentials**: [MicrosoftGraphPasswordCredential](#microsoftgraphpasswordcredential)[]: The collection of password credentials associated with the application. Not nullable.
* **publicClient**: [MicrosoftGraphPublicClientApplication](#microsoftgraphpublicclientapplication): Specifies settings for installed clients such as desktop or mobile devices.
* **publisherDomain**: string: The verified publisher domain for the application. Read-only. For more information, see How to: Configure an application's publisher domain.
* **requestSignatureVerification**: [MicrosoftGraphRequestSignatureVerification](#microsoftgraphrequestsignatureverification): Specifies whether this application requires Microsoft Entra ID to verify the signed authentication requests.
* **requiredResourceAccess**: [MicrosoftGraphRequiredResourceAccess](#microsoftgraphrequiredresourceaccess)[]: Specifies the resources that the application needs to access. This property also specifies the set of delegated permissions and application roles that it needs for each of those resources. This configuration of access to the required resources drives the consent experience. No more than 50 resource services (APIs) can be configured. Beginning mid-October 2021, the total number of required permissions must not exceed 400. For more information, see Limits on requested permissions per app. Not nullable.
* **samlMetadataUrl**: string: The URL where the service exposes SAML metadata for federation. This property is valid only for single-tenant applications. Nullable.
* **serviceManagementReference**: string: References application or service contact information from a Service or Asset Management database. Nullable.
* **servicePrincipalLockConfiguration**: [MicrosoftGraphServicePrincipalLockConfiguration](#microsoftgraphserviceprincipallockconfiguration): Specifies whether sensitive properties of a multitenant application should be locked for editing after the application is provisioned in a tenant. Nullable. null by default.
* **signInAudience**: string: Specifies the Microsoft accounts that are supported for the current application. The possible values are: AzureADMyOrg (default), AzureADMultipleOrgs, AzureADandPersonalMicrosoftAccount, and PersonalMicrosoftAccount. See more in the table. The value of this object also limits the number of permissions an app can request. For more information, see Limits on requested permissions per app. The value for this property has implications on other app object properties. As a result, if you change this property, you might need to change other properties first.
* **spa**: [MicrosoftGraphSpaApplication](#microsoftgraphspaapplication): Specifies settings for a single-page application, including sign out URLs and redirect URIs for authorization codes and access tokens.
* **tags**: string[]: Custom strings that can be used to categorize and identify the application. Not nullable.
* **tokenEncryptionKeyId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: Specifies the keyId of a public key from the keyCredentials collection. When configured, Microsoft Entra ID encrypts all the tokens it emits by using the key this property points to. The application code that receives the encrypted token must use the matching private key to decrypt the token before it can be used for the signed-in user.
* **type**: 'Microsoft.Graph/applications' (ReadOnly, DeployTimeConstant): The resource type
* **uniqueName**: string (Required, DeployTimeConstant, Identifier): The unique identifier that can be assigned to an application and used as an alternate key. Immutable.
* **verifiedPublisher**: [MicrosoftGraphVerifiedPublisher](#microsoftgraphverifiedpublisher): Specifies the verified publisher of the application. For more information about how publisher verification helps support application security, trustworthiness, and compliance, see Publisher verification.
* **web**: [MicrosoftGraphWebApplication](#microsoftgraphwebapplication): Specifies settings for a web application.

## Resource Microsoft.Graph/applications/federatedIdentityCredentials@beta
* **Valid Scope(s)**: Unknown
### Properties
* **apiVersion**: 'beta' (ReadOnly, DeployTimeConstant): The resource api version
* **audiences**: string[]: The audience that can appear in the external token. This field is mandatory and should be set to api://AzureADTokenExchange for Microsoft Entra ID. It says what Microsoft identity platform should accept in the aud claim in the incoming token. This value represents Microsoft Entra ID in your external identity provider and has no fixed value across identity providers - you might need to create a new application registration in your identity provider to serve as the audience of this token. This field can only accept a single value and has a limit of 600 characters. Required.
* **description**: string: The unvalidated description of the federated identity credential, provided by the user. It has a limit of 600 characters. Optional.
* **id**: string: The unique identifier for an entity. Read-only.
* **issuer**: string: The URL of the external identity provider, which must match the issuer claim of the external token being exchanged. The combination of the values of issuer and subject must be unique within the app. It has a limit of 600 characters. Required.
* **name**: string (Required, Identifier): The unique identifier for the federated identity credential, which has a limit of 120 characters and must be URL friendly. The string is immutable after it's created. Alternate key. Required. Not nullable.
* **subject**: string: Required. The identifier of the external software workload within the external identity provider. Like the audience value, it has no fixed format; each identity provider uses their own - sometimes a GUID, sometimes a colon delimited identifier, sometimes arbitrary strings. The value here must match the sub claim within the token presented to Microsoft Entra ID. The combination of issuer and subject must be unique within the app. It has a limit of 600 characters.
* **type**: 'Microsoft.Graph/applications/federatedIdentityCredentials' (ReadOnly, DeployTimeConstant): The resource type

## Resource Microsoft.Graph/appRoleAssignedTo@beta
* **Valid Scope(s)**: Unknown
### Properties
* **apiVersion**: 'beta' (ReadOnly, DeployTimeConstant): The resource api version
* **appRoleId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The identifier (id) for the app role that's assigned to the principal. This app role must be exposed in the appRoles property on the resource application's service principal (resourceId). If the resource application hasn't declared any app roles, a default app role ID of 00000000-0000-0000-0000-000000000000 can be specified to signal that the principal is assigned to the resource app without any specific app roles. Required on create.
* **createdDateTime**: string: The time when the app role assignment was created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only.
* **deletedDateTime**: string: Date and time when this object was deleted. Always null when the object hasn't been deleted.
* **id**: string: The unique identifier for an entity. Read-only.
* **principalDisplayName**: string: The display name of the user, group, or service principal that was granted the app role assignment. Maximum length is 256 characters. Read-only.
* **principalId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The unique identifier (id) for the user, security group, or service principal being granted the app role. Security groups with dynamic memberships are supported. Required on create.
* **principalType**: string: The type of the assigned principal. This can either be User, Group, or ServicePrincipal. Read-only.
* **resourceDisplayName**: string: The display name of the resource app's service principal to which the assignment is made. Maximum length is 256 characters.
* **resourceId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The unique identifier (id) for the resource service principal for which the assignment is made. Required on create.
* **type**: 'Microsoft.Graph/appRoleAssignedTo' (ReadOnly, DeployTimeConstant): The resource type

## Resource Microsoft.Graph/groups@beta
* **Valid Scope(s)**: Unknown
### Properties
* **allowExternalSenders**: bool: Indicates if people external to the organization can send messages to the group. The default value is false. Supported only on the Get group API (GET /groups/{ID}).
* **apiVersion**: 'beta' (ReadOnly, DeployTimeConstant): The resource api version
* **assignedLabels**: [MicrosoftGraphAssignedLabel](#microsoftgraphassignedlabel)[]: The list of sensitivity label pairs (label ID, label name) associated with a Microsoft 365 group. This property can be updated only in delegated scenarios where the caller requires both the Microsoft Graph permission and a supported administrator role.
* **assignedLicenses**: [MicrosoftGraphAssignedLicense](#microsoftgraphassignedlicense)[]: The licenses that are assigned to the group. Read-only.
* **autoSubscribeNewMembers**: bool: Indicates if new members added to the group are autosubscribed to receive email notifications. You can set this property in a PATCH request for the group; don't set it in the initial POST request that creates the group. Default value is false. Supported only on the Get group API (GET /groups/{ID}).
* **classification**: string: Describes a classification for the group (such as low, medium, or high business impact).
* **createdDateTime**: string: Timestamp of when the group was created. The value can't be modified and is automatically populated when the group is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on January 1, 2014 is 2014-01-01T00:00:00Z. Read-only.
* **deletedDateTime**: string: Date and time when this object was deleted. Always null when the object hasn't been deleted.
* **description**: string: An optional description for the group.
* **displayName**: string: The display name for the group. This property is required when a group is created and can't be cleared during updates. Maximum length is 256 characters.
* **expirationDateTime**: string: Timestamp of when the group is set to expire. It's null for security groups, but for Microsoft 365 groups, it represents when the group is set to expire as defined in the groupLifecyclePolicy. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on January 1, 2014 is 2014-01-01T00:00:00Z. Read-only.
* **groupTypes**: string[]: Specifies the group type and its membership. If the collection contains Unified, the group is a Microsoft 365 group; otherwise, it's either a security group or a distribution group. For details, see groups overview.If the collection includes DynamicMembership, the group has dynamic membership; otherwise, membership is static.
* **hasMembersWithLicenseErrors**: bool: Indicates whether there are members in this group that have license errors from its group-based license assignment. This property is never returned on a GET operation. See an example.
* **hideFromAddressLists**: bool: True if the group isn't displayed in certain parts of the Outlook UI: the Address Book, address lists for selecting message recipients, and the Browse Groups dialog for searching groups; otherwise, false. The default value is false. Supported only on the Get group API (GET /groups/{ID}).
* **hideFromOutlookClients**: bool: True if the group isn't displayed in Outlook clients, such as Outlook for Windows and Outlook on the web; otherwise, false. The default value is false. Supported only on the Get group API (GET /groups/{ID}).
* **id**: string: The unique identifier for an entity. Read-only.
* **isArchived**: bool: When a group is associated with a team, this property determines whether the team is in read-only mode.To read this property, use the /group/{groupId}/team endpoint or the Get team API. To update this property, use the archiveTeam and unarchiveTeam APIs.
* **isAssignableToRole**: bool: Indicates whether this group can be assigned to a Microsoft Entra role. Optional. This property can only be set while creating the group and is immutable. If set to true, the securityEnabled property must also be set to true, visibility must be Hidden, and the group can't be a dynamic group (that is, groupTypes can't contain DynamicMembership). Only callers with at least the Privileged Role Administrator role can set this property. The caller must also be assigned the RoleManagement.ReadWrite.Directory permission to set this property or update the membership of such groups. For more, see Using a group to manage Microsoft Entra role assignmentsUsing this feature requires a Microsoft Entra ID P1 license.
* **isManagementRestricted**: bool
* **isSubscribedByMail**: bool: Indicates whether the signed-in user is subscribed to receive email conversations. The default value is true. Supported only on the Get group API (GET /groups/{ID}).
* **licenseProcessingState**: [MicrosoftGraphLicenseProcessingState](#microsoftgraphlicenseprocessingstate): Indicates the status of the group license assignment to all group members. The default value is false. Read-only. Read-only.
* **mail**: string: The SMTP address for the group, for example, 'serviceadmins@contoso.com'. Read-only.
* **mailEnabled**: bool: Specifies whether the group is mail-enabled. Required.
* **mailNickname**: string: The mail alias for the group, unique for Microsoft 365 groups in the organization. Maximum length is 64 characters. This property can contain only characters in the ASCII character set 0 - 127 except the following characters: @ () / [] ' ; : <> , SPACE. Required.
* **membershipRule**: string: The rule that determines members for this group if the group is a dynamic group (groupTypes contains DynamicMembership). For more information about the syntax of the membership rule, see Membership Rules syntax.
* **membershipRuleProcessingState**: string: Indicates whether the dynamic membership processing is on or paused. Possible values are On or Paused.
* **onPremisesDomainName**: string: Contains the on-premises domain FQDN, also called dnsDomainName synchronized from the on-premises directory. Read-only.
* **onPremisesLastSyncDateTime**: string: Indicates the last time at which the group was synced with the on-premises directory. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on January 1, 2014 is 2014-01-01T00:00:00Z. Read-only.
* **onPremisesNetBiosName**: string: Contains the on-premises netBios name synchronized from the on-premises directory. Read-only.
* **onPremisesProvisioningErrors**: [MicrosoftGraphOnPremisesProvisioningError](#microsoftgraphonpremisesprovisioningerror)[]: Errors when using Microsoft synchronization product during provisioning.
* **onPremisesSamAccountName**: string: Contains the on-premises SAM account name synchronized from the on-premises directory. Read-only.
* **onPremisesSecurityIdentifier**: string: Contains the on-premises security identifier (SID) for the group synchronized from on-premises to the cloud. Read-only.
* **onPremisesSyncEnabled**: bool: true if this group is synced from an on-premises directory; false if this group was originally synced from an on-premises directory but is no longer synced; null if this object has never synced from an on-premises directory (default). Read-only.
* **preferredDataLocation**: string: The preferred data location for the Microsoft 365 group. By default, the group inherits the group creator's preferred data location. To set this property, the calling app must be granted the Directory.ReadWrite.All permission and the user be assigned at least one of the following Microsoft Entra roles: User Account Administrator Directory Writer  Exchange Administrator  SharePoint Administrator  For more information about this property, see OneDrive Online Multi-Geo. Nullable.
* **preferredLanguage**: string: The preferred language for a Microsoft 365 group. Should follow ISO 639-1 Code; for example, en-US.
* **proxyAddresses**: string[]: Email addresses for the group that direct to the same group mailbox. For example: ['SMTP: bob@contoso.com', 'smtp: bob@sales.contoso.com']. The any operator is required to filter expressions on multi-valued properties. Read-only. Not nullable.
* **renewedDateTime**: string: Timestamp of when the group was last renewed. This value can't be modified directly and is only updated via the renew service action. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on January 1, 2014 is 2014-01-01T00:00:00Z. Read-only.
* **securityEnabled**: bool: Specifies whether the group is a security group. Required.
* **securityIdentifier**: string: Security identifier of the group, used in Windows scenarios. Read-only.
* **serviceProvisioningErrors**: [MicrosoftGraphServiceProvisioningError](#microsoftgraphserviceprovisioningerror)[]: Errors published by a federated service describing a nontransient, service-specific error regarding the properties or link from a group object.
* **theme**: string: Specifies a Microsoft 365 group's color theme. Possible values are Teal, Purple, Green, Blue, Pink, Orange, or Red.
* **type**: 'Microsoft.Graph/groups' (ReadOnly, DeployTimeConstant): The resource type
* **uniqueName**: string (Required, DeployTimeConstant, Identifier): The unique identifier that can be assigned to a group and used as an alternate key. Immutable.
* **unseenCount**: int: Count of conversations that received new posts since the signed-in user last visited the group. Supported only on the Get group API (GET /groups/{ID}).
* **visibility**: string: Specifies the group join policy and group content visibility for groups. Possible values are: Private, Public, or HiddenMembership. HiddenMembership can be set only for Microsoft 365 groups when the groups are created. It can't be updated later. Other values of visibility can be updated after group creation. If visibility value isn't specified during group creation on Microsoft Graph, a security group is created as Private by default, and the Microsoft 365 group is Public. Groups assignable to roles are always Private. To learn more, see group visibility options. Nullable.

## Resource Microsoft.Graph/oauth2PermissionGrants@beta
* **Valid Scope(s)**: Unknown
### Properties
* **apiVersion**: 'beta' (ReadOnly, DeployTimeConstant): The resource api version
* **clientId**: string: The object id (not appId) of the client service principal for the application that's authorized to act on behalf of a signed-in user when accessing an API. Required.
* **consentType**: string: Indicates if authorization is granted for the client application to impersonate all users or only a specific user. AllPrincipals indicates authorization to impersonate all users. Principal indicates authorization to impersonate a specific user. Consent on behalf of all users can be granted by an administrator. Nonadmin users might be authorized to consent on behalf of themselves in some cases, for some delegated permissions. Required.
* **id**: string: The unique identifier for an entity. Read-only.
* **principalId**: string: The id of the user on behalf of whom the client is authorized to access the resource, when consentType is Principal. If consentType is AllPrincipals this value is null. Required when consentType is Principal.
* **resourceId**: string: The id of the resource service principal to which access is authorized. This identifies the API that the client is authorized to attempt to call on behalf of a signed-in user.
* **scope**: string: A space-separated list of the claim values for delegated permissions that should be included in access tokens for the resource application (the API). For example, openid User.Read GroupMember.Read.All. Each claim value should match the value field of one of the delegated permissions defined by the API, listed in the oauth2PermissionScopes property of the resource service principal. Must not exceed 3,850 characters in length.
* **type**: 'Microsoft.Graph/oauth2PermissionGrants' (ReadOnly, DeployTimeConstant): The resource type

## Resource Microsoft.Graph/servicePrincipals@beta
* **Valid Scope(s)**: Unknown
### Properties
* **accountEnabled**: bool: true if the service principal account is enabled; otherwise, false. If set to false, then no users are able to sign in to this app, even if they're assigned to it.
* **addIns**: [MicrosoftGraphAddIn](#microsoftgraphaddin)[]: Defines custom behavior that a consuming service can use to call an app in specific contexts. For example, applications that can render file streams may set the addIns property for its 'FileHandler' functionality. This lets services like Microsoft 365 call the application in the context of a document the user is working on.
* **alternativeNames**: string[]: Used to retrieve service principals by subscription, identify resource group and full resource IDs for managed identities.
* **apiVersion**: 'beta' (ReadOnly, DeployTimeConstant): The resource api version
* **appDescription**: string: The description exposed by the associated application.
* **appDisplayName**: string: The display name exposed by the associated application. Maximum length is 256 characters.
* **appId**: string (Required, Identifier): The unique identifier for the associated application (its appId property). Alternate key.
* **applicationTemplateId**: string: Unique identifier of the applicationTemplate. Read-only. null if the service principal wasn't created from an application template.
* **appOwnerOrganizationId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: Contains the tenant ID where the application is registered. This is applicable only to service principals backed by applications.
* **appRoleAssignmentRequired**: bool: Specifies whether users or other service principals need to be granted an app role assignment for this service principal before users can sign in or apps can get tokens. The default value is false. Not nullable.
* **appRoles**: [MicrosoftGraphAppRole](#microsoftgraphapprole)[]: The roles exposed by the application that's linked to this service principal. For more information, see the appRoles property definition on the application entity. Not nullable.
* **customSecurityAttributes**: any: An open complex type that holds the value of a custom security attribute that is assigned to a directory object. Nullable. Filter value is case sensitive. To read this property, the calling app must be assigned the CustomSecAttributeAssignment.Read.All permission. To write this property, the calling app must be assigned the CustomSecAttributeAssignment.ReadWrite.All permissions. To read or write this property in delegated scenarios, the admin must be assigned the Attribute Assignment Administrator role.
* **deletedDateTime**: string: Date and time when this object was deleted. Always null when the object hasn't been deleted.
* **description**: string: Free text field to provide an internal end-user facing description of the service principal. End-user portals such MyApps displays the application description in this field. The maximum allowed size is 1,024 characters.
* **disabledByMicrosoftStatus**: string: Specifies whether Microsoft has disabled the registered application. Possible values are: null (default value), NotDisabled, and DisabledDueToViolationOfServicesAgreement (reasons include suspicious, abusive, or malicious activity, or a violation of the Microsoft Services Agreement).
* **displayName**: string: The display name for the service principal.
* **homepage**: string: Home page or landing page of the application.
* **id**: string: The unique identifier for an entity. Read-only.
* **info**: [MicrosoftGraphInformationalUrl](#microsoftgraphinformationalurl): Basic profile information of the acquired application such as app's marketing, support, terms of service and privacy statement URLs. The terms of service and privacy statement are surfaced to users through the user consent experience. For more info, see How to: Add Terms of service and privacy statement for registered Microsoft Entra apps.
* **keyCredentials**: [MicrosoftGraphKeyCredential](#microsoftgraphkeycredential)[]: The collection of key credentials associated with the service principal. Not nullable.
* **loginUrl**: string: Specifies the URL where the service provider redirects the user to Microsoft Entra ID to authenticate. Microsoft Entra ID uses the URL to launch the application from Microsoft 365 or the Microsoft Entra My Apps. When blank, Microsoft Entra ID performs IdP-initiated sign-on for applications configured with SAML-based single sign-on. The user launches the application from Microsoft 365, the Microsoft Entra My Apps, or the Microsoft Entra SSO URL.
* **logoutUrl**: string: Specifies the URL that the Microsoft's authorization service uses to sign out a user using OpenID Connect front-channel, back-channel, or SAML sign out protocols.
* **notes**: string: Free text field to capture information about the service principal, typically used for operational purposes. Maximum allowed size is 1,024 characters.
* **notificationEmailAddresses**: string[]: Specifies the list of email addresses where Microsoft Entra ID sends a notification when the active certificate is near the expiration date. This is only for the certificates used to sign the SAML token issued for Microsoft Entra Gallery applications.
* **oauth2PermissionScopes**: [MicrosoftGraphPermissionScope](#microsoftgraphpermissionscope)[]: The delegated permissions exposed by the application. For more information, see the oauth2PermissionScopes property on the application entity's api property. Not nullable.
* **passwordCredentials**: [MicrosoftGraphPasswordCredential](#microsoftgraphpasswordcredential)[]: The collection of password credentials associated with the application. Not nullable.
* **preferredSingleSignOnMode**: string: Specifies the single sign-on mode configured for this application. Microsoft Entra ID uses the preferred single sign-on mode to launch the application from Microsoft 365 or the My Apps portal. The supported values are password, saml, notSupported, and oidc. Note: This field might be null for older SAML apps and for OIDC applications where it isn't set automatically.
* **preferredTokenSigningKeyThumbprint**: string: This property can be used on SAML applications (apps that have preferredSingleSignOnMode set to saml) to control which certificate is used to sign the SAML responses. For applications that aren't SAML, don't write or otherwise rely on this property.
* **replyUrls**: string[]: The URLs that user tokens are sent to for sign in with the associated application, or the redirect URIs that OAuth 2.0 authorization codes and access tokens are sent to for the associated application. Not nullable.
* **resourceSpecificApplicationPermissions**: [MicrosoftGraphResourceSpecificPermission](#microsoftgraphresourcespecificpermission)[]: The resource-specific application permissions exposed by this application. Currently, resource-specific permissions are only supported for Teams apps accessing to specific chats and teams using Microsoft Graph. Read-only.
* **samlSingleSignOnSettings**: [MicrosoftGraphSamlSingleSignOnSettings](#microsoftgraphsamlsinglesignonsettings): The collection for settings related to saml single sign-on.
* **servicePrincipalNames**: string[]: Contains the list of identifiersUris, copied over from the associated application. Additional values can be added to hybrid applications. These values can be used to identify the permissions exposed by this app within Microsoft Entra ID. For example,Client apps can specify a resource URI that is based on the values of this property to acquire an access token, which is the URI returned in the 'aud' claim.The any operator is required for filter expressions on multi-valued properties. Not nullable.
* **servicePrincipalType**: string: Identifies whether the service principal represents an application, a managed identity, or a legacy application. This is set by Microsoft Entra ID internally. The servicePrincipalType property can be set to three different values: Application - A service principal that represents an application or service. The appId property identifies the associated app registration, and matches the appId of an application, possibly from a different tenant. If the associated app registration is missing, tokens aren't issued for the service principal.ManagedIdentity - A service principal that represents a managed identity. Service principals representing managed identities can be granted access and permissions, but can't be updated or modified directly.Legacy - A service principal that represents an app created before app registrations, or through legacy experiences. A legacy service principal can have credentials, service principal names, reply URLs, and other properties that are editable by an authorized user, but doesn't have an associated app registration. The appId value doesn't associate the service principal with an app registration. The service principal can only be used in the tenant where it was created.SocialIdp - For internal use.
* **signInAudience**: string: Specifies the Microsoft accounts that are supported for the current application. Read-only. Supported values are:AzureADMyOrg: Users with a Microsoft work or school account in my organization's Microsoft Entra tenant (single-tenant).AzureADMultipleOrgs: Users with a Microsoft work or school account in any organization's Microsoft Entra tenant (multitenant).AzureADandPersonalMicrosoftAccount: Users with a personal Microsoft account, or a work or school account in any organization's Microsoft Entra tenant.PersonalMicrosoftAccount: Users with a personal Microsoft account only.
* **tags**: string[]: Custom strings that can be used to categorize and identify the service principal. Not nullable.
* **tokenEncryptionKeyId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: Specifies the keyId of a public key from the keyCredentials collection. When configured, Microsoft Entra ID issues tokens for this application encrypted using the key specified by this property. The application code that receives the encrypted token must use the matching private key to decrypt the token before it can be used for the signed-in user.
* **type**: 'Microsoft.Graph/servicePrincipals' (ReadOnly, DeployTimeConstant): The resource type
* **verifiedPublisher**: [MicrosoftGraphVerifiedPublisher](#microsoftgraphverifiedpublisher): Specifies the verified publisher of the application that's linked to this service principal.

## Resource Microsoft.Graph/users@beta
* **Valid Scope(s)**: Unknown
### Properties
* **aboutMe**: string: A freeform text entry field for the user to describe themselves.
* **accountEnabled**: bool: true if the account is enabled; otherwise, false. This property is required when a user is created.
* **ageGroup**: string: Sets the age group of the user. Allowed values: null, Minor, NotAdult, and Adult. For more information, see legal age group property definitions.
* **apiVersion**: 'beta' (ReadOnly, DeployTimeConstant): The resource api version
* **assignedLicenses**: [MicrosoftGraphAssignedLicense](#microsoftgraphassignedlicense)[]: The licenses that are assigned to the user, including inherited (group-based) licenses. This property doesn't differentiate between directly assigned and inherited licenses. Use the licenseAssignmentStates property to identify the directly assigned and inherited licenses. Not nullable.
* **assignedPlans**: [MicrosoftGraphAssignedPlan](#microsoftgraphassignedplan)[]: The plans that are assigned to the user. Read-only. Not nullable.
* **authorizationInfo**: [MicrosoftGraphAuthorizationInfo](#microsoftgraphauthorizationinfo)
* **birthday**: string: The birthday of the user. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014, is 2014-01-01T00:00:00Z.
* **businessPhones**: string[]: The telephone numbers for the user. NOTE: Although it's a string collection, only one number can be set for this property. Read-only for users synced from the on-premises directory.
* **city**: string: The city where the user is located. Maximum length is 128 characters.
* **companyName**: string: The name of the company that the user is associated with. This property can be useful for describing the company that a guest comes from.
* **consentProvidedForMinor**: string: Sets whether consent was obtained for minors. Allowed values: null, Granted, Denied, and NotRequired. For more information, see legal age group property definitions.
* **country**: string: The country or region where the user is located; for example, US or UK. Maximum length is 128 characters.
* **createdDateTime**: string: The date and time the user was created, in ISO 8601 format and UTC. The value can't be modified and is automatically populated when the entity is created. Nullable. For on-premises users, the value represents when they were first created in Microsoft Entra ID. Property is null for some users created before June 2018 and on-premises users that were synced to Microsoft Entra ID before June 2018. Read-only.
* **creationType**: string: Indicates whether the user account was created through one of the following methods:  As a regular school or work account (null). As an external account (Invitation). As a local account for an Azure Active Directory B2C tenant (LocalAccount). Through self-service sign-up by an internal user using email verification (EmailVerified). Through self-service sign-up by a guest signing up through a link that is part of a user flow (SelfServiceSignUp).
* **customSecurityAttributes**: any: An open complex type that holds the value of a custom security attribute that is assigned to a directory object. Nullable. The filter value is case-sensitive. To read this property, the calling app must be assigned the CustomSecAttributeAssignment.Read.All permission. To write this property, the calling app must be assigned the CustomSecAttributeAssignment.ReadWrite.All permissions. To read or write this property in delegated scenarios, the admin must be assigned the Attribute Assignment Administrator role.
* **deletedDateTime**: string: Date and time when this object was deleted. Always null when the object hasn't been deleted.
* **department**: string: The name of the department in which the user works. Maximum length is 64 characters.
* **deviceEnrollmentLimit**: int: The limit on the maximum number of devices that the user is permitted to enroll. Allowed values are 5 or 1000.
* **displayName**: string: The name displayed in the address book for the user. This value is usually the combination of the user's first name, middle initial, and family name. This property is required when a user is created and it can't be cleared during updates. Maximum length is 256 characters.
* **employeeHireDate**: string: The date and time when the user was hired or will start work in a future hire.
* **employeeId**: string: The employee identifier assigned to the user by the organization. The maximum length is 16 characters.
* **employeeLeaveDateTime**: string: The date and time when the user left or will leave the organization. To read this property, the calling app must be assigned the User-LifeCycleInfo.Read.All permission. To write this property, the calling app must be assigned the User.Read.All and User-LifeCycleInfo.ReadWrite.All permissions. To read this property in delegated scenarios, the admin needs at least one of the following Microsoft Entra roles: Lifecycle Workflows Administrator (least privilege), Global Reader. To write this property in delegated scenarios, the admin needs the Global Administrator role. For more information, see Configure the employeeLeaveDateTime property for a user.
* **employeeOrgData**: [MicrosoftGraphEmployeeOrgData](#microsoftgraphemployeeorgdata): Represents organization data (for example, division and costCenter) associated with a user.
* **employeeType**: string: Captures enterprise worker type. For example, Employee, Contractor, Consultant, or Vendor.
* **externalUserState**: string: For a guest invited to the tenant using the invitation API, this property represents the invited user's invitation status. For invited users, the state can be PendingAcceptance or Accepted, or null for all other users.
* **externalUserStateChangeDateTime**: string: Shows the timestamp for the latest change to the externalUserState property.
* **faxNumber**: string: The fax number of the user.
* **givenName**: string: The given name (first name) of the user. Maximum length is 64 characters.
* **hireDate**: string: The hire date of the user. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014, is 2014-01-01T00:00:00Z. Note: This property is specific to SharePoint in Microsoft 365. We recommend using the native employeeHireDate property to set and update hire date values using Microsoft Graph APIs.
* **id**: string: The unique identifier for an entity. Read-only.
* **identities**: [MicrosoftGraphObjectIdentity](#microsoftgraphobjectidentity)[]: Represents the identities that can be used to sign in to this user account. Microsoft (also known as a local account), organizations, or social identity providers such as Facebook, Google, and Microsoft can provide identity and tie it to a user account. It might contain multiple items with the same signInType value.
* **imAddresses**: string[]: The instant message voice-over IP (VOIP) session initiation protocol (SIP) addresses for the user. Read-only.
* **interests**: string[]: A list for the user to describe their interests.
* **isManagementRestricted**: bool
* **isResourceAccount**: bool: Don't use – reserved for future use.
* **jobTitle**: string: The user's job title. Maximum length is 128 characters.
* **lastPasswordChangeDateTime**: string: The time when this Microsoft Entra user last changed their password or when their password was created, whichever date the latest action was performed. The date and time information uses ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
* **legalAgeGroupClassification**: string: Used by enterprise applications to determine the legal age group of the user. This property is read-only and calculated based on ageGroup and consentProvidedForMinor properties. Allowed values: null, Undefined,  MinorWithOutParentalConsent, MinorWithParentalConsent, MinorNoParentalConsentRequired, NotAdult, and Adult. For more information, see legal age group property definitions.
* **licenseAssignmentStates**: [MicrosoftGraphLicenseAssignmentState](#microsoftgraphlicenseassignmentstate)[]: State of license assignments for this user. Also indicates licenses that are directly assigned or the user inherited through group memberships. Read-only.
* **mail**: string: The SMTP address for the user, for example, jeff@contoso.com. Changes to this property update the user's proxyAddresses collection to include the value as an SMTP address. This property can't contain accent characters. NOTE: We don't recommend updating this property for Azure AD B2C user profiles. Use the otherMails property instead.
* **mailboxSettings**: [MicrosoftGraphMailboxSettings](#microsoftgraphmailboxsettings): Settings for the primary mailbox of the signed-in user. You can get or update settings for sending automatic replies to incoming messages, locale, and time zone.
* **mailNickname**: string: The mail alias for the user. This property must be specified when a user is created. Maximum length is 64 characters.
* **mobilePhone**: string: The primary cellular telephone number for the user. Read-only for users synced from the on-premises directory. Maximum length is 64 characters.
* **mySite**: string: The URL for the user's site.
* **officeLocation**: string: The office location in the user's place of business.
* **onPremisesDistinguishedName**: string: Contains the on-premises Active Directory distinguished name or DN. The property is only populated for customers who are synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect. Read-only.
* **onPremisesDomainName**: string: Contains the on-premises domainFQDN, also called dnsDomainName synchronized from the on-premises directory. The property is only populated for customers who are synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect. Read-only.
* **onPremisesExtensionAttributes**: [MicrosoftGraphOnPremisesExtensionAttributes](#microsoftgraphonpremisesextensionattributes): Contains extensionAttributes1-15 for the user. These extension attributes are also known as Exchange custom attributes 1-15. Each attribute can store up to 1024 characters. For an onPremisesSyncEnabled user, the source of authority for this set of properties is the on-premises and is read-only. For a cloud-only user (where onPremisesSyncEnabled is false), these properties can be set during the creation or update of a user object. For a cloud-only user previously synced from on-premises Active Directory, these properties are read-only in Microsoft Graph but can be fully managed through the Exchange Admin Center or the Exchange Online V2 module in PowerShell.
* **onPremisesImmutableId**: string: This property is used to associate an on-premises Active Directory user account to their Microsoft Entra user object. This property must be specified when creating a new user account in the Graph if you're using a federated domain for the user's userPrincipalName (UPN) property. NOTE: The $ and _ characters can't be used when specifying this property.
* **onPremisesLastSyncDateTime**: string: Indicates the last time at which the object was synced with the on-premises directory; for example: 2013-02-16T03:04:54Z. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Read-only.
* **onPremisesProvisioningErrors**: [MicrosoftGraphOnPremisesProvisioningError](#microsoftgraphonpremisesprovisioningerror)[]: Errors when using Microsoft synchronization product during provisioning.
* **onPremisesSamAccountName**: string: Contains the on-premises samAccountName synchronized from the on-premises directory. The property is only populated for customers who are synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect. Read-only.
* **onPremisesSecurityIdentifier**: string: Contains the on-premises security identifier (SID) for the user that was synchronized from on-premises to the cloud. Read-only.
* **onPremisesSyncEnabled**: bool: true if this user object is currently being synced from an on-premises Active Directory (AD); otherwise the user isn't being synced and can be managed in Microsoft Entra ID. Read-only.
* **onPremisesUserPrincipalName**: string: Contains the on-premises userPrincipalName synchronized from the on-premises directory. The property is only populated for customers who are synchronizing their on-premises directory to Microsoft Entra ID via Microsoft Entra Connect. Read-only.
* **otherMails**: string[]: A list of other email addresses for the user; for example: ['bob@contoso.com', 'Robert@fabrikam.com']. Can store up to 250 values, each with a limit of 250 characters. NOTE: This property can't contain accent characters.
* **passwordPolicies**: string: Specifies password policies for the user. This value is an enumeration with one possible value being DisableStrongPassword, which allows weaker passwords than the default policy to be specified. DisablePasswordExpiration can also be specified. The two might be specified together; for example: DisablePasswordExpiration, DisableStrongPassword. For more information on the default password policies, see Microsoft Entra password policies.
* **passwordProfile**: [MicrosoftGraphPasswordProfile](#microsoftgraphpasswordprofile): Specifies the password profile for the user. The profile contains the user's password. This property is required when a user is created. The password in the profile must satisfy minimum requirements as specified by the passwordPolicies property. By default, a strong password is required. To update this property:  User-PasswordProfile.ReadWrite.All is the least privileged permission to update this property. In delegated scenarios, the User Administrator Microsoft Entra role is the least privileged admin role supported to update this property for nonadmin users. Privileged Authentication Administrator is the least privileged role that's allowed to update this property for all administrators in the tenant. In general, the signed-in user must have a higher privileged administrator role as indicated in Who can reset passwords. In app-only scenarios, the calling app must be assigned a supported permission and at least the User Administrator Microsoft Entra role.
* **pastProjects**: string[]: A list for the user to enumerate their past projects.
* **postalCode**: string: The postal code for the user's postal address. The postal code is specific to the user's country or region. In the United States of America, this attribute contains the ZIP code. Maximum length is 40 characters.
* **preferredDataLocation**: string: The preferred data location for the user. For more information, see OneDrive Online Multi-Geo.
* **preferredLanguage**: string: The preferred language for the user. The preferred language format is based on RFC 4646. The name is a combination of an ISO 639 two-letter lowercase culture code associated with the language, and an ISO 3166 two-letter uppercase subculture code associated with the country or region. Example: 'en-US', or 'es-ES'.
* **preferredName**: string: The preferred name for the user. Not Supported.
* **print**: any: Any object
* **provisionedPlans**: [MicrosoftGraphProvisionedPlan](#microsoftgraphprovisionedplan)[]: The plans that are provisioned for the user. Read-only. Not nullable.
* **proxyAddresses**: string[]: For example: ['SMTP: bob@contoso.com', 'smtp: bob@sales.contoso.com']. Changes to the mail property update this collection to include the value as an SMTP address. For more information, see mail and proxyAddresses properties. The proxy address prefixed with SMTP (capitalized) is the primary proxy address, while those addresses prefixed with smtp are the secondary proxy addresses. For Azure AD B2C accounts, this property has a limit of 10 unique addresses. Read-only in Microsoft Graph; you can update this property only through the Microsoft 365 admin center. Not nullable.
* **responsibilities**: string[]: A list for the user to enumerate their responsibilities.
* **schools**: string[]: A list for the user to enumerate the schools they attended.
* **securityIdentifier**: string: Security identifier (SID) of the user, used in Windows scenarios. Read-only.
* **serviceProvisioningErrors**: [MicrosoftGraphServiceProvisioningError](#microsoftgraphserviceprovisioningerror)[]: Errors published by a federated service describing a nontransient, service-specific error regarding the properties or link from a user object.
* **showInAddressList**: bool: Do not use in Microsoft Graph. Manage this property through the Microsoft 365 admin center instead. Represents whether the user should be included in the Outlook global address list. See Known issue.
* **signInActivity**: [MicrosoftGraphSignInActivity](#microsoftgraphsigninactivity): Get the last signed-in date and request ID of the sign-in for a given user. Note: Details for this property require a Microsoft Entra ID P1 or P2 license and the AuditLog.Read.All permission.This property isn't returned for a user who never signed in or last signed in before April 2020.
* **signInSessionsValidFromDateTime**: string: Any refresh tokens or session tokens (session cookies) issued before this time are invalid. Applications get an error when using an invalid refresh or session token to acquire a delegated access token (to access APIs such as Microsoft Graph). If this happens, the application needs to acquire a new refresh token by requesting the authorized endpoint. Read-only. Use revokeSignInSessions to reset.
* **skills**: string[]: A list for the user to enumerate their skills.
* **state**: string: The state or province in the user's address. Maximum length is 128 characters.
* **streetAddress**: string: The street address of the user's place of business. Maximum length is 1,024 characters.
* **surname**: string: The user's surname (family name or last name). Maximum length is 64 characters.
* **type**: 'Microsoft.Graph/users' (ReadOnly, DeployTimeConstant): The resource type
* **usageLocation**: string: A two-letter country code (ISO standard 3166). Required for users that are assigned licenses due to legal requirements to check for availability of services in countries/regions. Examples include: US, JP, and GB. Not nullable.
* **userPrincipalName**: string (Required, DeployTimeConstant, Identifier): The user principal name (UPN) of the user. The UPN is an Internet-style sign-in name for the user based on the Internet standard RFC 822. By convention, this value should map to the user's email name. The general format is alias@domain, where the domain must be present in the tenant's collection of verified domains. This property is required when a user is created. The verified domains for the tenant can be accessed from the verifiedDomains property of organization.NOTE: This property can't contain accent characters. Only the following characters are allowed A - Z, a - z, 0 - 9, '. - _ ! # ^ ~. For the complete list of allowed characters, see username policies.
* **userType**: string: A string value that can be used to classify user types in your directory. The possible values are Member and Guest. NOTE: For more information about the permissions for members and guests, see What are the default user permissions in Microsoft Entra ID?.

## MicrosoftGraphAddIn
### Properties
* **id**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The unique identifier for the addIn object.
* **properties**: [MicrosoftGraphKeyValue](#microsoftgraphkeyvalue)[]: The collection of key-value pairs that define parameters that the consuming service can use or call. You must specify this property when performing a POST or a PATCH operation on the addIns collection. Required.
* **type**: string: The unique name for the functionality exposed by the app.

## MicrosoftGraphApiApplication
### Properties
* **acceptMappedClaims**: bool: When true, allows an application to use claims mapping without specifying a custom signing key.
* **knownClientApplications**: (string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"})[]: Used for bundling consent if you have a solution that contains two parts: a client app and a custom web API app. If you set the appID of the client app to this value, the user only consents once to the client app. Microsoft Entra ID knows that consenting to the client means implicitly consenting to the web API and automatically provisions service principals for both APIs at the same time. Both the client and the web API app must be registered in the same tenant.
* **oauth2PermissionScopes**: [MicrosoftGraphPermissionScope](#microsoftgraphpermissionscope)[]: The definition of the delegated permissions exposed by the web API represented by this application registration. These delegated permissions may be requested by a client application, and may be granted by users or administrators during consent. Delegated permissions are sometimes referred to as OAuth 2.0 scopes.
* **preAuthorizedApplications**: [MicrosoftGraphPreAuthorizedApplication](#microsoftgraphpreauthorizedapplication)[]: Lists the client applications that are preauthorized with the specified delegated permissions to access this application's APIs. Users aren't required to consent to any preauthorized application (for the permissions specified). However, any other permissions not listed in preAuthorizedApplications (requested through incremental consent for example) will require user consent.
* **requestedAccessTokenVersion**: int: Specifies the access token version expected by this resource. This changes the version and format of the JWT produced independent of the endpoint or client used to request the access token. The endpoint used, v1.0 or v2.0, is chosen by the client and only impacts the version of id_tokens. Resources need to explicitly configure requestedAccessTokenVersion to indicate the supported access token format. Possible values for requestedAccessTokenVersion are 1, 2, or null. If the value is null, this defaults to 1, which corresponds to the v1.0 endpoint. If signInAudience on the application is configured as AzureADandPersonalMicrosoftAccount or PersonalMicrosoftAccount, the value for this property must be 2.

## MicrosoftGraphAppRole
### Properties
* **allowedMemberTypes**: string[]: Specifies whether this app role can be assigned to users and groups (by setting to ['User']), to other application's (by setting to ['Application'], or both (by setting to ['User', 'Application']). App roles supporting assignment to other applications' service principals are also known as application permissions. The 'Application' value is only supported for app roles defined on application entities.
* **description**: string: The description for the app role. This is displayed when the app role is being assigned and, if the app role functions as an application permission, during  consent experiences.
* **displayName**: string: Display name for the permission that appears in the app role assignment and consent experiences.
* **id**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: Unique role identifier inside the appRoles collection. When creating a new app role, a new GUID identifier must be provided.
* **isEnabled**: bool: When creating or updating an app role, this must be set to true (which is the default). To delete a role, this must first be set to false. At that point, in a subsequent call, this role may be removed.
* **origin**: string: Specifies if the app role is defined on the application object or on the servicePrincipal entity. Must not be included in any POST or PATCH requests. Read-only.
* **value**: string: Specifies the value to include in the roles claim in ID tokens and access tokens authenticating an assigned user or service principal. Must not exceed 120 characters in length. Allowed characters are : ! # $ % & ' ( ) * + , -. / : ;  =  ? @ [ ] ^ + _  {  } ~, and characters in the ranges 0-9, A-Z and a-z. Any other character, including the space character, aren't allowed. May not begin with ..

## MicrosoftGraphAssignedLabel
### Properties
* **displayName**: string: The display name of the label. Read-only.
* **labelId**: string: The unique identifier of the label.

## MicrosoftGraphAssignedLicense
### Properties
* **disabledPlans**: (string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"})[]: A collection of the unique identifiers for plans that have been disabled. IDs are available in servicePlans > servicePlanId in the tenant's subscribedSkus or serviceStatus > servicePlanId in the tenant's companySubscription.
* **skuId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The unique identifier for the SKU. Corresponds to the skuId from subscribedSkus or companySubscription.

## MicrosoftGraphAssignedPlan
### Properties
* **assignedDateTime**: string: The date and time at which the plan was assigned. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
* **capabilityStatus**: string: Condition of the capability assignment. The possible values are Enabled, Warning, Suspended, Deleted, LockedOut. See a detailed description of each value.
* **service**: string: The name of the service; for example, exchange.
* **servicePlanId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: A GUID that identifies the service plan. For a complete list of GUIDs and their equivalent friendly service names, see Product names and service plan identifiers for licensing.

## MicrosoftGraphAuthenticationBehaviors
### Properties
* **blockAzureADGraphAccess**: bool
* **removeUnverifiedEmailClaim**: bool
* **requireClientServicePrincipal**: bool

## MicrosoftGraphAuthorizationInfo
### Properties
* **certificateUserIds**: string[]

## MicrosoftGraphAutomaticRepliesSetting
### Properties
* **externalAudience**: 'all' | 'contactsOnly' | 'none' | string: The set of audience external to the signed-in user's organization who will receive the ExternalReplyMessage, if Status is AlwaysEnabled or Scheduled. The possible values are: none, contactsOnly, all.
* **externalReplyMessage**: string: The automatic reply to send to the specified external audience, if Status is AlwaysEnabled or Scheduled.
* **internalReplyMessage**: string: The automatic reply to send to the audience internal to the signed-in user's organization, if Status is AlwaysEnabled or Scheduled.
* **scheduledEndDateTime**: [MicrosoftGraphDateTimeZone](#microsoftgraphdatetimezone): The date and time that automatic replies are set to end, if Status is set to Scheduled.
* **scheduledStartDateTime**: [MicrosoftGraphDateTimeZone](#microsoftgraphdatetimezone): The date and time that automatic replies are set to begin, if Status is set to Scheduled.
* **status**: 'alwaysEnabled' | 'disabled' | 'scheduled' | string: Configurations status for automatic replies. The possible values are: disabled, alwaysEnabled, scheduled.

## MicrosoftGraphCertification
### Properties
* **certificationDetailsUrl**: string: URL that shows certification details for the application.
* **certificationExpirationDateTime**: string: The timestamp when the current certification for the application expires.
* **isCertifiedByMicrosoft**: bool: Indicates whether the application is certified by Microsoft.
* **isPublisherAttested**: bool: Indicates whether the application developer or publisher completed Publisher Attestation.
* **lastCertificationDateTime**: string: The timestamp when the certification for the application was most recently added or updated.

## MicrosoftGraphDateTimeZone
### Properties
* **dateTime**: string: A single point of time in a combined date and time representation ({date}T{time}; for example, 2017-08-29T04:00:00.0000000).
* **timeZone**: string: Represents a time zone, for example, 'Pacific Standard Time'. See below for more possible values.

## MicrosoftGraphEmployeeOrgData
### Properties
* **costCenter**: string: The cost center associated with the user.
* **division**: string: The name of the division in which the user works.

## MicrosoftGraphImplicitGrantSettings
### Properties
* **enableAccessTokenIssuance**: bool: Specifies whether this web application can request an access token using the OAuth 2.0 implicit flow.
* **enableIdTokenIssuance**: bool: Specifies whether this web application can request an ID token using the OAuth 2.0 implicit flow.

## MicrosoftGraphInformationalUrl
### Properties
* **logoUrl**: string: CDN URL to the application's logo, Read-only.
* **marketingUrl**: string: Link to the application's marketing page. For example, https://www.contoso.com/app/marketing.
* **privacyStatementUrl**: string: Link to the application's privacy statement. For example, https://www.contoso.com/app/privacy.
* **supportUrl**: string: Link to the application's support page. For example, https://www.contoso.com/app/support.
* **termsOfServiceUrl**: string: Link to the application's terms of service statement. For example, https://www.contoso.com/app/termsofservice.

## MicrosoftGraphKeyCredential
### Properties
* **customKeyIdentifier**: string: A 40-character binary type that can be used to identify the credential. Optional. When not provided in the payload, defaults to the thumbprint of the certificate.
* **displayName**: string: The friendly name for the key, with a maximum length of 90 characters. Longer values are accepted but shortened. Optional.
* **endDateTime**: string: The date and time at which the credential expires. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
* **key**: string: The certificate's raw data in byte array converted to Base64 string. From a .cer certificate, you can read the key using the Convert.ToBase64String() method. For more information, see Get the certificate key.
* **keyId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The unique identifier (GUID) for the key.
* **startDateTime**: string: The date and time at which the credential becomes valid.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
* **type**: string: The type of key credential; for example, Symmetric, AsymmetricX509Cert.
* **usage**: string: A string that describes the purpose for which the key can be used; for example, Verify.

## MicrosoftGraphKeyValue
### Properties
* **key**: string: Key for the key-value pair.
* **value**: string: Value for the key-value pair.

## MicrosoftGraphLicenseAssignmentState
### Properties
* **assignedByGroup**: string
* **disabledPlans**: (string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"})[]
* **error**: string
* **lastUpdatedDateTime**: string
* **skuId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}
* **state**: string

## MicrosoftGraphLicenseProcessingState
### Properties
* **state**: string

## MicrosoftGraphLocaleInfo
### Properties
* **displayName**: string: A name representing the user's locale in natural language, for example, 'English (United States)'.
* **locale**: string: A locale representation for the user, which includes the user's preferred language and country/region. For example, 'en-us'. The language component follows 2-letter codes as defined in ISO 639-1, and the country component follows 2-letter codes as defined in ISO 3166-1 alpha-2.

## MicrosoftGraphMailboxSettings
### Properties
* **archiveFolder**: string: Folder ID of an archive folder for the user.
* **automaticRepliesSetting**: [MicrosoftGraphAutomaticRepliesSetting](#microsoftgraphautomaticrepliessetting): Configuration settings to automatically notify the sender of an incoming email with a message from the signed-in user.
* **dateFormat**: string: The date format for the user's mailbox.
* **delegateMeetingMessageDeliveryOptions**: 'sendToDelegateAndInformationToPrincipal' | 'sendToDelegateAndPrincipal' | 'sendToDelegateOnly' | string: If the user has a calendar delegate, this specifies whether the delegate, mailbox owner, or both receive meeting messages and meeting responses. Possible values are: sendToDelegateAndInformationToPrincipal, sendToDelegateAndPrincipal, sendToDelegateOnly.
* **language**: [MicrosoftGraphLocaleInfo](#microsoftgraphlocaleinfo): The locale information for the user, including the preferred language and country/region.
* **timeFormat**: string: The time format for the user's mailbox.
* **timeZone**: string: The default time zone for the user's mailbox.
* **userPurpose**: 'equipment' | 'linked' | 'others' | 'room' | 'shared' | 'user' | string: The purpose of the mailbox. Differentiates a mailbox for a single user from a shared mailbox and equipment mailbox in Exchange Online. Possible values are: user, linked, shared, room, equipment, others, unknownFutureValue. Read-only.
* **workingHours**: [MicrosoftGraphWorkingHours](#microsoftgraphworkinghours): The days of the week and hours in a specific time zone that the user works.

## MicrosoftGraphObjectIdentity
### Properties
* **issuer**: string: Specifies the issuer of the identity, for example facebook.com. 512 character limit. For local accounts (where signInType isn't federated), this property is the local default domain name for the tenant, for example contoso.com. For guests from other Microsoft Entra organizations, this is the domain of the federated organization, for example contoso.com. For more information about filtering behavior for this property, see Filtering on the identities property of a user.
* **issuerAssignedId**: string: Specifies the unique identifier assigned to the user by the issuer. 64 character limit. The combination of issuer and issuerAssignedId must be unique within the organization. Represents the sign-in name for the user, when signInType is set to emailAddress or userName (also known as local accounts).When signInType is set to: emailAddress (or a custom string that starts with emailAddress like emailAddress1), issuerAssignedId must be a valid email addressuserName, issuerAssignedId must begin with an alphabetical character or number, and can only contain alphanumeric characters and the following symbols: - or _  For more information about filtering behavior for this property, see Filtering on the identities property of a user.
* **signInType**: string: Specifies the user sign-in types in your directory, such as emailAddress, userName, federated, or userPrincipalName. federated represents a unique identifier for a user from an issuer that can be in any format chosen by the issuer. Setting or updating a userPrincipalName identity updates the value of the userPrincipalName property on the user object. The validations performed on the userPrincipalName property on the user object, for example, verified domains and acceptable characters, are performed when setting or updating a userPrincipalName identity. Extra validation is enforced on issuerAssignedId when the sign-in type is set to emailAddress or userName. This property can also be set to any custom string. For more information about filtering behavior for this property, see Filtering on the identities property of a user.

## MicrosoftGraphOnPremisesExtensionAttributes
### Properties
* **extensionAttribute1**: string: First customizable extension attribute.
* **extensionAttribute10**: string: Tenth customizable extension attribute.
* **extensionAttribute11**: string: Eleventh customizable extension attribute.
* **extensionAttribute12**: string: Twelfth customizable extension attribute.
* **extensionAttribute13**: string: Thirteenth customizable extension attribute.
* **extensionAttribute14**: string: Fourteenth customizable extension attribute.
* **extensionAttribute15**: string: Fifteenth customizable extension attribute.
* **extensionAttribute2**: string: Second customizable extension attribute.
* **extensionAttribute3**: string: Third customizable extension attribute.
* **extensionAttribute4**: string: Fourth customizable extension attribute.
* **extensionAttribute5**: string: Fifth customizable extension attribute.
* **extensionAttribute6**: string: Sixth customizable extension attribute.
* **extensionAttribute7**: string: Seventh customizable extension attribute.
* **extensionAttribute8**: string: Eighth customizable extension attribute.
* **extensionAttribute9**: string: Ninth customizable extension attribute.

## MicrosoftGraphOnPremisesProvisioningError
### Properties
* **category**: string: Category of the provisioning error. Note: Currently, there is only one possible value. Possible value: PropertyConflict - indicates a property value is not unique. Other objects contain the same value for the property.
* **occurredDateTime**: string: The date and time at which the error occurred.
* **propertyCausingError**: string: Name of the directory property causing the error. Current possible values: UserPrincipalName or ProxyAddress.
* **value**: string: Value of the property causing the error.

## MicrosoftGraphOptionalClaim
### Properties
* **additionalProperties**: string[]: Additional properties of the claim. If a property exists in this collection, it modifies the behavior of the optional claim specified in the name property.
* **essential**: bool: If the value is true, the claim specified by the client is necessary to ensure a smooth authorization experience for the specific task requested by the end user. The default value is false.
* **name**: string: The name of the optional claim.
* **source**: string: The source (directory object) of the claim. There are predefined claims and user-defined claims from extension properties. If the source value is null, the claim is a predefined optional claim. If the source value is user, the value in the name property is the extension property from the user object.

## MicrosoftGraphOptionalClaims
### Properties
* **accessToken**: [MicrosoftGraphOptionalClaim](#microsoftgraphoptionalclaim)[]: The optional claims returned in the JWT access token.
* **idToken**: [MicrosoftGraphOptionalClaim](#microsoftgraphoptionalclaim)[]: The optional claims returned in the JWT ID token.
* **saml2Token**: [MicrosoftGraphOptionalClaim](#microsoftgraphoptionalclaim)[]: The optional claims returned in the SAML token.

## MicrosoftGraphParentalControlSettings
### Properties
* **countriesBlockedForMinors**: string[]: Specifies the two-letter ISO country codes. Access to the application will be blocked for minors from the countries specified in this list.
* **legalAgeGroupRule**: string: Specifies the legal age group rule that applies to users of the app. Can be set to one of the following values: ValueDescriptionAllowDefault. Enforces the legal minimum. This means parental consent is required for minors in the European Union and Korea.RequireConsentForPrivacyServicesEnforces the user to specify date of birth to comply with COPPA rules. RequireConsentForMinorsRequires parental consent for ages below 18, regardless of country/region minor rules.RequireConsentForKidsRequires parental consent for ages below 14, regardless of country/region minor rules.BlockMinorsBlocks minors from using the app.

## MicrosoftGraphPasswordCredential
### Properties
* **customKeyIdentifier**: string: Do not use.
* **displayName**: string: Friendly name for the password. Optional.
* **endDateTime**: string: The date and time at which the password expires represented using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Optional.
* **hint**: string: Contains the first three characters of the password. Read-only.
* **keyId**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The unique identifier for the password.
* **secretText**: string: Read-only; Contains the strong passwords generated by Microsoft Entra ID that are 16-64 characters in length. The generated password value is only returned during the initial POST request to addPassword. There is no way to retrieve this password in the future.
* **startDateTime**: string: The date and time at which the password becomes valid. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Optional.

## MicrosoftGraphPasswordProfile
### Properties
* **forceChangePasswordNextSignIn**: bool: true if the user must change their password on the next sign-in; otherwise false.
* **forceChangePasswordNextSignInWithMfa**: bool: If true, at next sign-in, the user must perform a multifactor authentication (MFA) before being forced to change their password. The behavior is identical to forceChangePasswordNextSignIn except that the user is required to first perform a multifactor authentication before password change. After a password change, this property will be automatically reset to false. If not set, default is false.
* **password**: string: The password for the user. This property is required when a user is created. It can be updated, but the user will be required to change the password on the next sign-in. The password must satisfy minimum requirements as specified by the user's passwordPolicies property. By default, a strong password is required.

## MicrosoftGraphPermissionScope
### Properties
* **adminConsentDescription**: string: A description of the delegated permissions, intended to be read by an administrator granting the permission on behalf of all users. This text appears in tenant-wide admin consent experiences.
* **adminConsentDisplayName**: string: The permission's title, intended to be read by an administrator granting the permission on behalf of all users.
* **id**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: Unique delegated permission identifier inside the collection of delegated permissions defined for a resource application.
* **isEnabled**: bool: When you create or update a permission, this property must be set to true (which is the default). To delete a permission, this property must first be set to false. At that point, in a subsequent call, the permission may be removed.
* **origin**: string
* **type**: string: The possible values are: User and Admin. Specifies whether this delegated permission should be considered safe for non-admin users to consent to on behalf of themselves, or whether an administrator consent should always be required. While Microsoft Graph defines the default consent requirement for each permission, the tenant administrator may override the behavior in their organization (by allowing, restricting, or limiting user consent to this delegated permission). For more information, see Configure how users consent to applications.
* **userConsentDescription**: string: A description of the delegated permissions, intended to be read by a user granting the permission on their own behalf. This text appears in consent experiences where the user is consenting only on behalf of themselves.
* **userConsentDisplayName**: string: A title for the permission, intended to be read by a user granting the permission on their own behalf. This text appears in consent experiences where the user is consenting only on behalf of themselves.
* **value**: string: Specifies the value to include in the scp (scope) claim in access tokens. Must not exceed 120 characters in length. Allowed characters are : ! # $ % & ' ( ) * + , -. / : ;  =  ? @ [ ] ^ + _  {  } ~, and characters in the ranges 0-9, A-Z and a-z. Any other character, including the space character, aren't allowed. May not begin with ..

## MicrosoftGraphPreAuthorizedApplication
### Properties
* **appId**: string: The unique identifier for the application.
* **delegatedPermissionIds**: string[]: The unique identifier for the oauth2PermissionScopes the application requires.

## MicrosoftGraphProvisionedPlan
### Properties
* **capabilityStatus**: string: Condition of the capability assignment. The possible values are Enabled, Warning, Suspended, Deleted, LockedOut. See a detailed description of each value.
* **provisioningStatus**: string: The possible values are:Success - Service is fully provisioned.Disabled - Service is disabled.Error - The service plan isn't provisioned and is in an error state.PendingInput - The service isn't provisioned and is awaiting service confirmation.PendingActivation - The service is provisioned but requires explicit activation by an administrator (for example, Intune_O365 service plan)PendingProvisioning - Microsoft has added a new service to the product SKU and it isn't activated in the tenant.
* **service**: string: The name of the service; for example, 'AccessControlS2S'.

## MicrosoftGraphPublicClientApplication
### Properties
* **redirectUris**: string[]: Specifies the URLs where user tokens are sent for sign-in, or the redirect URIs where OAuth 2.0 authorization codes and access tokens are sent. For iOS and macOS apps, specify the value following the syntax msauth.{BUNDLEID}://auth, replacing '{BUNDLEID}'. For example, if the bundle ID is com.microsoft.identitysample.MSALiOS, the URI is msauth.com.microsoft.identitysample.MSALiOS://auth.

## MicrosoftGraphRedirectUriSettings
### Properties
* **index**: int
* **uri**: string

## MicrosoftGraphRequestSignatureVerification
### Properties
* **allowedWeakAlgorithms**: 'rsaSha1' | string: Specifies which weak algorithms are allowed. The possible values are: rsaSha1, unknownFutureValue.
* **isSignedRequestRequired**: bool: Specifies whether signed authentication requests for this application should be required.

## MicrosoftGraphRequiredResourceAccess
### Properties
* **resourceAccess**: [MicrosoftGraphResourceAccess](#microsoftgraphresourceaccess)[]: The list of OAuth2.0 permission scopes and app roles that the application requires from the specified resource.
* **resourceAppId**: string: The unique identifier for the resource that the application requires access to. This should be equal to the appId declared on the target resource application.

## MicrosoftGraphResourceAccess
### Properties
* **id**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The unique identifier of an app role or delegated permission exposed by the resource application. For delegated permissions, this should match the id property of one of the delegated permissions in the oauth2PermissionScopes collection of the resource application's service principal. For app roles (application permissions), this should match the id property of an app role in the appRoles collection of the resource application's service principal.
* **type**: string: Specifies whether the id property references a delegated permission or an app role (application permission). The possible values are: Scope (for delegated permissions) or Role (for app roles).

## MicrosoftGraphResourceSpecificPermission
### Properties
* **description**: string: Describes the level of access that the resource-specific permission represents.
* **displayName**: string: The display name for the resource-specific permission.
* **id**: string {minLength: 36, maxLength: 36, pattern: "^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"}: The unique identifier for the resource-specific application permission.
* **isEnabled**: bool: Indicates whether the permission is enabled.
* **value**: string: The value of the permission.

## MicrosoftGraphSamlSingleSignOnSettings
### Properties
* **relayState**: string: The relative URI the service provider would redirect to after completion of the single sign-on flow.

## MicrosoftGraphServicePrincipalLockConfiguration
### Properties
* **allProperties**: bool: Enables locking all sensitive properties. The sensitive properties are keyCredentials, passwordCredentials, and tokenEncryptionKeyId.
* **credentialsWithUsageSign**: bool: Locks the keyCredentials and passwordCredentials properties for modification where credential usage type is Sign.
* **credentialsWithUsageVerify**: bool: Locks the keyCredentials and passwordCredentials properties for modification where credential usage type is Verify. This locks OAuth service principals.
* **isEnabled**: bool: Enables or disables service principal lock configuration. To allow the sensitive properties to be updated, update this property to false to disable the lock on the service principal.
* **tokenEncryptionKeyId**: bool: Locks the tokenEncryptionKeyId property for modification on the service principal.

## MicrosoftGraphServiceProvisioningError
### Properties
* **createdDateTime**: string: The date and time at which the error occurred.
* **isResolved**: bool: Indicates whether the error has been attended to.
* **serviceInstance**: string: Qualified service instance (for example, 'SharePoint/Dublin') that published the service error information.

## MicrosoftGraphSignInActivity
### Properties
* **lastNonInteractiveSignInDateTime**: string: The last non-interactive sign-in date for a specific user. You can use this field to calculate the last time a client attempted (either successfully or unsuccessfully) to sign in to the directory on behalf of a user. Because some users may use clients to access tenant resources rather than signing into your tenant directly, you can use the non-interactive sign-in date to along with lastSignInDateTime to identify inactive users. The timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Microsoft Entra ID maintains non-interactive sign-ins going back to May 2020. For more information about using the value of this property, see Manage inactive user accounts in Microsoft Entra ID.
* **lastNonInteractiveSignInRequestId**: string: Request identifier of the last non-interactive sign-in performed by this user.
* **lastSignInDateTime**: string: The last interactive sign-in date and time for a specific user. This property records the last time a user attempted an interactive sign-in to the directory—whether the attempt was successful or not. Note: Since unsuccessful attempts are also logged, this value might not accurately reflect actual system usage. For tracking actual account access, please use the lastSuccessfulSignInDateTime property. The timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z.
* **lastSignInRequestId**: string: Request identifier of the last interactive sign-in performed by this user.
* **lastSuccessfulSignInDateTime**: string: The date and time of the user's most recent successful interactive or non-interactive sign-in. Use this property if you need to determine when the account was truly accessed. This field can be used to build reports, such as inactive users. The timestamp type represents date and time information using ISO 8601 format and is always in UTC. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Microsoft Entra ID maintains interactive sign-ins going back to April 2020. For more information about using the value of this property, see Manage inactive user accounts in Microsoft Entra ID.
* **lastSuccessfulSignInRequestId**: string: The request ID of the last successful sign-in.

## MicrosoftGraphSpaApplication
### Properties
* **redirectUris**: string[]: Specifies the URLs where user tokens are sent for sign-in, or the redirect URIs where OAuth 2.0 authorization codes and access tokens are sent.

## MicrosoftGraphTimeZoneBase
### Properties
* **name**: string: The name of a time zone. It can be a standard time zone name such as 'Hawaii-Aleutian Standard Time', or 'Customized Time Zone' for a custom time zone.

## MicrosoftGraphVerifiedPublisher
### Properties
* **addedDateTime**: string: The timestamp when the verified publisher was first added or most recently updated.
* **displayName**: string: The verified publisher name from the app publisher's Partner Center account.
* **verifiedPublisherId**: string: The ID of the verified publisher from the app publisher's Partner Center account.

## MicrosoftGraphWebApplication
### Properties
* **homePageUrl**: string: Home page or landing page of the application.
* **implicitGrantSettings**: [MicrosoftGraphImplicitGrantSettings](#microsoftgraphimplicitgrantsettings): Specifies whether this web application can request tokens using the OAuth 2.0 implicit flow.
* **logoutUrl**: string: Specifies the URL that is used by Microsoft's authorization service to log out a user using front-channel, back-channel or SAML logout protocols.
* **redirectUris**: string[]: Specifies the URLs where user tokens are sent for sign-in, or the redirect URIs where OAuth 2.0 authorization codes and access tokens are sent.
* **redirectUriSettings**: [MicrosoftGraphRedirectUriSettings](#microsoftgraphredirecturisettings)[]

## MicrosoftGraphWorkingHours
### Properties
* **daysOfWeek**: ('friday' | 'monday' | 'saturday' | 'sunday' | 'thursday' | 'tuesday' | 'wednesday' | string)[]: The days of the week on which the user works.
* **endTime**: string: The time of the day that the user stops working.
* **startTime**: string: The time of the day that the user starts working.
* **timeZone**: [MicrosoftGraphTimeZoneBase](#microsoftgraphtimezonebase): The time zone to which the working hours apply.

