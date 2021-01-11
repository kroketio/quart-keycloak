# -*- coding: utf-8 -*-
"""
    Adds OpenID Connect support to your Quart application.
    :copyright: (c) 2021 by Sander.
    :license: BSD, see LICENSE for more details.
"""
__version__ = '1.0.0'


DEFAULT_AUDIENCE = "account"  # Keycloak default

from quart_session_openid.utils import AzureResource
AAD_GRAPH_API = AzureResource("AAD Graph API", "https://graph.windows.net/", "00000002-0000-0000-c000-000000000000")  # legacy
OFFICE_365_EXCHANGE_ONLINE = AzureResource("Office 365 Exchange Online", "https://outlook-sdf.office.com/", "00000002-0000-0ff1-ce00-000000000000")
MICROSOFT_GRAPH = AzureResource("Microsoft Graph", "https://graph.microsoft.com", "00000003-0000-0000-c000-000000000000")
SKYPE_FOR_BUSINESS_ONLINE = AzureResource("Skype for Business Online", "https://api.skypeforbusiness.com/", "00000004-0000-0ff1-ce00-000000000000")
OFFICE_365_YAMMER = AzureResource("Office 365 Yammer", "https://api.yammer.com/", "00000005-0000-0ff1-ce00-000000000000")
ONENOTE = AzureResource("OneNote", "https://onenote.com/", "2d4d3d8e-2be3-4bef-9f87-7875a61c29de")
WINDOWS_AZURE_SERVICE_MANAGEMENT_API = AzureResource("Windows Azure Service Management API", "https://management.core.windows.net/", "797f4846-ba00-4fd7-ba43-dac1f8f63013")
OFFICE_365_MANAGEMENT_APIS = AzureResource("Office 365 Management APIs", "https://manage.office.com", "c5393580-f805-4401-95e8-94b7a6ef2fc2")
MICROSOFT_TEAMS_SERVICES = AzureResource("Microsoft Teams Services", "https://api.spaces.skype.com/", "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe")
AZURE_KEY_VAULT = AzureResource("Azure Key Vault", "https://vault.azure.net", "cfa8b339-82a2-471a-a3c9-0fc0be7a4093")
MS_SERVICES = [AAD_GRAPH_API, OFFICE_365_EXCHANGE_ONLINE, MICROSOFT_GRAPH, SKYPE_FOR_BUSINESS_ONLINE,
               OFFICE_365_YAMMER, ONENOTE, WINDOWS_AZURE_SERVICE_MANAGEMENT_API, OFFICE_365_MANAGEMENT_APIS,
               MICROSOFT_TEAMS_SERVICES, AZURE_KEY_VAULT]

# https://nicolgit.github.io/AzureAD-Endopoint-V1-vs-V2-comparison/
# Because there are small differences between the various identity
# providers out there (sigh), we'll keep track of 'm here.
PROVIDER_DEFAULT = 0
PROVIDER_KEYCLOAK = 0
PROVIDER_AZURE_AD_V1 = 1
PROVIDER_AZURE_AD_V2 = 2

from quart_session_openid.openid import OpenID
