This package is for authentication to Google APIs via Workforce Identity Federation (WIF).
It is based on gargle's package credentials_external_account() call. However, it is specifically designed for Azure accounts. 

In the beginning you need to set credentials for Azure and Google projects. These are subsequently used for obtaining personal / STS and GCP access tokens respectively. 

Upon successfull authentication you obtain a WifToken2.0 object, which can be used for impersonation while calling various Google APIs. 

bigrquery::bq_auth(token = wif_token)

googleAnalyticsR::ga_auth(token = wif_token) ... 
