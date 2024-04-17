library(bigrquery)
source('impersonation.R')

wif_token <- get_azure_wif_token(wif_lifetime = '1000s') 

bq_auth(token = wif_token)

