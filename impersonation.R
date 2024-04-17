wif_params_list <- list(
  azure_resource = "https://googlewif.example.com/.default", 
  azure_tenant = "911aacex-ampl-exam-pleex-ampleexample", 
  azure_app = "f8d0dexa-mple-exam-plee-xampleexampl",
  
  gcp_project_number = '123456789012', 
  gcp_project_wifPoolIdName = 'wip-azure', 
  gcp_project_wifPoviderName = 'azure', 
  wif_email = 'wif-azure@example.iam.gserviceaccount.com', 
  
  sts_grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
  sts_scope = "https://www.googleapis.com/auth/cloud-platform", 
  sts_subjectTokenType = "urn:ietf:params:oauth:token-type:jwt", 
  sts_requestedTokenType = "urn:ietf:params:oauth:token-type:access_token", 
  
  url = 'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/'
)

get_azure_wif_token <- function(wif_params = wif_params_list, wif_lifetime = '3600s') {
  #############################
  ##### BEGIN constructor ####
  #############################
  
  WifToken <- R6::R6Class("WifToken", inherit = httr::Token2.0, list(
    #' @description Get a token via workload identity federation
    #' @param params A list of parameters for `init_oauth_external_account()`.
    #' @return A WifToken.
    initialize = function(params = list()) {
      message("WifToken initialize")
      # TODO: any desired validity checks on contents of params
      
      # NOTE: the final token exchange with
      # https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
      # takes scopes as an **array**, not a space delimited string
      # so we do NOT collapse scopes in this flow
      params$scope <- params$scopes
      self$params <- params
      
      self$init_credentials()
    },
    
    #' @description Enact the actual token exchange for workload identity
    #'   federation.
    init_credentials = function() {
      message("WifToken init_credentials")
      creds <- init_oauth_external_account()
      
      # for some reason, the serviceAccounts.generateAccessToken method of
      # Google's Service Account Credentials API returns in camelCase, not
      # snake_case
      # as in, we get this:
      # "accessToken":"ya29.c.KsY..."
      # "expireTime":"2021-06-01T18:01:06Z"
      # instead of this:
      # "access_token": "ya29.a0A..."
      # "expires_in": 3599
      snake_case <- function(x) {
        gsub("([a-z0-9])([A-Z])", "\\1_\\L\\2", x, perl = TRUE)
      }
      names(creds) <- snake_case(names(creds))
      self$credentials <- creds
      self
    },
    
    #' @description Refreshes the token, which means re-doing the entire token
    #'   flow in this case.
    refresh = function() {
      message("WifToken refresh")
      # There's something kind of wrong about this, because it's not a true
      # refresh. But this method is basically required by the way httr currently
      # works.
      # This means that some uses of $refresh() aren't really appropriate for a
      # WifToken.
      # For example, if I attempt token_userinfo(x) on a WifToken that lacks
      # appropriate scope, it fails with 401.
      # httr tries to "fix" things by refreshing the token. But this is
      # not a problem that refreshing can fix.
      # I've now prevented that particular phenomenon in token_userinfo().
      self$init_credentials()
    },
    
    #' @description Format a [WifToken()].
    #' @param ... Not used.
    format = function(...) {
      x <- list(
        scopes         = wif_params$sts_scope,
        credentials    = wif_params$wif_email
      )
      c(
        cli::cli_format_method(
          cli::cli_h1("<WifToken (via {.pkg gargle})>")
        ),
        glue::glue("{fr(names(x))}: {fl(x)}")
      )
    },
    #' @description Print a [WifToken()].
    #' @param ... Not used.
    print = function(...) {
      # a format method is not sufficient for WifToken because the parent class
      # has a print method
      cli::cat_line(self$format())
    },
    
    #' @description Placeholder implementation of required method. Returns `TRUE`.
    can_refresh = function() {
      # TODO: see above re: my ambivalence about the whole notion of refresh with
      # respect to this flow
      TRUE
    },
    
    # TODO: are cache and load_from_cache really required?
    # alternatively, what if calling them threw an error?
    #' @description Placeholder implementation of required method. Returns self.
    cache = function() self,
    #' @description Placeholder implementation of required method. Returns self.
    load_from_cache = function() self,
    
    # TODO: are these really required?
    #' @description Placeholder implementation of required method.
    validate = function() {},
    #' @description Placeholder implementation of required method.
    revoke = function() {}
  ))
  
  #############################
  ##### END of constructor ####
  #############################
  
  library(AzureAuth)
  library(tidyverse)
  library(httr2)
  library(gargle)

  fr <- function(x) format(x, justify = "right")
  fl <- function(x) format(x, justify = "left")

  init_oauth_external_account <- function() {
    # first get the Azure token 
    subject_token <- get_azure_token(resource = wif_params$azure_resource, 
                                     tenant = wif_params$azure_tenant, 
                                     app = wif_params$azure_app,
                                     auth_type = "authorization_code", 
                                     version = 2 # for work accounts / version = 1 for private
    )
    
    # next, get the STS token 
    
     audience = paste0("//iam.googleapis.com/projects/", 
                        wif_params$gcp_project_number, 
                        "/locations/global/workloadIdentityPools/", 
                        wif_params$gcp_project_wifPoolIdName, 
                        "/providers/", 
                        wif_params$gcp_project_wifPoviderName)

    google_sts_request <- request("https://sts.googleapis.com/v1/token") %>%
      req_body_form(audience = audience) %>% 
      req_body_form(grantType = wif_params$sts_grantType) %>% 
      req_body_form(subjectToken = subject_token$credentials$access_token) %>% 
      req_body_form(scope = wif_params$sts_scope) %>% 
      req_body_form(subjectTokenType = wif_params$sts_subjectTokenType) %>% 
      req_body_form(requestedTokenType = wif_params$sts_requestedTokenType) 
    
    google_sts_response <- req_perform(google_sts_request)
    
    # Now you extract the Google Security Token Service token 
    federated_access_token <- resp_body_json(google_sts_response)
    
    # finally get the WIF token 
    req <- list(
      method = "POST",
      url = str_c('https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/', 
                  wif_params$wif_email, 
                  ':generateAccessToken'),
      body = list(scope = wif_params$sts_scope, 
                  lifetime = wif_lifetime),
      token = httr::add_headers(
        Authorization = paste("Bearer", federated_access_token$access_token)
      )
    )
    
    resp <- request_make(req)
    
    response_process(resp)
  }
  
  params <- list(scopes = wif_params$sts_scope, 
                 as_header = TRUE)
  
  WifToken$new(params = params)
}