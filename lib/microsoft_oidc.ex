defmodule MicrosoftOidc do
  @moduledoc """
  Utility for creating sign-in URLS and parsing/validating the params returned by the Oauth server.  You will need to be listening on the redirect URL (without CSRF enabled) for the OIDC flow to be completed. 

  ## Application Enviornment 

  - :microsoft_oidc, :nonce_size : (10 by default) The size in bytes of the nonce used to validate credential responses received from the Oauth server . 
  - :microsoft_oidc, :nonce_timeout : (60 seconds by default) the time (in miliseconds) that a nonce value will be retained in the cache.
  - :microsoft_oidc, :state_size : (10 by default) The size in bytes of the state value used to validate credential responses received from the Oauth server. 
  - :microsoft_oidc, :state_timeout : (60 seconds by default) the time (in miliseconds) that a state value will be retained in the cache.
  - :microsoft_oidc, :msft_client_id : Your application client ID.
  - :microsoft_oidc, :msft_tenant_id : The tenant ID of AAD you are authenticating to.
  - :microsoft_oidc, :msft_redirect_uri : The redirect URI provided to the oauth server to redirect your user back to your app.
  """

  @doc """
  Creates a request URL that users can be redirected to for OIDC
  login.

  When setting a redirect URI be sure to exclude it from CSRF check plugs 
  on your server.  The request response will be validated using its own tokens and the redirect will not have a session   with  CSRF info.

  ## Options
  - prompt: defaults to "login". 
  - response_mode: defaults to "form_post".
  - client_id: the id of your application, deafaults to the application environment value under :microsoft_oidc :msft_client_id
  - tenant: the id of the AAD tenant defautls to the key application environment value under :microsoft_oidc :msft_tenant_id
  - redirect_uri: the URL that the user will be redirected to after completing OIDC flow. Defaults to the value under :microsoft_oidc :msft_redirect_uri
  """
  @spec initiate_request(options :: Keyword.t()) :: request_url :: String.t()
  def initiate_request(options \\ []) do
    nonce = MicrosoftOidc.AuthNonce.generate()
    state = MicrosoftOidc.AuthState.generate()

    MicrosoftOidc.Request.sign_in_request_url(state, nonce, options)
  end

  @doc """
  Validates the params returned to the server after completing OIDC and 
  returns an {:ok, claims} tuple where claims is a map containing the 
  claims contained within the token.

  The function expectss a valid params map to be passed in, and will return 
  an error tuple if the expected "state" and "id_token" fields are not present
  in the params.
  """
  @spec validate_params(params :: map) :: {:ok, map} | {:error, Exception.t()}
  def validate_params(%{"state" => state, "id_token" => token} = _params) do
    with :ok <- valid_state(state),
         {:ok, claims} <- MicrosoftOidc.Token.verify_and_validate(token),
         {:ok, claims} <- validate_nonce(claims) do
      {:ok, claims}
    end
  end

  def validate_params(_),
    do:
      {:error,
       %MicrosoftOidc.ValidateError{
         message:
           "invalid params provided, expected a map with string keys of 'state' and 'id_token'"
       }}

  defp valid_state(state_value) when is_binary(state_value) do
    if MicrosoftOidc.AuthState.validate(state_value) do
      :ok
    else
      {:error,
       %MicrosoftOidc.ValidateError{
         message: "state does not match existing, received: #{state_value}"
       }}
    end
  end

  defp validate_nonce(%{"nonce" => nonce} = claims) do
    if MicrosoftOidc.AuthNonce.validate(nonce) do
      {:ok, claims}
    else
      {:error,
       %MicrosoftOidc.ValidateError{
         message: "nonce received does not match existing, received: #{nonce}"
       }}
    end
  end

  defp validate_nonce(_) do
    {:error, %MicrosoftOidc.ValidateError{message: "no nonce was found in the provided token"}}
  end
end
