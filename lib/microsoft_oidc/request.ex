defmodule MicrosoftOidc.Request do
  @moduledoc """
  Creates the URL and params to redirect the user to the  
  Microsoft OIDC login.
  """
  @login_base_url "https://login.microsoftonline.com/"
  @application_name :microsoft_oidc

  @doc """
  Creates a sign_in URL.  See MicrosoftOidc.initiate_request/0 for options.
  """
  @spec sign_in_request_url(state :: String.t(), nonce :: String.t(), options :: Keyword.t()) ::
          url :: String.t()
  def sign_in_request_url(state, nonce, options \\ []) do
    defaults = [
      prompt: "login",
      response_mode: "form_post",
      client_id: Application.fetch_env!(@application_name, :msft_client_id),
      tenant: Application.fetch_env!(@application_name, :msft_tenant_id),
      redirect_uri: Application.fetch_env!(@application_name, :msft_redirect_uri)
    ]

    opts = Keyword.merge(defaults, options)
    URI.encode(request_url() <> "?" <> query_string(nonce, state, opts))
  end

  defp request_url() do
    Path.join([
      @login_base_url,
      Application.fetch_env!(@application_name, :msft_tenant_id),
      "oauth2",
      "v2.0",
      "authorize"
    ])
  end

  defp query_string(nonce, state, options) do
    built_in = [
      response_type: "id_token",
      nonce: nonce,
      state: state,
      scope: "openid"
    ]

    Keyword.merge(built_in, options)
    |> Enum.map_join("&", fn {k, v} ->
      "#{Atom.to_string(k)}=#{v}"
    end)
  end
end
